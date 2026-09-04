"""Helpers for turning friendly tool arguments into OpenSearch queries."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import WazuhMCPError

RELATIVE_RE = re.compile(r"^(?:now-)?(\d+)\s*([smhdwM])$")

_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
    "M": 2_592_000,  # 30 days
}

#: Wazuh rule levels map onto these conventional severity bands.
SEVERITY_BANDS: dict[str, tuple[int, int]] = {
    "critical": (15, 16),
    "high": (12, 14),
    "medium": (7, 11),
    "low": (4, 6),
    "info": (0, 3),
}


def parse_time(value: str, *, now: datetime | None = None) -> datetime:
    """Parse `24h`, `now-7d`, `now`, or an ISO-8601 timestamp into UTC.

    Relative forms are the common case in chat ("last 24 hours"), so they are
    accepted with or without the `now-` prefix.
    """
    now = now or datetime.now(UTC)
    text = value.strip()
    if not text:
        raise WazuhMCPError("Time value must not be empty")
    if text.lower() in ("now", "*"):
        return now

    match = RELATIVE_RE.match(text)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return now - timedelta(seconds=amount * _UNIT_SECONDS[unit])

    iso = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise WazuhMCPError(
            f"Could not parse time {value!r}. Use a relative form like '24h' or "
            "'now-7d', or an ISO-8601 timestamp like '2026-08-01T00:00:00Z'."
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def time_range(
    start: str | None,
    end: str | None,
    *,
    default_start: str = "24h",
    field: str = "@timestamp",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a `range` clause, defaulting to the trailing 24 hours."""
    now = now or datetime.now(UTC)
    start_dt = parse_time(start or default_start, now=now)
    end_dt = parse_time(end, now=now) if end else now
    if start_dt > end_dt:
        raise WazuhMCPError(
            f"Start time ({start_dt.isoformat()}) is after end time ({end_dt.isoformat()})"
        )
    return {
        "range": {
            field: {
                "gte": start_dt.isoformat().replace("+00:00", "Z"),
                "lte": end_dt.isoformat().replace("+00:00", "Z"),
                "format": "strict_date_optional_time",
            }
        }
    }


#: Intervals OpenSearch accepts, paired with their length in seconds.
_INTERVALS: tuple[tuple[int, str], ...] = (
    (1, "1s"), (5, "5s"), (30, "30s"),
    (60, "1m"), (300, "5m"), (600, "10m"), (1800, "30m"),
    (3600, "1h"), (10800, "3h"), (21600, "6h"), (43200, "12h"),
    (86400, "1d"), (604800, "1w"), (2592000, "30d"),
)


def auto_interval(start: datetime, end: datetime, buckets: int = 40) -> str:
    """Pick a date_histogram interval that yields roughly `buckets` points.

    Chooses the interval closest to the target *by ratio* rather than the first
    one at least as large. Rounding up always undershoots the bucket count — a
    one-hour window would land on 5-minute buckets, twelve points, too coarse
    to see the shape of a spike.
    """
    span = max((end - start).total_seconds(), 1.0)
    target = span / max(buckets, 1)
    return min(
        _INTERVALS,
        key=lambda entry: max(entry[0] / target, target / entry[0]),
    )[1]


#: Units that `fixed_interval` cannot express, so must go to `calendar_interval`.
_CALENDAR_UNITS = frozenset({"w", "M", "q", "y"})


def interval_key(interval: str) -> str:
    """Name the date_histogram parameter a given interval must be passed under.

    `fixed_interval` handles ms/s/m/h/d with any multiple; `calendar_interval`
    handles w/M/q/y but only as a single unit. Sending a multiple like `30d` as
    a calendar interval is rejected by OpenSearch, so days stay fixed.
    """
    unit = interval.strip()[-1:] or "h"
    return "calendar_interval" if unit in _CALENDAR_UNITS else "fixed_interval"


def severity_clause(severity: str) -> dict[str, Any]:
    """Translate a severity word into a rule.level range clause."""
    band = SEVERITY_BANDS.get(severity.strip().lower())
    if band is None:
        raise WazuhMCPError(
            f"Unknown severity {severity!r}. Choose one of: "
            + ", ".join(SEVERITY_BANDS)
        )
    low, high = band
    return {"range": {"rule.level": {"gte": low, "lte": high}}}


def build_bool(
    *,
    filters: list[dict[str, Any]] | None = None,
    must: list[dict[str, Any]] | None = None,
    must_not: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a bool query, collapsing to match_all when empty."""
    clauses: dict[str, Any] = {}
    if filters:
        clauses["filter"] = filters
    if must:
        clauses["must"] = must
    if must_not:
        clauses["must_not"] = must_not
    if not clauses:
        return {"match_all": {}}
    return {"bool": clauses}


def term_or_terms(field: str, value: str | list[str] | int | None) -> dict[str, Any] | None:
    """A `term` clause for one value, `terms` for many, None for nothing."""
    if value is None:
        return None
    if isinstance(value, list):
        cleaned = [v for v in value if v not in (None, "")]
        if not cleaned:
            return None
        if len(cleaned) == 1:
            return {"term": {field: cleaned[0]}}
        return {"terms": {field: cleaned}}
    if value == "":
        return None
    return {"term": {field: value}}


def query_string(text: str | None, *, default_field: str = "full_log") -> dict[str, Any] | None:
    """A lucene `query_string` clause for free-text search."""
    if not text or not text.strip():
        return None
    return {
        "query_string": {
            "query": text.strip(),
            "default_field": default_field,
            "analyze_wildcard": True,
            "lenient": True,
        }
    }
