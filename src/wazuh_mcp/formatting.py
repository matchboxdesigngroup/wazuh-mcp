"""Output shaping: keep tool results small enough to be worth reading."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

#: Truncate any single string value longer than this.
MAX_STRING = 2000
#: Absolute ceiling on nested container size before it is summarised.
MAX_ITEMS = 200


def dig(source: Any, path: str, default: Any = None) -> Any:
    """Read a dotted path out of nested containers, e.g. `rule.level`.

    A numeric segment indexes a list, so OpenSearch shapes like
    `input_results.results.0.hits.total.value` resolve in one call.
    """
    current: Any = source
    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, (list, tuple)) and part.lstrip("-").isdigit():
            index = int(part)
            if not -len(current) <= index < len(current):
                return default
            current = current[index]
        else:
            return default
    return default if current is None else current


def project(doc: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Pull a flat dict of dotted fields out of a nested document.

    Missing fields are omitted rather than emitted as nulls, which keeps
    sparse Wazuh documents from tripling in size.
    """
    out: dict[str, Any] = {}
    for field in fields:
        value = dig(doc, field)
        if value not in (None, "", [], {}):
            out[field] = value
    return out


def trim(value: Any, *, max_string: int = MAX_STRING, depth: int = 0) -> Any:
    """Recursively cap string lengths and container sizes."""
    if isinstance(value, str):
        if len(value) <= max_string:
            return value
        return value[:max_string] + f"… [truncated, {len(value)} chars total]"
    if isinstance(value, Mapping):
        if depth > 8:
            return f"<nested object with {len(value)} keys>"
        return {k: trim(v, max_string=max_string, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if depth > 8:
            return f"<nested list of {len(value)} items>"
        items = [trim(v, max_string=max_string, depth=depth + 1) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"… [{len(value) - MAX_ITEMS} more items omitted]")
        return items
    return value


def paged(
    items: Sequence[Any],
    *,
    total: int,
    limit: int,
    offset: int = 0,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Standard envelope so every list-shaped tool reads the same way."""
    result: dict[str, Any] = {
        "count": len(items),
        "total_matching": total,
        "items": trim(list(items)),
    }
    if total > offset + len(items):
        result["next_offset"] = offset + len(items)
        result["note"] = (
            f"Showing {len(items)} of {total} matches starting at offset {offset}. "
            f"Pass offset={offset + len(items)} for the next page."
        )
    if limit and len(items) == limit and total <= offset + len(items):
        result.setdefault("note", f"Result set truncated at limit={limit}.")
    if extra:
        result.update(extra)
    return result


def buckets_to_rows(
    buckets: Iterable[Mapping[str, Any]],
    *,
    key_name: str = "key",
    sub_agg: str | None = None,
    sub_key: str = "value",
) -> list[dict[str, Any]]:
    """Flatten OpenSearch terms buckets into readable rows."""
    rows: list[dict[str, Any]] = []
    for bucket in buckets:
        if not isinstance(bucket, Mapping):
            continue
        row: dict[str, Any] = {
            key_name: bucket.get("key_as_string", bucket.get("key")),
            "count": bucket.get("doc_count", 0),
        }
        if sub_agg and isinstance(bucket.get(sub_agg), Mapping):
            inner = bucket[sub_agg]
            if "buckets" in inner:
                row[sub_agg] = buckets_to_rows(inner.get("buckets") or [], key_name=sub_key)
            elif "value" in inner:
                row[sub_agg] = inner["value"]
        rows.append(row)
    return rows


def severity_of(level: Any) -> str:
    """Name the severity band for a Wazuh rule level."""
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 15:
        return "critical"
    if value >= 12:
        return "high"
    if value >= 7:
        return "medium"
    if value >= 4:
        return "low"
    return "info"


def pct(part: float, whole: float) -> float:
    """Percentage rounded to one decimal, guarding division by zero."""
    return round(100.0 * part / whole, 1) if whole else 0.0


# --- Wazuh-specific normalisation -------------------------------------------

#: Daemons that are stopped in a healthy default install. They back opt-in
#: features (agentless monitoring, syslog forwarding, email alerts, reports,
#: clustering), so treating them as failures raises a false alarm on almost
#: every single-node deployment.
OPTIONAL_DAEMONS = frozenset({
    "wazuh-agentlessd",
    "wazuh-csyslogd",
    "wazuh-maild",
    "wazuh-reportd",
    "wazuh-clusterd",
})


def agent_status_counts(item: Any) -> dict[str, Any]:
    """Normalise `/agents/summary/status` across Wazuh versions.

    Current releases nest the counts under `connection` and `configuration`;
    older ones returned a single flat mapping. Both are flattened to the same
    shape so callers do not have to care which they got.
    """
    if not isinstance(item, Mapping):
        return {"total": 0, "connection": {}, "configuration": {}}

    nested = item.get("connection")
    if isinstance(nested, Mapping):
        connection = {
            k: v for k, v in nested.items() if k != "total" and isinstance(v, int)
        }
        total = int(nested.get("total") or 0)
        raw_config = item.get("configuration")
        configuration = (
            {k: v for k, v in raw_config.items() if isinstance(v, int)}
            if isinstance(raw_config, Mapping)
            else {}
        )
    else:
        connection = {
            k: v for k, v in item.items() if k != "total" and isinstance(v, int)
        }
        total = int(item.get("total") or 0)
        configuration = {}

    return {"total": total, "connection": connection, "configuration": configuration}


def classify_daemons(
    daemons: Mapping[str, Any], *, cluster_enabled: bool = False
) -> dict[str, Any]:
    """Split daemon states into running, and stopped-but-expected vs concerning.

    Only a stopped *core* daemon indicates a problem. `wazuh-clusterd` counts
    as core only when clustering is actually enabled.
    """
    states = {k: v for k, v in daemons.items() if isinstance(v, str)}
    optional = set(OPTIONAL_DAEMONS)
    if cluster_enabled:
        optional.discard("wazuh-clusterd")

    running = sorted(k for k, v in states.items() if v == "running")
    stopped = sorted(k for k, v in states.items() if v != "running")
    core_stopped = [d for d in stopped if d not in optional]
    optional_stopped = [d for d in stopped if d in optional]

    result: dict[str, Any] = {
        "running": running,
        "healthy": not core_stopped,
    }
    if core_stopped:
        result["core_not_running"] = core_stopped
        result["warning"] = (
            f"{len(core_stopped)} core Wazuh daemon(s) are not running: "
            + ", ".join(core_stopped)
        )
    if optional_stopped:
        result["optional_not_running"] = optional_stopped
        result["optional_note"] = (
            "These back opt-in features and are normally stopped: "
            + ", ".join(optional_stopped)
        )
    return result
