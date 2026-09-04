"""Unit tests for the query, formatting and index-guard helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise

import pytest

from wazuh_mcp.clients.indexer import hits_of, total_of, validate_index
from wazuh_mcp.errors import UpstreamError, WazuhMCPError
from wazuh_mcp.formatting import (
    agent_status_counts,
    classify_daemons,
    dig,
    paged,
    project,
    severity_of,
    trim,
)
from wazuh_mcp.query import (
    auto_interval,
    interval_key,
    parse_time,
    severity_clause,
    term_or_terms,
    time_range,
)

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("30m", "2026-08-26T11:30:00+00:00"),
        ("24h", "2026-08-25T12:00:00+00:00"),
        ("now-7d", "2026-08-19T12:00:00+00:00"),
        ("2w", "2026-08-12T12:00:00+00:00"),
        ("now", "2026-08-26T12:00:00+00:00"),
        ("2026-08-01T06:30:00Z", "2026-08-01T06:30:00+00:00"),
        ("2026-08-01", "2026-08-01T00:00:00+00:00"),
    ],
)
def test_parse_time_accepts_relative_and_absolute(value, expected):
    assert parse_time(value, now=NOW).isoformat() == expected


@pytest.mark.parametrize("value", ["yesterday", "", "7 fortnights", "24hh"])
def test_parse_time_rejects_junk(value):
    with pytest.raises(WazuhMCPError):
        parse_time(value, now=NOW)


def test_time_range_defaults_to_24h_and_formats_for_opensearch():
    clause = time_range(None, None, now=NOW)["range"]["@timestamp"]
    assert clause["gte"] == "2026-08-25T12:00:00Z"
    assert clause["lte"] == "2026-08-26T12:00:00Z"
    assert clause["format"] == "strict_date_optional_time"


def test_time_range_rejects_inverted_window():
    with pytest.raises(WazuhMCPError, match="after end time"):
        time_range("2026-08-26T00:00:00Z", "2026-08-01T00:00:00Z", now=NOW)


@pytest.mark.parametrize(
    "span,expected",
    [("1h", "1m"), ("24h", "30m"), ("7d", "3h"), ("30d", "1d"), ("1y", "1w")],
)
def test_auto_interval_scales_with_window(span, expected):
    if span == "1y":
        start = parse_time("365d", now=NOW)
    else:
        start = parse_time(span, now=NOW)
    assert auto_interval(start, NOW) == expected


def test_severity_clause_bands_do_not_overlap():
    bands = [severity_clause(name)["range"]["rule.level"]
             for name in ("info", "low", "medium", "high", "critical")]
    for lower, upper in pairwise(bands):
        assert lower["lte"] < upper["gte"], "severity bands must be contiguous, not overlapping"


def test_severity_clause_rejects_unknown_band():
    with pytest.raises(WazuhMCPError, match="Unknown severity"):
        severity_clause("catastrophic")


def test_severity_of_matches_the_clause_bands():
    assert severity_of(16) == "critical"
    assert severity_of(15) == "critical"
    assert severity_of(12) == "high"
    assert severity_of(7) == "medium"
    assert severity_of(4) == "low"
    assert severity_of(0) == "info"
    assert severity_of(None) == "unknown"


def test_term_or_terms_collapses_single_values():
    assert term_or_terms("agent.id", "001") == {"term": {"agent.id": "001"}}
    assert term_or_terms("agent.id", ["001"]) == {"term": {"agent.id": "001"}}
    assert term_or_terms("agent.id", ["001", "002"]) == {"terms": {"agent.id": ["001", "002"]}}
    assert term_or_terms("agent.id", None) is None
    assert term_or_terms("agent.id", []) is None
    assert term_or_terms("agent.id", "") is None


# --- index guard ------------------------------------------------------------


@pytest.mark.parametrize("index", [
    "wazuh-alerts-*", "wazuh-alerts-4.x-2026.08.26",
    "wazuh-states-vulnerabilities-*", "wazuh-archives-*,wazuh-alerts-*",
])
def test_validate_index_accepts_wazuh_patterns(index):
    assert validate_index(index) == index


@pytest.mark.parametrize("index", [
    "logs-prod-*", ".opendistro_security", "*", "wazuh-alerts-*/../_nodes",
    "wazuh-alerts,secrets", "", "wazuh alerts",
])
def test_validate_index_rejects_everything_else(index):
    with pytest.raises(UpstreamError):
        validate_index(index)


# --- formatting -------------------------------------------------------------

def test_dig_reads_dotted_paths():
    doc = {"rule": {"level": 10, "mitre": {"id": ["T1110"]}}}
    assert dig(doc, "rule.level") == 10
    assert dig(doc, "rule.mitre.id") == ["T1110"]
    assert dig(doc, "rule.missing", "fallback") == "fallback"
    assert dig(doc, "rule.level.deeper") is None
    assert dig(None, "rule.level") is None


def test_project_omits_empty_values():
    doc = {"a": 1, "b": "", "c": None, "d": [], "e": {"f": 0}}
    assert project(doc, ("a", "b", "c", "d", "e.f", "missing")) == {"a": 1, "e.f": 0}


def test_trim_caps_long_strings_and_reports_original_length():
    out = trim({"log": "x" * 5000}, max_string=100)
    assert out["log"].startswith("x" * 100)
    assert "5000 chars total" in out["log"]


def test_trim_caps_long_lists():
    out = trim(list(range(500)))
    assert len(out) == 201
    assert "300 more items omitted" in out[-1]


def test_trim_survives_deep_nesting():
    deep: dict = {}
    node = deep
    for _ in range(30):
        node["next"] = {}
        node = node["next"]
    trim(deep)  # must not recurse without bound


def test_paged_signals_more_results():
    out = paged([1, 2, 3], total=100, limit=3, offset=0)
    assert out["next_offset"] == 3
    assert "offset=3" in out["note"]


def test_paged_is_quiet_when_complete():
    out = paged([1, 2], total=2, limit=10, offset=0)
    assert "next_offset" not in out
    assert "note" not in out


def test_paged_final_page_has_no_next_offset():
    out = paged([1, 2], total=12, limit=2, offset=10)
    assert "next_offset" not in out


# --- indexer response shaping -----------------------------------------------

def test_hits_of_flattens_source_and_keeps_ids():
    response = {"hits": {"hits": [
        {"_id": "abc", "_index": "wazuh-alerts-4.x", "_source": {"rule": {"level": 5}}},
    ]}}
    doc = hits_of(response)[0]
    assert doc["_id"] == "abc"
    assert doc["rule"]["level"] == 5


def test_total_of_handles_both_response_shapes():
    assert total_of({"hits": {"total": {"value": 42}}}) == 42
    assert total_of({"hits": {"total": 42}}) == 42
    assert total_of({}) == 0


@pytest.mark.parametrize(
    "interval,expected",
    [
        ("30s", "fixed_interval"), ("5m", "fixed_interval"),
        ("1h", "fixed_interval"), ("12h", "fixed_interval"),
        # Days stay fixed: `calendar_interval` rejects multiples like 30d.
        ("1d", "fixed_interval"), ("30d", "fixed_interval"),
        # These units only exist as calendar intervals.
        ("1w", "calendar_interval"), ("1M", "calendar_interval"),
        ("1q", "calendar_interval"), ("1y", "calendar_interval"),
    ],
)
def test_interval_key_routes_units_correctly(interval, expected):
    assert interval_key(interval) == expected


def test_every_auto_interval_is_a_valid_pairing():
    """No window may produce a multiple under `calendar_interval`."""
    from wazuh_mcp.query import _INTERVALS

    for _, label in _INTERVALS:
        key = interval_key(label)
        if key == "calendar_interval":
            assert label[0] == "1", f"{label} is a multiple; calendar_interval forbids it"


# --- version-tolerant Wazuh payload parsing ---------------------------------

def test_agent_status_counts_parses_nested_shape():
    """Current Wazuh nests counts under `connection` / `configuration`."""
    parsed = agent_status_counts({
        "connection": {"active": 9, "disconnected": 1, "total": 10},
        "configuration": {"synced": 8, "not_synced": 2, "total": 10},
    })
    assert parsed["total"] == 10
    assert parsed["connection"] == {"active": 9, "disconnected": 1}
    assert parsed["configuration"] == {"synced": 8, "not_synced": 2, "total": 10}


def test_agent_status_counts_parses_legacy_flat_shape():
    """Older releases returned one flat mapping."""
    parsed = agent_status_counts({"active": 9, "disconnected": 1, "total": 10})
    assert parsed["total"] == 10
    assert parsed["connection"] == {"active": 9, "disconnected": 1}
    assert parsed["configuration"] == {}


def test_agent_status_counts_survives_junk():
    assert agent_status_counts(None)["total"] == 0
    assert agent_status_counts({})["connection"] == {}


def test_classify_daemons_ignores_optional_features():
    result = classify_daemons({
        "wazuh-analysisd": "running",
        "wazuh-maild": "stopped",
        "wazuh-reportd": "stopped",
    })
    assert result["healthy"] is True
    assert "warning" not in result
    assert result["optional_not_running"] == ["wazuh-maild", "wazuh-reportd"]


def test_classify_daemons_flags_core_failures():
    result = classify_daemons({"wazuh-analysisd": "stopped", "wazuh-maild": "stopped"})
    assert result["healthy"] is False
    assert result["core_not_running"] == ["wazuh-analysisd"]
    assert "wazuh-analysisd" in result["warning"]
    assert "wazuh-maild" not in result["warning"], "optional daemons must not be in the warning"


def test_classify_daemons_promotes_clusterd_when_clustering_on():
    stopped = {"wazuh-clusterd": "stopped"}
    assert classify_daemons(stopped)["healthy"] is True
    assert classify_daemons(stopped, cluster_enabled=True)["healthy"] is False


def test_validate_index_accepts_the_whole_namespace_wildcard():
    """`wazuh-*` is the default for the index-listing tool and must validate."""
    assert validate_index("wazuh-*") == "wazuh-*"


def test_index_taking_tool_defaults_all_validate():
    """Guards against a tool shipping a default its own validator rejects."""
    from wazuh_mcp.config import Settings

    defaults = Settings(_env_file=None)
    for pattern in ("wazuh-*", defaults.alerts_index, defaults.vulnerability_index):
        assert validate_index(pattern) == pattern


def test_dig_indexes_into_lists():
    """OpenSearch responses nest arrays, e.g. input_results.results.0.hits."""
    doc = {"input_results": {"results": [{"hits": {"total": {"value": 42}}}]}}
    assert dig(doc, "input_results.results.0.hits.total.value") == 42
    assert dig(doc, "input_results.results.1.hits") is None
    assert dig(doc, "input_results.results.-1.hits.total.value") == 42
    assert dig({"a": [1, 2]}, "a.5", "fallback") == "fallback"
    assert dig({"a": [1, 2]}, "a.notanindex") is None
