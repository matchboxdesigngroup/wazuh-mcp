"""Alert tools exercised through the real MCP call_tool path."""

from __future__ import annotations

import json

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from wazuh_mcp.server import build_server

from .conftest import IDX, search_response


@pytest.fixture
def srv(ctx):
    server, _ = build_server(ctx)
    return server


async def call(server, name, **args):
    """Invoke a tool and return its structured payload."""
    result = await server.call_tool(name, args)
    assert not result.is_error, _error_text(result)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


async def call_expect_error(server, name, **args) -> str:
    """Invoke a tool expected to fail, returning the message the model sees."""
    try:
        result = await server.call_tool(name, args)
    except UnexpectedToolError as exc:  # pragma: no cover - a crash, not a handled error
        raise AssertionError(
            f"{name} crashed instead of raising a handled error: {exc.__cause__!r}"
        ) from exc
    except ToolError as exc:
        return str(exc)
    assert result.is_error, f"expected {name} to fail, got {result.structured_content}"
    return _error_text(result)


def _error_text(result) -> str:
    return " ".join(
        block.text for block in (result.content or []) if getattr(block, "text", None)
    )


ALERT = {
    "timestamp": "2026-08-26T10:00:00.000+0000",
    "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
    "rule": {
        "id": "5710", "level": 13, "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["syslog", "sshd", "authentication_failed"],
        "mitre": {"id": ["T1110"], "technique": ["Brute Force"], "tactic": ["Credential Access"]},
    },
    "data": {"srcip": "203.0.113.7", "srcport": "48122"},
    "location": "/var/log/auth.log",
    "decoder": {"name": "sshd"},
    "full_log": "Aug 26 10:00:00 web-01 sshd[1234]: Invalid user admin from 203.0.113.7",
    "manager": {"name": "wazuh-manager"},
}


@pytest.mark.respx(assert_all_called=False)
async def test_search_alerts_projects_and_adds_severity(srv, respx_mock):
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([ALERT], total=1)
    )

    out = await call(srv, "wazuh_search_alerts", severity="high", limit=10)

    assert out["count"] == 1
    alert = out["items"][0]
    assert alert["severity"] == "high"
    assert alert["rule.level"] == 13
    assert alert["agent.name"] == "web-01"
    assert alert["rule.mitre.id"] == ["T1110"]
    # Nested source fields are flattened into dotted keys.
    assert "agent" not in alert

    body = json.loads(route.calls[0].request.content)
    clauses = body["query"]["bool"]["filter"]
    assert {"range": {"rule.level": {"gte": 12, "lte": 14}}} in clauses
    assert any("range" in c and "@timestamp" in c["range"] for c in clauses)
    assert body["size"] == 10
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]


@pytest.mark.respx(assert_all_called=False)
async def test_search_alerts_full_documents_keeps_nesting(srv, respx_mock):
    respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([ALERT], total=1)
    )
    out = await call(srv, "wazuh_search_alerts", full_documents=True)
    assert out["items"][0]["agent"]["name"] == "web-01"


@pytest.mark.respx(assert_all_called=False)
async def test_search_alerts_builds_all_filters(srv, respx_mock):
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=0)
    )
    await call(
        srv, "wazuh_search_alerts",
        start="2026-08-01T00:00:00Z", end="2026-08-02T00:00:00Z",
        agent_id=["001", "002"], rule_id=["5710"], rule_group=["sshd"],
        mitre_id=["T1110"], src_ip=["203.0.113.7"], min_level=10, max_level=15,
        text="invalid user",
    )
    body = json.loads(route.calls[0].request.content)
    filters = body["query"]["bool"]["filter"]

    assert {"terms": {"agent.id": ["001", "002"]}} in filters
    # A single value uses `term`, not `terms`.
    assert {"term": {"rule.id": "5710"}} in filters
    assert {"term": {"rule.groups": "sshd"}} in filters
    assert {"term": {"rule.mitre.id": "T1110"}} in filters
    assert {"range": {"rule.level": {"gte": 10, "lte": 15}}} in filters
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == "invalid user"

    window = next(c for c in filters if "range" in c and "@timestamp" in c["range"])
    assert window["range"]["@timestamp"]["gte"] == "2026-08-01T00:00:00Z"


@pytest.mark.respx(assert_all_called=False)
async def test_paging_note_reports_next_offset(srv, respx_mock):
    respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([ALERT] * 5, total=137)
    )
    out = await call(srv, "wazuh_search_alerts", limit=5, offset=10)
    assert out["total_matching"] == 137
    assert out["next_offset"] == 15
    assert "offset=15" in out["note"]


@pytest.mark.respx(assert_all_called=False)
async def test_bad_time_value_explains_the_formats(srv, respx_mock):
    message = await call_expect_error(srv, "wazuh_search_alerts", start="last tuesday")
    assert "ISO-8601" in message or "relative" in message


@pytest.mark.respx(assert_all_called=False)
async def test_start_after_end_is_rejected(srv, respx_mock):
    message = await call_expect_error(
        srv, "wazuh_search_alerts",
        start="2026-08-10T00:00:00Z", end="2026-08-01T00:00:00Z",
    )
    assert "after end time" in message


@pytest.mark.respx(assert_all_called=False)
async def test_alert_stats_aggregates(srv, respx_mock):
    aggs = {
        "grouped": {
            "sum_other_doc_count": 42,
            "buckets": [
                {"key": "sshd: brute force", "doc_count": 300},
                {"key": "File added", "doc_count": 120},
            ],
        }
    }
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=462, aggregations=aggs)
    )
    out = await call(srv, "wazuh_alert_stats", group_by="rule.description", top=2)

    assert out["buckets"][0] == {"rule.description": "sshd: brute force", "count": 300}
    assert out["alerts_outside_top_buckets"] == 42
    assert out["total_alerts_in_window"] == 462

    body = json.loads(route.calls[0].request.content)
    assert body["size"] == 0, "aggregation-only search must not fetch documents"
    assert body["aggs"]["grouped"]["terms"]["size"] == 2


@pytest.mark.respx(assert_all_called=False)
async def test_alert_stats_retries_on_keyword_subfield(srv, respx_mock):
    """A text field must transparently fall back to its .keyword subfield."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        field = body["aggs"]["grouped"]["terms"]["field"]
        calls.append(field)
        if field == "rule.description":
            return httpx.Response(400, json={
                "error": {
                    "type": "illegal_argument_exception",
                    "reason": "Fielddata is disabled on text fields by default.",
                }
            })
        return httpx.Response(200, json=search_response(
            [], total=7, aggregations={"grouped": {"buckets": [{"key": "x", "doc_count": 7}]}}
        ))

    respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").mock(side_effect=handler)

    out = await call(srv, "wazuh_alert_stats", group_by="rule.description")

    assert calls == ["rule.description", "rule.description.keyword"]
    # The caller's field name is what comes back, so no branching is needed...
    assert out["group_by"] == "rule.description"
    assert out["buckets"] == [{"rule.description": "x", "count": 7}]
    # ...but the substitution is still reported.
    assert out["aggregated_field"] == "rule.description.keyword"
    assert "keyword" in out["note"]


@pytest.mark.respx(assert_all_called=False)
async def test_alert_stats_nested_grouping(srv, respx_mock):
    aggs = {
        "grouped": {
            "buckets": [{
                "key": "web-01", "doc_count": 50,
                "nested": {"buckets": [{"key": "5710", "doc_count": 30}]},
            }]
        }
    }
    respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=50, aggregations=aggs)
    )
    out = await call(srv, "wazuh_alert_stats", group_by="agent.name", then_by="rule.id")
    assert out["buckets"][0]["nested"] == [{"value": "5710", "count": 30}]


@pytest.mark.respx(assert_all_called=False)
async def test_timeline_picks_interval_and_peak(srv, respx_mock):
    buckets = [
        {"key_as_string": "2026-08-26T08:00:00Z", "key": 1, "doc_count": 10},
        {"key_as_string": "2026-08-26T09:00:00Z", "key": 2, "doc_count": 95},
        {"key_as_string": "2026-08-26T10:00:00Z", "key": 3, "doc_count": 12},
    ]
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=117, aggregations={"timeline": {"buckets": buckets}})
    )
    out = await call(srv, "wazuh_alert_timeline", start="24h")

    assert out["interval"] == "30m"
    assert out["peak"] == {"count": 95, "at": "2026-08-26T09:00:00Z"}
    assert len(out["buckets"]) == 3

    body = json.loads(route.calls[0].request.content)
    hist = body["aggs"]["timeline"]["date_histogram"]
    assert hist["fixed_interval"] == "30m"
    assert hist["min_doc_count"] == 0, "gaps must render as zero, not vanish"


@pytest.mark.respx(assert_all_called=False)
@pytest.mark.parametrize(
    "interval,key",
    [("1d", "fixed_interval"), ("30d", "fixed_interval"), ("1w", "calendar_interval")],
)
async def test_timeline_picks_the_right_interval_parameter(srv, respx_mock, interval, key):
    """`calendar_interval` rejects multiples, so only w/M/q/y units go there."""
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=0, aggregations={"timeline": {"buckets": []}})
    )
    await call(srv, "wazuh_alert_timeline", start="90d", interval=interval)
    hist = json.loads(route.calls[0].request.content)["aggs"]["timeline"]["date_histogram"]
    assert hist[key] == interval
    other = "calendar_interval" if key == "fixed_interval" else "fixed_interval"
    assert other not in hist


@pytest.mark.respx(assert_all_called=False)
async def test_indexer_query_rejects_foreign_index(srv, respx_mock):
    message = await call_expect_error(
        srv, "wazuh_indexer_query", body={"query": {"match_all": {}}}, index="secrets-prod"
    )
    assert "outside the Wazuh namespace" in message


@pytest.mark.respx(assert_all_called=False)
async def test_indexer_query_rejects_path_traversal(srv, respx_mock):
    message = await call_expect_error(
        srv, "wazuh_indexer_query", body={"query": {"match_all": {}}},
        index="wazuh-alerts-*/../../_cluster",
    )
    assert "Invalid index pattern" in message


@pytest.mark.respx(assert_all_called=False)
async def test_indexer_query_passes_body_through(srv, respx_mock):
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-archives").respond(
        200, json=search_response([{"x": 1}], total=1, aggregations={"a": {"value": 9}})
    )
    body = {"query": {"term": {"agent.id": "001"}}, "size": 1}
    out = await call(srv, "wazuh_indexer_query", body=body, index="wazuh-archives-*")

    assert json.loads(route.calls[0].request.content) == body
    assert out["aggregations"] == {"a": {"value": 9}}
    assert out["total_matching"] == 1


@pytest.mark.respx(assert_all_called=False)
async def test_empty_index_pattern_is_not_an_error(srv, respx_mock):
    """A fresh cluster with no backing indices should return zero, not fail."""
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=0)
    )
    out = await call(srv, "wazuh_search_alerts")
    assert out["count"] == 0
    params = route.calls[0].request.url.params
    assert params["ignore_unavailable"] == "true"
    assert params["allow_no_indices"] == "true"
