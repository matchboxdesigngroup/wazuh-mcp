"""Vulnerability backend routing and composite report generation."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from wazuh_mcp.context import WazuhContext
from wazuh_mcp.server import build_server

from .conftest import API, IDX, envelope, make_settings, search_response


@pytest.fixture
def srv(ctx):
    server, _ = build_server(ctx)
    return server


async def call(server, name, **args):
    result = await server.call_tool(name, args)
    assert not result.is_error, _text(result)
    return result.structured_content if result.structured_content is not None \
        else json.loads(result.content[0].text)


async def call_err(server, name, **args) -> str:
    try:
        result = await server.call_tool(name, args)
    except UnexpectedToolError as exc:
        raise AssertionError(f"{name} crashed: {exc.__cause__!r}") from exc
    except ToolError as exc:
        return str(exc)
    assert result.is_error
    return _text(result)


def _text(result) -> str:
    return " ".join(b.text for b in (result.content or []) if getattr(b, "text", None))


def version(v: str):
    return envelope([{"version": v}])


VULN_DOC = {
    "agent": {"id": "001", "name": "web-01"},
    "vulnerability": {
        "id": "CVE-2024-3094", "severity": "Critical",
        "score": {"base": 10.0, "version": "3.1"},
        "published_at": "2024-03-29T00:00:00Z",
        "detected_at": "2026-08-20T00:00:00Z",
        "description": "Malicious code in xz",
    },
    "package": {"name": "xz-utils", "version": "5.6.0", "architecture": "amd64"},
}


# --- backend routing --------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_48_plus_reads_vulnerabilities_from_indexer(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.9.2"))
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([VULN_DOC], total=1)
    )

    out = await call(srv, "wazuh_vulnerabilities", severity=["Critical"])

    assert out["source"] == "indexer"
    row = out["items"][0]
    assert row["vulnerability.id"] == "CVE-2024-3094"
    assert row["package.name"] == "xz-utils"

    body = json.loads(route.calls[0].request.content)
    assert {"term": {"vulnerability.severity": "Critical"}} in body["query"]["bool"]["filter"]
    assert body["sort"][0]["vulnerability.score.base"]["missing"] == "_last"


@pytest.mark.respx(assert_all_called=False)
async def test_pre_48_reads_vulnerabilities_from_manager_api(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.7.5"))
    route = respx_mock.get(f"{API}/vulnerability/001").respond(200, json=envelope([{
        "cve": "CVE-2023-1234", "name": "openssl", "version": "1.1.1",
        "severity": "High", "cvss3_score": 8.1, "condition": "Package unfixed",
    }], total=1))

    out = await call(srv, "wazuh_vulnerabilities", agent_id=["001"], severity=["High"])

    assert out["source"] == "manager_api"
    assert out["items"][0]["cve"] == "CVE-2023-1234"
    assert out["items"][0]["agent.id"] == "001"
    assert route.calls[0].request.url.params["q"] == "(severity=High)"


@pytest.mark.respx(assert_all_called=False)
async def test_pre_48_fleet_wide_query_explains_the_limitation(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.7.0"))
    message = await call_err(srv, "wazuh_vulnerabilities")
    assert "agent_id is required" in message
    assert "wazuh_list_agents" in message


@pytest.mark.respx(assert_all_called=False)
async def test_unreadable_version_falls_back_to_indexer(srv, respx_mock, auth_route):
    """A manager we cannot version-check should not block a modern query."""
    respx_mock.get(f"{API}/manager/info").respond(403, json={"title": "Permission denied"})
    respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([VULN_DOC], total=1)
    )
    out = await call(srv, "wazuh_vulnerabilities")
    assert out["source"] == "indexer"


@pytest.mark.respx(assert_all_called=False)
async def test_vulnerability_summary_aggregates(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.9.0"))
    aggs = {
        "by_severity": {"buckets": [
            {"key": "Critical", "doc_count": 12}, {"key": "High", "doc_count": 88},
        ]},
        "by_agent": {"buckets": [
            {"key": "web-01", "doc_count": 60, "critical": {"doc_count": 5}},
        ]},
        "by_cve": {"buckets": [
            {"key": "CVE-2024-3094", "doc_count": 9, "agents": {"value": 9}},
        ]},
        "by_package": {"buckets": [{"key": "openssl", "doc_count": 40}]},
        "affected_agents": {"value": 23},
        "distinct_cves": {"value": 77},
        "max_score": {"value": 10.0},
    }
    respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([], total=100, aggregations=aggs)
    )

    out = await call(srv, "wazuh_vulnerability_summary")

    assert out["total_findings"] == 100
    assert out["affected_agents"] == 23
    assert out["distinct_cves"] == 77
    assert out["highest_cvss"] == 10.0
    # Severity order is meaningful, not alphabetical.
    assert list(out["by_severity"]) == ["Critical", "High"]
    assert out["most_affected_agents"][0] == {
        "agent": "web-01", "vulnerabilities": 60, "critical": 5
    }
    assert out["most_common_cves"][0]["affected_agents"] == 9


@pytest.mark.respx(assert_all_called=False)
async def test_min_severity_expands_to_band(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.9.0"))
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([], total=0, aggregations={})
    )
    await call(srv, "wazuh_vulnerability_summary", min_severity="High")
    filters = json.loads(route.calls[0].request.content)["query"]["bool"]["filter"]
    assert {"terms": {"vulnerability.severity": ["Critical", "High"]}} in filters


# --- reports ----------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_executive_summary_renders_markdown(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents/summary/status").respond(
        200, json=envelope([{"total": 100, "active": 90, "disconnected": 10}])
    )
    respx_mock.get(f"{API}/manager/status").respond(
        200, json=envelope([{"wazuh-analysisd": "running", "wazuh-modulesd": "stopped"}])
    )

    def indexer_handler(request):
        import httpx
        body = json.loads(request.content)
        aggs = body.get("aggs", {})
        if "bands" in aggs:
            return httpx.Response(200, json=search_response([], total=5000, aggregations={
                "bands": {"buckets": {
                    "info": {"doc_count": 4000}, "low": {"doc_count": 700},
                    "medium": {"doc_count": 250}, "high": {"doc_count": 45},
                    "critical": {"doc_count": 5},
                }}
            }))
        if "by_severity" in aggs:
            return httpx.Response(200, json=search_response([], total=300, aggregations={
                "by_severity": {"buckets": [{"key": "Critical", "doc_count": 300}]}
            }))
        return httpx.Response(200, json=search_response([], total=50, aggregations={
            "grouped": {"buckets": [{"key": "sshd brute force", "doc_count": 40}]}
        }))

    respx_mock.post(url__startswith=IDX).mock(side_effect=indexer_handler)

    out = await call(srv, "wazuh_generate_report", report_type="executive_summary", start="7d")

    md = out["report_markdown"]
    assert md.startswith("# Wazuh Executive Summary")
    assert "**100** agents registered, **90** active (90.0%)" in md
    assert "wazuh-modulesd" in md, "stopped daemons must surface in the report"
    assert "Critical: **5**" in md
    assert "| sshd brute force |" in md
    assert out["data"]["alert_severity_mix"]["total"] == 5000
    # The markdown is moved out of `data` into its own field, not duplicated.
    assert "_markdown" not in out["data"]


@pytest.mark.respx(assert_all_called=False)
async def test_agent_health_report_tables(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents/summary/status").respond(
        200, json=envelope([{"total": 50, "active": 45, "disconnected": 5}])
    )
    respx_mock.get(f"{API}/agents/outdated").respond(200, json=envelope([
        {"id": "003", "name": "legacy-01", "version": "Wazuh v4.3.0",
         "os": {"platform": "centos"}},
    ], total=3))
    respx_mock.get(f"{API}/agents").respond(200, json=envelope([
        {"id": "009", "name": "gone-01", "ip": "10.0.0.9",
         "lastKeepAlive": "2026-07-01T00:00:00Z"},
    ]))
    respx_mock.get(f"{API}/agents/no_group").respond(200, json=envelope([], total=4))

    out = await call(srv, "wazuh_generate_report", report_type="agent_health")

    md = out["report_markdown"]
    assert "| active | 45 | 90.0% |" in md
    assert "legacy-01" in md and "centos" in md
    assert "gone-01" in md
    assert "**4** agent(s) belong to no group" in md


@pytest.mark.respx(assert_all_called=False)
async def test_compliance_report_requires_framework(srv, respx_mock, auth_route):
    message = await call_err(srv, "wazuh_generate_report", report_type="compliance")
    assert "needs a framework" in message
    assert "pci_dss" in message


@pytest.mark.respx(assert_all_called=False)
async def test_compliance_report_filters_on_framework_field(srv, respx_mock, auth_route):
    route = respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").respond(
        200, json=search_response([], total=900, aggregations={
            "by_control": {"buckets": [
                {"key": "10.2.4", "doc_count": 500, "agents": {"value": 12}},
                {"key": "10.2.5", "doc_count": 400, "agents": {"value": 8}},
            ]},
            "by_agent": {"buckets": [{"key": "web-01", "doc_count": 300}]},
            "by_level": {"buckets": [{"key": 10, "doc_count": 900}]},
        })
    )

    out = await call(
        srv, "wazuh_generate_report", report_type="compliance", framework="pci_dss"
    )

    filters = json.loads(route.calls[0].request.content)["query"]["bool"]["filter"]
    assert {"exists": {"field": "rule.pci_dss"}} in filters

    md = out["report_markdown"]
    assert md.startswith("# PCI DSS Compliance Report")
    assert "| 10.2.4 | 500 | 12 |" in md
    assert "not an attestation of compliance" in md
    assert out["data"]["by_rule_level"][0]["severity"] == "medium"


@pytest.mark.respx(assert_all_called=False)
async def test_report_survives_one_failing_source(srv, respx_mock, auth_route):
    """A partial outage should degrade the report, not fail the whole call."""
    respx_mock.get(f"{API}/agents/summary/status").respond(
        200, json=envelope([{"total": 10, "active": 10}])
    )
    respx_mock.get(f"{API}/manager/status").respond(200, json=envelope([{"wazuh-db": "running"}]))
    respx_mock.post(url__startswith=IDX).respond(503, json={"error": {"reason": "overloaded"}})

    out = await call(srv, "wazuh_generate_report", report_type="executive_summary")

    assert "**10** agents registered" in out["report_markdown"]
    assert "error" in out["data"]["alert_severity_mix"]


@pytest.mark.respx(assert_all_called=False)
async def test_threat_activity_needs_indexer():
    ctx = WazuhContext(make_settings(api_url=API, api_user="u", api_password="p"))
    server, _ = build_server(ctx)
    message = await call_err(server, "wazuh_generate_report", report_type="threat_activity")
    assert "WAZUH_INDEXER_URL" in message
    await ctx.aclose()


@pytest.mark.respx(assert_all_called=False)
async def test_authentication_report_uses_auth_rule_groups(srv, respx_mock, auth_route):
    seen = []

    def handler(request):
        import httpx
        body = json.loads(request.content)
        seen.append(body["query"]["bool"]["filter"])
        return httpx.Response(200, json=search_response([], total=10, aggregations={
            "grouped": {"buckets": [{"key": "203.0.113.7", "doc_count": 10}]}
        }))

    respx_mock.post(url__startswith=f"{IDX}/wazuh-alerts-").mock(side_effect=handler)

    out = await call(srv, "wazuh_generate_report", report_type="authentication")

    groups = {
        clause["term"]["rule.groups"]
        for filters in seen for clause in filters
        if "term" in clause and "rule.groups" in clause["term"]
    }
    assert groups == {"authentication_failed", "authentication_failures"}
    assert "# Authentication Report" in out["report_markdown"]
    assert "203.0.113.7" in out["report_markdown"]


# --- unscored severity ------------------------------------------------------


def test_order_severity_counts_relabels_and_keeps_everything():
    """Wazuh writes "-" for unassigned severity; it must not be dropped."""
    from wazuh_mcp.tools.vulnerabilities import order_severity_counts

    counts = order_severity_counts([
        {"key": "Medium", "count": 4922},
        {"key": "High", "count": 4116},
        {"key": "-", "count": 2354},
        {"key": "Critical", "count": 556},
        {"key": "Low", "count": 74},
    ])
    assert sum(counts.values()) == 12022, "counts must reconcile with the total"
    assert counts["Untriaged"] == 2354
    assert "-" not in counts
    # Known severities come first, in severity order.
    assert list(counts) == ["Critical", "High", "Medium", "Low", "Untriaged"]


def test_order_severity_counts_appends_unknown_labels():
    from wazuh_mcp.tools.vulnerabilities import order_severity_counts

    counts = order_severity_counts([
        {"key": "High", "count": 2}, {"key": "Bizarre", "count": 1},
    ])
    assert list(counts) == ["High", "Bizarre"], "unknown labels are kept, not filtered"


@pytest.mark.respx(assert_all_called=False)
async def test_vulnerability_summary_counts_reconcile(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(200, json=version("v4.14.7"))
    respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([], total=12022, aggregations={
            "by_severity": {"buckets": [
                {"key": "Medium", "doc_count": 4922},
                {"key": "High", "doc_count": 4116},
                {"key": "-", "doc_count": 2354},
                {"key": "Critical", "doc_count": 556},
                {"key": "Low", "doc_count": 74},
            ]},
            "by_agent": {"buckets": []}, "by_cve": {"buckets": []},
            "by_package": {"buckets": []},
            "affected_agents": {"value": 2}, "distinct_cves": {"value": 2993},
            "max_score": {"value": 9.8},
        })
    )
    out = await call(srv, "wazuh_vulnerability_summary")

    assert out["total_findings"] == 12022
    assert sum(out["by_severity"].values()) == 12022, (
        "the severity breakdown must account for every finding"
    )
    assert out["by_severity"]["Untriaged"] == 2354


@pytest.mark.respx(assert_all_called=False)
async def test_exposure_report_never_renders_a_bare_dash(srv, respx_mock, auth_route):
    respx_mock.post(url__startswith=f"{IDX}/wazuh-states-vulnerabilities").respond(
        200, json=search_response([], total=100, aggregations={
            "by_severity": {"buckets": [
                {"key": "High", "doc_count": 60}, {"key": "-", "doc_count": 40},
            ]},
            "by_agent": {"buckets": []}, "by_cve": {"buckets": []},
            "by_package": {"buckets": []},
            "affected_agents": {"value": 1}, "distinct_cves": {"value": 5},
        })
    )
    out = await call(srv, "wazuh_generate_report", report_type="vulnerability_exposure")
    md = out["report_markdown"]
    assert "| Untriaged | 40 | 40.0% |" in md
    assert "| - |" not in md, "a raw '-' severity key must never reach the markdown"
