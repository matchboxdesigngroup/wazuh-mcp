"""Rules, SCA, FIM, inventory and the fleet-wide software search fallback."""

from __future__ import annotations

import json

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from wazuh_mcp.server import build_server

from .conftest import API, envelope


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


# --- rules ------------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_list_rules_adds_severity_band(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/rules").respond(200, json=envelope([
        {"id": 5710, "level": 5, "description": "sshd: attempted login",
         "groups": ["sshd"], "filename": "0095-sshd_rules.xml"},
        {"id": 5712, "level": 10, "description": "sshd: brute force", "groups": ["sshd"]},
    ]))
    out = await call(srv, "wazuh_list_rules", group="sshd")
    assert [r["severity"] for r in out["items"]] == ["low", "medium"]


@pytest.mark.respx(assert_all_called=False)
async def test_compliance_filter_uses_hyphenated_nist_param(srv, respx_mock, auth_route):
    """Wazuh spells this one requirement with hyphens, unlike the others."""
    route = respx_mock.get(f"{API}/rules").respond(200, json=envelope([]))
    await call(srv, "wazuh_list_rules", compliance="nist_800_53", compliance_value="AU.6")
    assert route.calls[0].request.url.params["nist-800-53"] == "AU.6"


@pytest.mark.respx(assert_all_called=False)
async def test_compliance_filter_without_value_matches_any(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/rules").respond(200, json=envelope([]))
    await call(srv, "wazuh_list_rules", compliance="pci_dss")
    assert route.calls[0].request.url.params["pci_dss"] == ""


@pytest.mark.respx(assert_all_called=False)
async def test_get_rule_includes_definition_file(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/rules").respond(200, json=envelope([
        {"id": 5712, "level": 10, "description": "brute force",
         "filename": "0095-sshd_rules.xml"},
    ]))
    respx_mock.get(f"{API}/rules/files/0095-sshd_rules.xml").respond(
        200, json="<group name=\"sshd\"><rule id=\"5712\" level=\"10\"/></group>"
    )
    out = await call(srv, "wazuh_get_rule", rule_id="5712")
    assert out["severity"] == "medium"
    assert "5712" in out["file_contents"]


@pytest.mark.respx(assert_all_called=False)
async def test_get_rule_tolerates_unreadable_file(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/rules").respond(200, json=envelope([
        {"id": 5712, "level": 10, "filename": "0095-sshd_rules.xml"},
    ]))
    respx_mock.get(f"{API}/rules/files/0095-sshd_rules.xml").respond(
        403, json={"title": "Permission denied"}
    )
    out = await call(srv, "wazuh_get_rule", rule_id="5712")
    assert "rules:read" in out["file_contents_note"]


@pytest.mark.respx(assert_all_called=False)
async def test_missing_rule_is_reported_clearly(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/rules").respond(200, json=envelope([], total=0))
    assert "No rule with ID '99999'" in await call_err(srv, "wazuh_get_rule", rule_id="99999")


# --- SCA / FIM --------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_sca_policies_sorted_worst_first_with_pass_rate(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/sca/001").respond(200, json=envelope([
        {"policy_id": "cis_ubuntu22", "name": "CIS Ubuntu 22", "score": 71,
         "pass": 142, "fail": 58, "total_checks": 200},
        {"policy_id": "cis_docker", "name": "CIS Docker", "score": 40,
         "pass": 40, "fail": 60, "total_checks": 100},
    ]))
    out = await call(srv, "wazuh_sca_policies", agent_id="1")
    assert [p["policy_id"] for p in out["policies"]] == ["cis_docker", "cis_ubuntu22"]
    assert out["policies"][0]["pass_rate_percent"] == 40.0
    assert out["policies"][1]["pass_rate_percent"] == 71.0


@pytest.mark.respx(assert_all_called=False)
async def test_sca_policies_empty_explains_why(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/sca/001").respond(200, json=envelope([], total=0))
    out = await call(srv, "wazuh_sca_policies", agent_id="001")
    assert "disconnected" in out["note"]


@pytest.mark.respx(assert_all_called=False)
async def test_sca_checks_defaults_to_failures(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/sca/001/checks/cis_ubuntu22").respond(
        200, json=envelope([{
            "id": 6001, "title": "Ensure permissions on /etc/passwd", "result": "failed",
            "remediation": "chmod 644 /etc/passwd", "rationale": "Prevent tampering",
        }])
    )
    out = await call(srv, "wazuh_sca_checks", agent_id="001", policy_id="cis_ubuntu22")
    assert route.calls[0].request.url.params["result"] == "failed"
    assert out["items"][0]["remediation"] == "chmod 644 /etc/passwd"


@pytest.mark.respx(assert_all_called=False)
async def test_sca_checks_can_drop_verbose_prose(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/sca/001/checks/p1").respond(200, json=envelope([{
        "id": 1, "title": "t", "result": "failed",
        "remediation": "long text", "rationale": "long text", "description": "long text",
    }]))
    out = await call(srv, "wazuh_sca_checks", agent_id="001", policy_id="p1",
                     include_remediation=False)
    item = out["items"][0]
    assert "remediation" not in item and "rationale" not in item
    assert item["title"] == "t"


@pytest.mark.respx(assert_all_called=False)
async def test_fim_changed_only_builds_query_and_includes_last_scan(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/syscheck/001/last_scan").respond(
        200, json=envelope([{"start": "2026-08-26T02:00:00Z", "end": "2026-08-26T02:05:00Z"}])
    )
    route = respx_mock.get(f"{API}/syscheck/001").respond(200, json=envelope([{
        "file": "/etc/passwd", "type": "file", "changes": 3,
        "sha256": "abc", "mtime": "2026-08-25T09:00:00Z",
    }]))

    out = await call(srv, "wazuh_fim_findings", agent_id="001", changed_only=True)

    assert route.calls[0].request.url.params["q"] == "changes>0"
    assert out["items"][0]["file"] == "/etc/passwd"
    assert out["last_scan"]["start"] == "2026-08-26T02:00:00Z"


@pytest.mark.respx(assert_all_called=False)
async def test_rootcheck_absence_points_at_sca(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/rootcheck/001").respond(404, json={"title": "Not Found"})
    message = await call_err(srv, "wazuh_rootcheck", agent_id="001")
    assert "wazuh_sca_checks" in message


# --- inventory --------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_inventory_projects_per_component(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/syscollector/001/ports").respond(200, json=envelope([{
        "protocol": "tcp", "local": {"ip": "0.0.0.0", "port": 22},
        "state": "listening", "process": "sshd", "pid": 900, "inode": 12345,
    }]))
    out = await call(srv, "wazuh_agent_inventory", agent_id="001", component="ports")
    row = out["items"][0]
    assert row["local.port"] == 22
    assert row["process"] == "sshd"
    assert "inode" not in row, "unprojected fields are dropped"


@pytest.mark.respx(assert_all_called=False)
async def test_inventory_applies_default_sort(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/syscollector/001/processes").respond(
        200, json=envelope([])
    )
    await call(srv, "wazuh_agent_inventory", agent_id="001", component="processes")
    assert route.calls[0].request.url.params["sort"] == "-vm_size"


@pytest.mark.respx(assert_all_called=False)
async def test_inventory_error_is_actionable(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/syscollector/001/hotfixes").respond(
        500, json={"title": "Internal", "detail": "no data"}
    )
    message = await call_err(srv, "wazuh_agent_inventory", agent_id="001", component="hotfixes")
    assert "Windows-only" in message


@pytest.mark.respx(assert_all_called=False)
async def test_find_software_uses_fleet_wide_endpoint(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/experimental/syscollector/packages").respond(
        200, json=envelope([
            {"agent_id": "001", "name": "log4j-core", "version": "2.14.1"},
            {"agent_id": "004", "name": "log4j-core", "version": "2.14.1"},
        ], total=2)
    )
    out = await call(srv, "wazuh_find_software", package="log4j")
    assert route.calls[0].request.url.params["q"] == "name~log4j"
    assert out["affected_agents"] == 2
    assert out["source"] == "experimental fleet-wide endpoint"


@pytest.mark.respx(assert_all_called=False)
async def test_find_software_falls_back_to_per_agent_scan(srv, respx_mock, auth_route):
    """Hardened deployments disable /experimental, so scan agents individually."""
    respx_mock.get(f"{API}/experimental/syscollector/packages").respond(
        400, json={"title": "Bad Request", "detail": "experimental features disabled"}
    )
    respx_mock.get(f"{API}/agents").respond(200, json=envelope([
        {"id": "000", "name": "manager"},
        {"id": "001", "name": "web-01"},
        {"id": "002", "name": "web-02"},
    ]))

    def packages(request: httpx.Request) -> httpx.Response:
        if "/001/" in request.url.path:
            return httpx.Response(200, json=envelope([
                {"name": "log4j-core", "version": "2.14.1", "architecture": "noarch"},
            ]))
        return httpx.Response(200, json=envelope([]))

    respx_mock.get(url__regex=rf"{API}/syscollector/\d+/packages").mock(side_effect=packages)

    out = await call(srv, "wazuh_find_software", package="log4j")

    assert out["source"] == "per-agent scan"
    assert out["agents_scanned"] == 2, "agent 000 (the manager) is excluded"
    assert out["match_count"] == 1
    assert out["matches"][0]["agent_name"] == "web-01"
    assert "experimental" in out["note"]


@pytest.mark.respx(assert_all_called=False)
async def test_find_software_tolerates_failing_agents(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/experimental/syscollector/packages").respond(400, json={})
    respx_mock.get(f"{API}/agents").respond(200, json=envelope([
        {"id": "001", "name": "ok"}, {"id": "002", "name": "broken"},
    ]))

    def packages(request: httpx.Request) -> httpx.Response:
        if "/002/" in request.url.path:
            return httpx.Response(500, json={"title": "boom"})
        return httpx.Response(200, json=envelope([{"name": "openssl", "version": "3.0"}]))

    respx_mock.get(url__regex=rf"{API}/syscollector/\d+/packages").mock(side_effect=packages)

    out = await call(srv, "wazuh_find_software", package="openssl")
    assert out["match_count"] == 1, "one failing agent must not fail the search"


# --- MITRE id handling ------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_mitre_looks_up_attack_numbers_via_external_id(srv, respx_mock, auth_route):
    """Wazuh's `technique_ids` matches STIX ids, so T-numbers need `external_id`."""
    route = respx_mock.get(f"{API}/mitre/techniques").respond(200, json=envelope([
        {"id": "attack-pattern--abc", "external_id": "T1595", "name": "Active Scanning"},
    ]))
    out = await call(srv, "wazuh_mitre", resource="techniques", ids=["T1595"])

    params = route.calls[0].request.url.params
    assert params["q"] == "external_id=T1595"
    assert "technique_ids" not in params, (
        "passing a T-number as technique_ids silently returns nothing"
    )
    assert out["items"][0]["external_id"] == "T1595"


@pytest.mark.respx(assert_all_called=False)
async def test_mitre_ors_multiple_numbers(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/mitre/techniques").respond(200, json=envelope([]))
    await call(srv, "wazuh_mitre", resource="techniques", ids=["T1595", "T1110"])
    assert route.calls[0].request.url.params["q"] == "external_id=T1595,external_id=T1110"


@pytest.mark.respx(assert_all_called=False)
async def test_mitre_routes_stix_ids_to_the_id_field(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/mitre/techniques").respond(200, json=envelope([]))
    await call(srv, "wazuh_mitre", resource="techniques",
               ids=["attack-pattern--0042a9f5", "T1110"])
    assert route.calls[0].request.url.params["q"] == (
        "id=attack-pattern--0042a9f5,external_id=T1110"
    )


@pytest.mark.respx(assert_all_called=False)
async def test_mitre_tactics_accept_ta_numbers(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/mitre/tactics").respond(200, json=envelope([]))
    await call(srv, "wazuh_mitre", resource="tactics", ids=["TA0043"])
    assert route.calls[0].request.url.params["q"] == "external_id=TA0043"
