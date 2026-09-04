"""Manager-backed tools: agents, health, write gating, escape hatch."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from wazuh_mcp.context import WazuhContext
from wazuh_mcp.server import build_server

from .conftest import API, IDX, envelope, make_settings


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
    assert result.is_error, f"expected failure, got {result.structured_content}"
    return _text(result)


def _text(result) -> str:
    return " ".join(b.text for b in (result.content or []) if getattr(b, "text", None))


# --- agents -----------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_list_agents_projects_and_filters(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/agents").respond(200, json=envelope([{
        "id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "active",
        "version": "Wazuh v4.9.0", "os": {"name": "Ubuntu", "platform": "ubuntu",
                                          "version": "22.04"},
        "group": ["default", "web"], "lastKeepAlive": "2026-08-26T10:00:00Z",
        "internal_key": "should-not-appear",
    }], total=1))

    out = await call(srv, "wazuh_list_agents", status=["active"], os_platform="ubuntu", limit=10)

    agent = out["items"][0]
    assert agent["os.platform"] == "ubuntu"
    assert agent["group"] == ["default", "web"]
    # Only the projected fields survive.
    assert "internal_key" not in agent

    params = route.calls[0].request.url.params
    assert params["status"] == "active"
    assert params["q"] == "os.platform=ubuntu"
    assert params["limit"] == "10"


@pytest.mark.respx(assert_all_called=False)
async def test_list_agents_combines_query_and_platform(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/agents").respond(200, json=envelope([]))
    await call(srv, "wazuh_list_agents", query="version!=v4.9.0", os_platform="windows")
    assert route.calls[0].request.url.params["q"] == "version!=v4.9.0;os.platform=windows"


@pytest.mark.respx(assert_all_called=False)
async def test_get_agent_pads_id_and_tolerates_missing_inventory(srv, respx_mock, auth_route):
    agents = respx_mock.get(f"{API}/agents").respond(
        200, json=envelope([{"id": "007", "name": "db-01", "status": "disconnected"}])
    )
    respx_mock.get(f"{API}/syscollector/007/os").respond(200, json=envelope([]))
    respx_mock.get(f"{API}/syscollector/007/hardware").respond(
        500, json={"title": "Internal error"}
    )
    respx_mock.get(f"{API}/syscollector/007/packages").respond(
        200, json=envelope([{"name": "bash"}], total=412)
    )

    out = await call(srv, "wazuh_get_agent", agent_id="7")

    assert agents.calls[0].request.url.params["agents_list"] == "007", "ID must be zero-padded"
    assert out["agent"]["name"] == "db-01"
    assert out["installed_packages"] == 412
    # A failing component degrades rather than failing the whole call.
    assert "hardware" in out["inventory_unavailable"]


@pytest.mark.respx(assert_all_called=False)
async def test_get_agent_missing_gives_clear_error(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents").respond(200, json=envelope([], total=0))
    message = await call_err(srv, "wazuh_get_agent", agent_id="999")
    assert "No agent with ID '999'" in message


@pytest.mark.respx(assert_all_called=False)
async def test_agent_summary_computes_percentages(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents/summary/status").respond(200, json=envelope([{
        "total": 200, "active": 150, "disconnected": 40, "pending": 5, "never_connected": 5,
    }]))
    respx_mock.get(f"{API}/agents/summary/os").respond(200, json=envelope(["ubuntu", "windows"]))
    respx_mock.get(f"{API}/agents/outdated").respond(
        200, json=envelope([{"id": "003", "name": "old", "version": "Wazuh v4.3.0"}], total=12)
    )
    respx_mock.get(f"{API}/agents/no_group").respond(200, json=envelope([], total=7))
    respx_mock.get(f"{API}/groups").respond(
        200, json=envelope([{"name": "default", "count": 200}])
    )

    out = await call(srv, "wazuh_agent_summary")

    assert out["total_agents"] == 200
    assert out["percent_by_status"]["active"] == 75.0
    assert out["outdated_agent_count"] == 12
    assert out["agents_without_group"] == 7


# --- health -----------------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_health_flags_stopped_daemons_and_yellow_indexer(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/info").respond(
        200, json=envelope([{"version": "v4.9.2", "type": "manager", "max_agents": "10000"}])
    )
    respx_mock.get(f"{API}/manager/status").respond(200, json=envelope([{
        "wazuh-analysisd": "running", "wazuh-remoted": "running",
        "wazuh-modulesd": "stopped", "wazuh-db": "running",
    }]))
    respx_mock.get(f"{API}/agents/summary/status").respond(
        200, json=envelope([{"total": 10, "active": 9, "disconnected": 1}])
    )
    respx_mock.get(f"{API}/cluster/status").respond(
        200, json=envelope([{"enabled": "no", "running": "no"}])
    )
    respx_mock.get(f"{IDX}/_cluster/health").respond(200, json={
        "cluster_name": "wazuh", "status": "yellow", "number_of_nodes": 1,
        "active_shards": 10, "unassigned_shards": 5,
    })

    out = await call(srv, "wazuh_health")

    assert out["daemons_healthy"] is False
    assert out["daemons"]["core_not_running"] == ["wazuh-modulesd"]
    assert "wazuh-modulesd" in out["daemon_warning"]
    assert out["indexer"]["status"] == "yellow"
    assert "unassigned" in out["indexer_warning"]
    assert out["read_only_mode"] is True


@pytest.mark.respx(assert_all_called=False)
async def test_health_does_not_alarm_on_optional_daemons(srv, respx_mock, auth_route):
    """A default single-node install leaves several daemons stopped by design."""
    respx_mock.get(f"{API}/manager/info").respond(200, json=envelope([{"version": "v4.14.7"}]))
    respx_mock.get(f"{API}/manager/status").respond(200, json=envelope([{
        "wazuh-analysisd": "running", "wazuh-remoted": "running",
        "wazuh-db": "running", "wazuh-modulesd": "running",
        # All opt-in features, stopped on a healthy default deployment.
        "wazuh-agentlessd": "stopped", "wazuh-csyslogd": "stopped",
        "wazuh-maild": "stopped", "wazuh-reportd": "stopped",
        "wazuh-clusterd": "stopped",
    }]))
    respx_mock.get(f"{API}/cluster/status").respond(
        200, json=envelope([{"enabled": "no", "running": "no"}])
    )
    respx_mock.get(f"{API}/agents/summary/status").respond(
        200, json=envelope([{"connection": {"active": 2, "total": 2}}])
    )

    respx_mock.get(f"{IDX}/_cluster/health").respond(
        200, json={"cluster_name": "wazuh", "status": "green", "number_of_nodes": 1}
    )

    out = await call(srv, "wazuh_health")

    assert out["daemons_healthy"] is True, "optional daemons must not fail the check"
    assert "daemon_warning" not in out
    assert set(out["daemons"]["optional_not_running"]) == {
        "wazuh-agentlessd", "wazuh-csyslogd", "wazuh-maild",
        "wazuh-reportd", "wazuh-clusterd",
    }


@pytest.mark.respx(assert_all_called=False)
async def test_clusterd_is_core_when_clustering_enabled(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/status").respond(
        200, json=envelope([{"wazuh-analysisd": "running", "wazuh-clusterd": "stopped"}])
    )
    respx_mock.get(f"{API}/cluster/status").respond(
        200, json=envelope([{"enabled": "yes", "running": "yes"}])
    )
    respx_mock.get(f"{IDX}/_cluster/health").respond(
        200, json={"cluster_name": "wazuh", "status": "green", "number_of_nodes": 1}
    )

    out = await call(srv, "wazuh_health")
    assert out["daemons_healthy"] is False
    assert out["daemons"]["core_not_running"] == ["wazuh-clusterd"]


@pytest.mark.respx(assert_all_called=False)
async def test_health_parses_nested_agent_summary(srv, respx_mock, auth_route):
    """Wazuh 4.14 nests counts under `connection` / `configuration`."""
    respx_mock.get(f"{API}/agents/summary/status").respond(200, json=envelope([{
        "connection": {"active": 2, "disconnected": 0, "pending": 0,
                       "never_connected": 0, "total": 2},
        "configuration": {"synced": 1, "not_synced": 1, "total": 2},
    }]))
    respx_mock.get(f"{IDX}/_cluster/health").respond(
        200, json={"cluster_name": "wazuh", "status": "green", "number_of_nodes": 1}
    )

    out = await call(srv, "wazuh_health")
    assert out["agents"] == {
        "total": 2, "active": 2, "disconnected": 0, "pending": 0, "never_connected": 0
    }
    assert out["agent_config_sync"] == {"synced": 1, "not_synced": 1, "total": 2}


@pytest.mark.respx(assert_all_called=False)
async def test_health_reports_unconfigured_backends():
    ctx = WazuhContext(make_settings(api_url=None, indexer_url=None))
    server, _ = build_server(ctx)
    out = await call(server, "wazuh_health")
    assert "not configured" in out["manager"]
    assert "not configured" in out["indexer"]
    await ctx.aclose()


@pytest.mark.respx(assert_all_called=False)
async def test_manager_stats_warns_on_queue_saturation(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/stats/analysisd").respond(200, json={
        "data": {"event_queue_usage": 0.95, "alerts_queue_usage": 0.1,
                 "rule_matching_queue_usage": 0.82, "events_dropped": 1500},
        "error": 0,
    })
    out = await call(srv, "wazuh_manager_stats", kind="analysisd")
    assert "event_queue_usage=0.95" in out["warning"]
    assert "rule_matching_queue_usage=0.82" in out["warning"]
    assert out["events_dropped"] == 1500


@pytest.mark.respx(assert_all_called=False)
async def test_manager_stats_quiet_when_healthy(srv, respx_mock, auth_route):
    respx_mock.get(f"{API}/manager/stats/analysisd").respond(
        200, json={"data": {"event_queue_usage": 0.02}, "error": 0}
    )
    out = await call(srv, "wazuh_manager_stats", kind="analysisd")
    assert "warning" not in out


# --- escape hatch -----------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_api_request_forwards_path_and_params(srv, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/overview/agents").respond(
        200, json=envelope([{"nodes": 1}])
    )
    out = await call(srv, "wazuh_api_request", path="overview/agents", params={"limit": 5})
    assert route.calls[0].request.url.params["limit"] == "5"
    assert out["path"] == "/overview/agents"


@pytest.mark.respx(assert_all_called=False)
async def test_api_request_refuses_agent_key_endpoint(srv, respx_mock, auth_route):
    message = await call_err(srv, "wazuh_api_request", path="/agents/001/key")
    assert "returns credentials" in message


@pytest.mark.respx(assert_all_called=False)
async def test_api_request_refuses_full_url(srv, respx_mock, auth_route):
    message = await call_err(srv, "wazuh_api_request", path="https://evil.test/agents")
    assert "Pass a path, not a URL" in message


# --- write gating -----------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_restart_blocked_in_read_only_mode(srv, respx_mock, auth_route):
    route = respx_mock.put(f"{API}/agents/restart").respond(200, json=envelope(["001"]))
    message = await call_err(srv, "wazuh_restart_agents", agent_ids=["001"])
    assert "WAZUH_ALLOW_WRITE" in message
    assert route.call_count == 0, "no request may reach Wazuh when writes are disabled"


@pytest.mark.respx(assert_all_called=False)
async def test_active_response_blocked_in_read_only_mode(srv, respx_mock, auth_route):
    route = respx_mock.put(f"{API}/active-response").respond(200, json=envelope([]))
    message = await call_err(
        srv, "wazuh_active_response", command="firewall-drop",
        agent_ids=["001"], arguments=["1.2.3.4"],
    )
    assert "WAZUH_ALLOW_WRITE" in message
    assert route.call_count == 0


@pytest.mark.respx(assert_all_called=False)
async def test_active_response_sends_bang_prefixed_command(respx_mock, auth_route):
    ctx = WazuhContext(make_settings(
        api_url=API, api_user="u", api_password="p", verify_ssl=False, allow_write=True,
    ))
    server, _ = build_server(ctx)
    route = respx_mock.put(f"{API}/active-response").respond(
        200, json=envelope(["001"], message="AR command was sent to all agents")
    )

    out = await call(
        server, "wazuh_active_response", command="firewall-drop",
        agent_ids=["1"], arguments=["203.0.113.7"],
    )

    body = json.loads(route.calls[0].request.content)
    assert body == {"command": "!firewall-drop", "arguments": ["203.0.113.7"]}
    assert route.calls[0].request.url.params["agents_list"] == "001"
    assert out["command"] == "!firewall-drop"
    assert "asynchronously" in out["warning"]
    await ctx.aclose()


@pytest.mark.respx(assert_all_called=False)
async def test_custom_active_response_command_not_prefixed(respx_mock, auth_route):
    ctx = WazuhContext(make_settings(
        api_url=API, api_user="u", api_password="p", verify_ssl=False, allow_write=True,
    ))
    server, _ = build_server(ctx)
    route = respx_mock.put(f"{API}/active-response").respond(200, json=envelope([]))
    await call(server, "wazuh_active_response", command="my-script.sh",
               agent_ids=["001"], custom=True)
    assert json.loads(route.calls[0].request.content)["command"] == "my-script.sh"
    await ctx.aclose()


# --- config guards ----------------------------------------------------------


@pytest.mark.respx(assert_all_called=False)
async def test_missing_manager_config_names_env_vars():
    ctx = WazuhContext(make_settings(indexer_url=IDX, indexer_user="u", indexer_password="p"))
    server, _ = build_server(ctx)
    message = await call_err(server, "wazuh_list_agents")
    assert "WAZUH_API_URL" in message and "WAZUH_API_USER" in message
    await ctx.aclose()


@pytest.mark.respx(assert_all_called=False)
async def test_missing_indexer_config_names_env_vars():
    ctx = WazuhContext(make_settings(api_url=API, api_user="u", api_password="p"))
    server, _ = build_server(ctx)
    message = await call_err(server, "wazuh_search_alerts")
    assert "WAZUH_INDEXER_URL" in message
    await ctx.aclose()
