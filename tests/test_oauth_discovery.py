"""Public OAuth discovery endpoints vs. the protected MCP endpoint."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from wazuh_mcp.context import WazuhContext
from wazuh_mcp.server import build_server, transport_security_for

from .test_auth_transport import GOOD, http_settings

PUBLIC = "https://wazuh.example.com/mcp"
BASE = "https://wazuh.example.com"
DISCOVERY = [
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-protected-resource",
]
INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "t", "version": "1"}},
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def make_client(**overrides):
    settings = http_settings(**overrides)
    server, _ = build_server(WazuhContext(settings))
    app = server.streamable_http_app(
        streamable_http_path=settings.http_path,
        transport_security=transport_security_for(settings),
    )
    return TestClient(app, base_url=BASE)


@pytest.fixture
def client():
    with make_client() as c:  # entering runs the app lifespan (session manager)
        yield c


@pytest.mark.parametrize("path", DISCOVERY)
def test_discovery_is_public_and_correct(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["resource"] == PUBLIC
    assert body["authorization_servers"] == [PUBLIC]


def test_issuer_is_configurable():
    with make_client(issuer_url="https://idp.example.com") as c:
        for path in DISCOVERY:
            assert c.get(path).json()["authorization_servers"] == ["https://idp.example.com"]


def test_unauthenticated_mcp_points_at_a_live_metadata_url(client):
    r = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert 'error="invalid_token"' in challenge
    url = challenge.split('resource_metadata="')[1].split('"')[0]
    assert url == f"{BASE}/.well-known/oauth-protected-resource/mcp"
    assert client.get(url.removeprefix(BASE)).status_code == 200


@pytest.mark.parametrize("method", ["get", "delete"])
def test_other_mcp_methods_stay_protected(client, method):
    assert getattr(client, method)("/mcp").status_code == 401


def test_wrong_token_is_rejected(client):
    r = client.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_authenticated_mcp_succeeds(client):
    r = client.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": f"Bearer {GOOD}"})
    assert r.status_code == 200
    assert "wazuh" in r.text


def test_authenticated_bare_get_is_400_without_session(client):
    """Expected stateful Streamable HTTP behaviour, not a bug (see README)."""
    r = client.get("/mcp", headers={"Authorization": f"Bearer {GOOD}",
                                    "Accept": "text/event-stream"})
    assert r.status_code == 400


@pytest.mark.parametrize("path", [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/",
    "/.well-known/oauth-protected-resource/other",
    "/mcp/anything",
    "/authorize", "/token", "/register",
])
def test_no_other_paths_are_exposed(client, path):
    r = client.get(path)
    assert r.status_code in (401, 404)
    assert "resource" not in r.text
