"""Manager API client: auth, token reuse, refresh-on-401, error mapping."""

from __future__ import annotations

import httpx
import pytest

from wazuh_mcp.errors import AuthError, NotFoundError, UpstreamError

from .conftest import API, envelope


@pytest.mark.respx(assert_all_called=False)
async def test_authenticates_once_and_reuses_token(ctx, respx_mock, auth_route):
    agents = respx_mock.get(f"{API}/agents").respond(
        200, json=envelope([{"id": "001", "name": "web-01"}])
    )
    manager = await ctx.manager()

    await manager.list("/agents")
    await manager.list("/agents")

    assert auth_route.call_count == 1, "token should be cached across calls"
    assert agents.call_count == 2
    assert agents.calls[0].request.headers["authorization"].startswith("Bearer ")


@pytest.mark.respx(assert_all_called=False)
async def test_refreshes_token_after_401(ctx, respx_mock, auth_route):
    calls = {"n": 0}

    def agents_handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, json={"title": "Unauthorized"})
        return httpx.Response(200, json=envelope([{"id": "001"}]))

    respx_mock.get(f"{API}/agents").mock(side_effect=agents_handler)
    manager = await ctx.manager()

    result = await manager.list("/agents")

    assert result["items"] == [{"id": "001"}]
    assert auth_route.call_count == 2, "should re-authenticate after a 401"
    assert calls["n"] == 2, "should retry the request once"


@pytest.mark.respx(assert_all_called=False)
async def test_does_not_loop_on_persistent_401(ctx, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents").respond(401, json={"title": "Permission denied"})
    manager = await ctx.manager()

    with pytest.raises(AuthError, match="rejected the credentials"):
        await manager.list("/agents")


@pytest.mark.respx(assert_all_called=False)
async def test_bad_credentials_name_the_env_vars(ctx, respx_mock):
    respx_mock.post(f"{API}/security/user/authenticate").respond(
        401, json={"title": "Unauthorized", "detail": "Invalid credentials"}
    )
    manager = await ctx.manager()

    with pytest.raises(AuthError) as exc:
        await manager.list("/agents")
    assert "WAZUH_API_USER" in str(exc.value)


@pytest.mark.respx(assert_all_called=False)
async def test_404_maps_to_not_found(ctx, respx_mock, auth_route):
    respx_mock.get(f"{API}/agents/999").respond(
        404, json={"title": "Not found", "detail": "Agent does not exist"}
    )
    manager = await ctx.manager()

    with pytest.raises(NotFoundError, match="Agent does not exist"):
        await manager.list("/agents/999")


@pytest.mark.respx(assert_all_called=False)
async def test_connect_error_is_actionable(ctx, respx_mock):
    respx_mock.post(f"{API}/security/user/authenticate").mock(
        side_effect=httpx.ConnectError("refused")
    )
    manager = await ctx.manager()

    with pytest.raises(UpstreamError, match="Cannot reach Wazuh Manager API"):
        await manager.list("/agents")


@pytest.mark.respx(assert_all_called=False)
async def test_retries_503_then_succeeds(ctx, respx_mock, auth_route):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, json={"title": "Service Unavailable"})
        return httpx.Response(200, json=envelope([{"id": "001"}]))

    respx_mock.get(f"{API}/agents").mock(side_effect=handler)
    manager = await ctx.manager()

    result = await manager.list("/agents")
    assert calls["n"] == 3
    assert result["total"] == 1


@pytest.mark.respx(assert_all_called=False)
async def test_unwrap_handles_non_list_payloads(ctx, respx_mock, auth_route):
    """Endpoints like /manager/stats return a bare object, not affected_items."""
    respx_mock.get(f"{API}/manager/stats/analysisd").respond(
        200, json={"data": {"total_events_decoded": 42, "event_queue_usage": 0.9}, "error": 0}
    )
    manager = await ctx.manager()

    result = await manager.list("/manager/stats/analysisd")
    assert result["items"] == [{"total_events_decoded": 42, "event_queue_usage": 0.9}]


@pytest.mark.respx(assert_all_called=False)
async def test_none_params_are_dropped_from_query(ctx, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/agents").respond(200, json=envelope([]))
    manager = await ctx.manager()

    await manager.list("/agents", status=None, group="linux", limit=10)

    query = route.calls[0].request.url.params
    assert "status" not in query
    assert query["group"] == "linux"


@pytest.mark.respx(assert_all_called=False)
async def test_version_tuple_parses_and_caches(ctx, respx_mock, auth_route):
    route = respx_mock.get(f"{API}/manager/info").respond(
        200, json=envelope([{"version": "v4.9.2"}])
    )
    manager = await ctx.manager()

    assert await manager.version_tuple() == (4, 9, 2)
    assert await manager.version_tuple() == (4, 9, 2)
    assert route.call_count == 1, "version should be cached"


@pytest.mark.respx(assert_all_called=False)
async def test_403_is_reported_as_permissions_not_credentials(ctx, respx_mock, auth_route):
    """A 403 means the account lacks a role, not that the password is wrong."""
    respx_mock.get(f"{API}/rules").respond(
        403, json={"title": "Permission denied", "detail": "Not enough permissions"}
    )
    manager = await ctx.manager()

    with pytest.raises(AuthError) as exc:
        await manager.list("/rules")

    message = str(exc.value)
    assert "authorisation problem" in message
    assert "needs a role" in message
    assert "rejected the credentials" not in message, (
        "must not misdirect the reader toward checking the password"
    )


@pytest.mark.respx(assert_all_called=False)
async def test_401_still_points_at_the_credentials(ctx, respx_mock, auth_route):
    respx_mock.get(f"{API}/rules").respond(401, json={"title": "Unauthorized"})
    manager = await ctx.manager()
    with pytest.raises(AuthError, match="username and password"):
        await manager.list("/rules")
