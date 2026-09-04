from __future__ import annotations

import base64
import json
import os
import time

import pytest

from wazuh_mcp.config import Settings
from wazuh_mcp.context import WazuhContext

API = "https://wazuh.test:55000"
IDX = "https://wazuh.test:9200"


def make_jwt(ttl: int = 900) -> str:
    """A structurally valid unsigned JWT with the given TTL."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + ttl, "sub": "wazuh"}).encode()
    ).decode().rstrip("=")
    return f"header.{payload}.signature"


def envelope(items, total=None, failed=None, message="ok"):
    """The standard Wazuh Manager API response envelope."""
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": total if total is not None else len(items),
            "failed_items": failed or [],
            "total_failed_items": len(failed or []),
        },
        "message": message,
        "error": 0,
    }


def search_response(hits, total=None, aggregations=None):
    """An OpenSearch search response."""
    body = {
        "took": 3,
        "timed_out": False,
        "hits": {
            "total": {"value": total if total is not None else len(hits), "relation": "eq"},
            "hits": [{"_id": f"id{i}", "_index": "wazuh-alerts-4.x-2026.08.26", "_source": h}
                     for i, h in enumerate(hits)],
        },
    }
    if aggregations:
        body["aggregations"] = aggregations
    return body


def make_settings(**overrides):
    """Build Settings isolated from any real configuration.

    `_env_file=None` stops pydantic-settings reading the developer's `.env`,
    which would otherwise silently fill in the very fields a test is trying to
    leave unset — quietly disabling the guard assertions.
    """
    return Settings(_env_file=None, **overrides)


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch):
    """Strip inherited WAZUH_* variables so a real shell cannot leak in."""
    for key in list(os.environ):
        if key.startswith("WAZUH_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def settings():
    return make_settings(
        api_url=API, api_user="wazuh-api", api_password="secret",
        indexer_url=IDX, indexer_user="admin", indexer_password="secret",
        verify_ssl=False, allow_write=False, max_results=500,
    )


@pytest.fixture
async def ctx(settings):
    context = WazuhContext(settings)
    yield context
    await context.aclose()


@pytest.fixture
def auth_route(respx_mock):
    """Register the authentication endpoint; returns the route for assertions."""
    return respx_mock.post(f"{API}/security/user/authenticate").respond(
        200, json={"data": {"token": make_jwt()}, "error": 0}
    )
