"""Bearer-token verification, HTTP transport config and its fail-closed guards."""

from __future__ import annotations

import pytest

from wazuh_mcp.auth import StaticTokenVerifier
from wazuh_mcp.config import MIN_TOKEN_LENGTH
from wazuh_mcp.context import WazuhContext
from wazuh_mcp.errors import ConfigError
from wazuh_mcp.server import build_server, transport_security_for

from .conftest import API, IDX, make_settings

GOOD = "t" * 40
OTHER = "u" * 40
PUBLIC = "https://wazuh.example.com/mcp"


def http_settings(**overrides):
    base = {
        "transport": "http", "public_url": PUBLIC, "auth_tokens": GOOD,
        "api_url": API, "api_user": "u", "api_password": "p",
        "indexer_url": IDX, "indexer_user": "u", "indexer_password": "p",
    }
    base.update(overrides)
    return make_settings(**base)


# --- token verification -----------------------------------------------------


async def test_accepts_a_configured_token():
    verifier = StaticTokenVerifier([GOOD], resource=PUBLIC)
    token = await verifier.verify_token(GOOD)
    assert token is not None
    assert token.scopes == ["wazuh"]
    assert token.resource == PUBLIC


async def test_rejects_anything_else():
    verifier = StaticTokenVerifier([GOOD])
    for candidate in (OTHER, "", GOOD[:-1], GOOD + "x", GOOD.upper(), " " + GOOD):
        assert await verifier.verify_token(candidate) is None, candidate


async def test_accepts_any_of_several_tokens_for_rotation():
    verifier = StaticTokenVerifier([GOOD, OTHER])
    assert await verifier.verify_token(GOOD) is not None
    assert await verifier.verify_token(OTHER) is not None
    assert len(verifier.token_labels) == 2


async def test_token_labels_never_reveal_the_secret():
    verifier = StaticTokenVerifier([GOOD])
    for label in verifier.token_labels:
        assert GOOD not in label
        assert GOOD[:8] not in label


async def test_verifier_needs_at_least_one_token():
    with pytest.raises(ValueError, match="at least one token"):
        StaticTokenVerifier([])


# --- fail-closed guards -----------------------------------------------------


def test_http_without_tokens_is_refused():
    with pytest.raises(ConfigError) as exc:
        http_settings(auth_tokens=None).require_http_auth()
    assert "without authentication" in str(exc.value)
    assert "WAZUH_AUTH_TOKENS" in str(exc.value)


@pytest.mark.parametrize("weak", ["x", "short", "a" * (MIN_TOKEN_LENGTH - 1)])
def test_http_with_a_weak_token_is_refused(weak):
    with pytest.raises(ConfigError, match="shorter than"):
        http_settings(auth_tokens=weak).require_http_auth()


def test_one_weak_token_among_good_ones_is_still_refused():
    with pytest.raises(ConfigError, match="shorter than"):
        http_settings(auth_tokens=f"{GOOD},weak").require_http_auth()


def test_http_without_public_url_is_refused():
    with pytest.raises(ConfigError, match="WAZUH_PUBLIC_URL"):
        http_settings(public_url=None).require_http_auth()


def test_build_server_refuses_unauthenticated_http():
    ctx = WazuhContext(http_settings(auth_tokens=None))
    with pytest.raises(ConfigError, match="without authentication"):
        build_server(ctx)


def test_stdio_needs_no_token():
    """The local transport has no network surface to protect."""
    ctx = WazuhContext(make_settings(
        api_url=API, api_user="u", api_password="p", transport="stdio",
    ))
    server, _ = build_server(ctx)
    assert server is not None


# --- settings derivation ----------------------------------------------------


def test_tokens_are_split_and_stripped():
    assert http_settings(auth_tokens=f" {GOOD} , {OTHER} ").tokens == [GOOD, OTHER]
    assert http_settings(auth_tokens=f"{GOOD},,").tokens == [GOOD]


def test_public_url_gains_a_scheme_and_loses_trailing_slash():
    assert http_settings(public_url="wazuh.example.com/mcp/").public_url == \
        "https://wazuh.example.com/mcp"


def test_http_path_is_normalised():
    assert http_settings(http_path="mcp").http_path == "/mcp"
    assert http_settings(http_path="/mcp/").http_path == "/mcp"


def test_host_allowlist_includes_the_public_name_and_bind_address():
    hosts = http_settings(bind_port=8080).host_allowlist
    assert "wazuh.example.com" in hosts, "the proxy forwards the public Host"
    assert "127.0.0.1:8080" in hosts
    assert "localhost:8080" in hosts


def test_explicit_allowed_hosts_wins():
    hosts = http_settings(allowed_hosts="a.example.com, b.example.com").host_allowlist
    assert hosts == ["a.example.com", "b.example.com"]


def test_transport_security_covers_both_schemes():
    security = transport_security_for(http_settings())
    assert security.enable_dns_rebinding_protection is True
    assert "wazuh.example.com" in security.allowed_hosts
    assert "https://wazuh.example.com" in security.allowed_origins
    assert "http://wazuh.example.com" in security.allowed_origins


# --- warnings ---------------------------------------------------------------


def test_binding_publicly_warns_about_cleartext_tokens():
    warnings = " ".join(http_settings(bind_host="0.0.0.0").warnings())
    assert "clear text" in warnings


def test_loopback_binding_does_not_warn():
    warnings = " ".join(http_settings(bind_host="127.0.0.1").warnings())
    assert "clear text" not in warnings
