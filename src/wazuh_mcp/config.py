"""Configuration loaded from environment variables (or a .env file)."""

from __future__ import annotations

import ssl
from functools import cached_property
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigError

#: Shortest bearer token accepted; 32 chars is `secrets.token_urlsafe(24)`.
MIN_TOKEN_LENGTH = 32


class Settings(BaseSettings):
    """Runtime configuration.

    Every field is optional so the server always starts; tools that need a
    backend call `require_manager()` / `require_indexer()` and fail with a
    message naming the missing variables.
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Manager API (default port 55000) ---
    api_url: str | None = None
    api_user: str | None = None
    api_password: str | None = None

    # --- Indexer / OpenSearch (default port 9200) ---
    indexer_url: str | None = None
    indexer_user: str | None = None
    indexer_password: str | None = None

    # --- TLS ---
    verify_ssl: bool = True
    ca_bundle: str | None = None

    # --- Behaviour ---
    # --- Transport -----------------------------------------------------------
    transport: Literal["stdio", "http"] = "stdio"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8080, ge=1, le=65535)
    http_path: str = "/mcp"
    #: Public URL clients reach this server on, e.g.
    #: https://wazuh.example.com/mcp. Used for the protected-resource metadata
    #: in 401 responses and to derive the allowed Host header.
    public_url: str | None = None
    #: Comma-separated bearer tokens accepted by the HTTP transport. Several
    #: may be listed so a token can be rotated without downtime.
    auth_tokens: str | None = None
    #: Comma-separated Host values to accept, for DNS-rebinding protection.
    #: Derived from public_url when unset.
    allowed_hosts: str | None = None

    timeout: float = Field(default=30.0, gt=0, le=600)
    allow_write: bool = False
    max_results: int = Field(default=500, ge=1, le=10_000)
    alerts_index: str = "wazuh-alerts-*"
    vulnerability_index: str = "wazuh-states-vulnerabilities-*"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    @field_validator("public_url")
    @classmethod
    def _normalise_public_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().rstrip("/")
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        return v

    @field_validator("http_path")
    @classmethod
    def _normalise_http_path(cls, v: str) -> str:
        v = "/" + v.strip().strip("/")
        return v

    @field_validator("api_url", "indexer_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().rstrip("/")
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        return v

    @cached_property
    def ssl_context(self) -> ssl.SSLContext | bool:
        """An httpx-compatible `verify` value.

        A CA bundle takes precedence over `verify_ssl`; self-signed Wazuh
        deployments are common, so `verify_ssl=false` is supported but noisy
        by design (see `warnings()`).
        """
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return self.verify_ssl

    @property
    def tokens(self) -> list[str]:
        """Accepted bearer tokens, in the order they were configured."""
        if not self.auth_tokens:
            return []
        return [t.strip() for t in self.auth_tokens.split(",") if t.strip()]

    @property
    def host_allowlist(self) -> list[str]:
        """Host header values to accept.

        Derived from `public_url` when not set explicitly, since that is the
        name clients actually connect to and therefore what the reverse proxy
        forwards.
        """
        if self.allowed_hosts:
            return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]
        hosts: list[str] = []
        if self.public_url:
            hosts.append(urlparse(self.public_url).netloc)
        hosts.append(f"{self.bind_host}:{self.bind_port}")
        if self.bind_host in ("127.0.0.1", "0.0.0.0"):
            hosts.append(f"localhost:{self.bind_port}")
        return [h for h in dict.fromkeys(hosts) if h]

    def require_http_auth(self) -> list[str]:
        """Validate the HTTP transport is safe to start, returning the tokens.

        Refuses to serve unauthenticated: on the HTTP transport the token is
        the only thing between the internet and a security console, so an
        absent or weak one is a configuration error rather than a warning.
        """
        tokens = self.tokens
        if not tokens:
            raise ConfigError(
                "Refusing to start the HTTP transport without authentication. "
                "Set WAZUH_AUTH_TOKENS to one or more secrets (comma-separated "
                "to allow rotation). Generate one with: "
                "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        weak = [t for t in tokens if len(t) < MIN_TOKEN_LENGTH]
        if weak:
            raise ConfigError(
                f"{len(weak)} configured bearer token(s) are shorter than "
                f"{MIN_TOKEN_LENGTH} characters. This token is the only control "
                "protecting the endpoint, so short values are rejected. "
                "Generate one with: "
                "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        if not self.public_url:
            raise ConfigError(
                "WAZUH_PUBLIC_URL is required for the HTTP transport, e.g. "
                "https://wazuh.example.com/mcp. Clients are told where to find "
                "the resource metadata through it, and it determines which Host "
                "header is accepted."
            )
        return tokens

    def warnings(self) -> list[str]:
        out: list[str] = []
        if not self.verify_ssl and not self.ca_bundle:
            out.append(
                "TLS verification is DISABLED (WAZUH_VERIFY_SSL=false). "
                "Prefer setting WAZUH_CA_BUNDLE to your Wazuh root CA."
            )
        if self.transport == "http" and self.bind_host not in ("127.0.0.1", "localhost"):
            out.append(
                f"The HTTP transport is bound to {self.bind_host}, so it is "
                "reachable directly rather than only through a reverse proxy. "
                "Bind 127.0.0.1 and let the proxy terminate TLS unless you have "
                "a reason not to — a bearer token sent over plain HTTP is "
                "transmitted in clear text."
            )
        if self.allow_write:
            out.append(
                "Write mode is ENABLED: agent restarts, group changes and "
                "active-response tools are callable."
            )
        return out

    # --- Guards -------------------------------------------------------------

    def require_manager(self) -> ManagerCreds:
        missing = [
            name
            for name, value in (
                ("WAZUH_API_URL", self.api_url),
                ("WAZUH_API_USER", self.api_user),
                ("WAZUH_API_PASSWORD", self.api_password),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "Wazuh Manager API is not configured. Missing: " + ", ".join(missing)
            )
        assert self.api_url and self.api_user and self.api_password
        return ManagerCreds(self.api_url, self.api_user, self.api_password)

    def require_indexer(self) -> IndexerCreds:
        missing = [
            name
            for name, value in (
                ("WAZUH_INDEXER_URL", self.indexer_url),
                ("WAZUH_INDEXER_USER", self.indexer_user),
                ("WAZUH_INDEXER_PASSWORD", self.indexer_password),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "Wazuh Indexer is not configured. Missing: "
                + ", ".join(missing)
                + ". Alert search, alert aggregation and 4.8+ vulnerability "
                "state all live in the Indexer."
            )
        assert self.indexer_url and self.indexer_user and self.indexer_password
        return IndexerCreds(self.indexer_url, self.indexer_user, self.indexer_password)


class ManagerCreds:
    __slots__ = ("password", "url", "user")

    def __init__(self, url: str, user: str, password: str):
        self.url, self.user, self.password = url, user, password


class IndexerCreds(ManagerCreds):
    __slots__ = ()


def load_settings() -> Settings:
    return Settings()
