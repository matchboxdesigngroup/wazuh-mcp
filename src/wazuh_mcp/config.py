"""Configuration loaded from environment variables (or a .env file)."""

from __future__ import annotations

import ssl
from functools import cached_property
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigError


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
    timeout: float = Field(default=30.0, gt=0, le=600)
    allow_write: bool = False
    max_results: int = Field(default=500, ge=1, le=10_000)
    alerts_index: str = "wazuh-alerts-*"
    vulnerability_index: str = "wazuh-states-vulnerabilities-*"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

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

    def warnings(self) -> list[str]:
        out: list[str] = []
        if not self.verify_ssl and not self.ca_bundle:
            out.append(
                "TLS verification is DISABLED (WAZUH_VERIFY_SSL=false). "
                "Prefer setting WAZUH_CA_BUNDLE to your Wazuh root CA."
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
