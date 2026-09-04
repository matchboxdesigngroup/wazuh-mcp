"""Holds settings and lazily-constructed clients for the process lifetime."""

from __future__ import annotations

import asyncio
import logging

from .clients import IndexerClient, ManagerClient
from .config import Settings, load_settings
from .errors import WriteDisabledError

log = logging.getLogger(__name__)


class WazuhContext:
    """One instance per server process; clients are built on first use."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self._manager: ManagerClient | None = None
        self._indexer: IndexerClient | None = None
        self._manager_lock = asyncio.Lock()
        self._indexer_lock = asyncio.Lock()

    async def manager(self) -> ManagerClient:
        """The Manager API client, or a ConfigError naming missing env vars."""
        if self._manager is None:
            async with self._manager_lock:
                if self._manager is None:
                    creds = self.settings.require_manager()
                    self._manager = ManagerClient(creds, self.settings)
        return self._manager

    async def indexer(self) -> IndexerClient:
        """The Indexer client, or a ConfigError naming missing env vars."""
        if self._indexer is None:
            async with self._indexer_lock:
                if self._indexer is None:
                    creds = self.settings.require_indexer()
                    self._indexer = IndexerClient(creds, self.settings)
        return self._indexer

    def has_manager(self) -> bool:
        return bool(self.settings.api_url and self.settings.api_user and self.settings.api_password)

    def has_indexer(self) -> bool:
        return bool(
            self.settings.indexer_url
            and self.settings.indexer_user
            and self.settings.indexer_password
        )

    def require_write(self, action: str) -> None:
        """Gate state-changing tools behind WAZUH_ALLOW_WRITE."""
        if not self.settings.allow_write:
            raise WriteDisabledError(action)

    def clamp(self, limit: int | None, default: int = 50) -> int:
        """Keep result counts inside the configured ceiling."""
        value = default if limit is None else int(limit)
        return max(1, min(value, self.settings.max_results))

    async def aclose(self) -> None:
        for client in (self._manager, self._indexer):
            if client is not None:
                try:
                    await client.aclose()
                except Exception:  # pragma: no cover - shutdown best effort
                    log.debug("Error closing client", exc_info=True)
        self._manager = self._indexer = None
