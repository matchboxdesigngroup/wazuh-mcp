"""Client for the Wazuh Indexer (OpenSearch, default port 9200)."""

from __future__ import annotations

import logging
from typing import Any

from ..config import IndexerCreds, Settings
from ..errors import UpstreamError
from .base import BaseClient

log = logging.getLogger(__name__)

#: Every index this server may touch lives under this prefix, so a raw-DSL tool
#: cannot be pointed at unrelated indices sharing the cluster. Requiring the
#: namespace rather than an explicit list of index names keeps `wazuh-*` and any
#: future Wazuh index working without loosening the boundary.
REQUIRED_INDEX_PREFIX = "wazuh-"


def validate_index(index: str) -> str:
    """Reject index expressions outside the Wazuh namespace."""
    candidate = index.strip()
    if not candidate:
        raise UpstreamError("Index pattern must not be empty")
    if any(ch in candidate for ch in ("..", "/", "\\", " ")):
        raise UpstreamError(f"Invalid index pattern: {index!r}")
    for part in candidate.split(","):
        part = part.strip().lstrip("-+")
        if not part.startswith(REQUIRED_INDEX_PREFIX):
            raise UpstreamError(
                f"Index {part!r} is outside the Wazuh namespace: patterns must "
                f"start with {REQUIRED_INDEX_PREFIX!r} (e.g. 'wazuh-alerts-*')."
            )
    return candidate


class IndexerClient(BaseClient):
    """Runs searches and aggregations against Wazuh's OpenSearch indices."""

    label = "Wazuh Indexer"

    def __init__(self, creds: IndexerCreds, settings: Settings):
        super().__init__(creds.url, verify=settings.ssl_context, timeout=settings.timeout)
        self._auth = (creds.user, creds.password)
        self._settings = settings

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        response = await self._send(
            method, path, params=params, json=json, auth=self._auth
        )
        return self._decode(response, context=f"{method} {path}")

    async def search(
        self,
        index: str,
        body: dict[str, Any],
        *,
        track_total: bool | int = True,
    ) -> dict[str, Any]:
        """POST a search body and return the raw OpenSearch response."""
        index = validate_index(index)
        params: dict[str, Any] = {
            "track_total_hits": "true" if track_total is True else track_total,
            # An index pattern with no backing indices is a normal state on a
            # fresh cluster, not an error worth surfacing as a failure.
            "ignore_unavailable": "true",
            "allow_no_indices": "true",
        }
        result = await self.request("POST", f"/{index}/_search", params=params, json=body)
        if not isinstance(result, dict):
            raise UpstreamError("Wazuh Indexer returned an unexpected search response")
        if result.get("timed_out"):
            log.warning("Indexer search on %s timed out partially", index)
        return result

    async def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        index = validate_index(index)
        body = {"query": query} if query else {}
        result = await self.request(
            "POST", f"/{index}/_count",
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            json=body or None,
        )
        return int((result or {}).get("count", 0))

    async def indices(self, pattern: str = "wazuh-*") -> list[dict[str, Any]]:
        """List matching indices with doc counts and sizes."""
        validate_index(pattern)
        result = await self.request(
            "GET", f"/_cat/indices/{pattern}",
            params={"format": "json", "h": "index,health,docs.count,store.size", "s": "index"},
        )
        return result if isinstance(result, list) else []

    async def health(self) -> dict[str, Any]:
        result = await self.request("GET", "/_cluster/health")
        return result if isinstance(result, dict) else {}

    async def field_exists(self, index: str, field: str) -> bool:
        """Whether a field is mapped — used to detect schema differences."""
        index = validate_index(index)
        try:
            result = await self.request(
                "GET", f"/{index}/_mapping/field/{field}",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )
        except UpstreamError:
            return False
        if not isinstance(result, dict):
            return False
        return any(
            (entry.get("mappings") or {})
            for entry in result.values()
            if isinstance(entry, dict)
        )


# --- response shaping -------------------------------------------------------


def hits_of(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract `_source` documents from a search response."""
    raw = ((response or {}).get("hits") or {}).get("hits") or []
    out: list[dict[str, Any]] = []
    for hit in raw:
        if not isinstance(hit, dict):
            continue
        doc = dict(hit.get("_source") or {})
        doc["_id"] = hit.get("_id")
        doc["_index"] = hit.get("_index")
        out.append(doc)
    return out


def total_of(response: dict[str, Any]) -> int:
    """Extract the total hit count across OpenSearch response shapes."""
    total = ((response or {}).get("hits") or {}).get("total")
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total or 0)
