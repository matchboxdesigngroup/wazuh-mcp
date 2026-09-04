"""Shared HTTP plumbing for the Wazuh Manager API and Indexer clients."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..errors import AuthError, NotFoundError, UpstreamError

log = logging.getLogger(__name__)

RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_ATTEMPTS = 3


def _extract_error(payload: Any, fallback: str) -> str:
    """Pull the most useful human message out of a Wazuh/OpenSearch error body."""
    if isinstance(payload, dict):
        # Wazuh Manager API error shape
        for key in ("detail", "title", "message"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        # OpenSearch error shape
        err = payload.get("error")
        if isinstance(err, dict):
            reason = err.get("reason") or err.get("type")
            root = err.get("root_cause")
            if isinstance(root, list) and root and isinstance(root[0], dict):
                reason = root[0].get("reason") or reason
            if reason:
                return str(reason)
        elif isinstance(err, str) and err.strip():
            return err.strip()
    if isinstance(payload, str) and payload.strip():
        return payload.strip()[:500]
    return fallback


class BaseClient:
    """Thin async HTTP wrapper with retries and Wazuh-aware error mapping."""

    #: Label used in error messages, e.g. "Wazuh Manager API".
    label = "Wazuh"

    def __init__(self, base_url: str, *, verify: Any, timeout: float):
        self._base_url = base_url
        self._client = httpx.AsyncClient(
            base_url=base_url,
            verify=verify,
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            headers={"User-Agent": "wazuh-mcp/0.1"},
        )
        self._lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        return self._base_url

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- request -----------------------------------------------------------

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> httpx.Response:
        """Send one request, retrying transient failures with backoff."""
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        last_exc: Exception | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = await self._client.request(
                    method,
                    path,
                    params=clean_params or None,
                    json=json,
                    headers=headers,
                    auth=auth or httpx.USE_CLIENT_DEFAULT,  # type: ignore[arg-type]
                )
            except httpx.ConnectError as exc:
                raise UpstreamError(
                    f"Cannot reach {self.label} at {self._base_url}: {exc}. "
                    "Check the URL, port and network path."
                ) from exc
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt == MAX_ATTEMPTS:
                    raise UpstreamError(
                        f"{self.label} timed out after {MAX_ATTEMPTS} attempts "
                        f"on {method} {path}. Narrow the query or raise WAZUH_TIMEOUT."
                    ) from exc
            except httpx.HTTPError as exc:
                raise UpstreamError(f"{self.label} request failed: {exc}") from exc
            else:
                if response.status_code in RETRY_STATUSES and attempt < MAX_ATTEMPTS:
                    last_exc = None
                    log.debug(
                        "%s returned %s on %s %s; retrying (%d/%d)",
                        self.label, response.status_code, method, path, attempt, MAX_ATTEMPTS,
                    )
                else:
                    return response

            await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

        raise UpstreamError(f"{self.label} request failed after retries") from last_exc

    def _decode(self, response: httpx.Response, *, context: str) -> Any:
        """Raise on error statuses, else return the parsed JSON body."""
        if response.is_success:
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                raise UpstreamError(
                    f"{self.label} returned a non-JSON body for {context}"
                ) from exc

        try:
            payload: Any = response.json()
        except ValueError:
            payload = response.text

        message = _extract_error(payload, response.reason_phrase or "request failed")
        status = response.status_code

        if status == 401:
            raise AuthError(
                f"{self.label} rejected the credentials for {context} "
                f"(HTTP 401): {message}. Check the configured username and password."
            )
        if status == 403:
            # The account authenticated fine; it simply lacks the permission.
            # Saying "bad credentials" here sends people to check passwords when
            # the fix is a role mapping.
            raise AuthError(
                f"{self.label} authenticated the account but denied this request "
                f"for {context} (HTTP 403): {message}. This is an authorisation "
                "problem, not a password problem — the account needs a role "
                "granting the action named above."
            )
        if status == 404:
            raise NotFoundError(
                f"{self.label} has no such resource for {context}: {message}",
                status=status,
                detail=payload,
            )
        raise UpstreamError(
            f"{self.label} error on {context} (HTTP {status}): {message}",
            status=status,
            detail=payload,
        )
