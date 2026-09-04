"""Client for the Wazuh Manager RESTful API (default port 55000)."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from typing import Any

from ..config import ManagerCreds, Settings
from ..errors import AuthError, UpstreamError
from .base import BaseClient

log = logging.getLogger(__name__)

AUTH_PATH = "/security/user/authenticate"
#: Refresh the JWT this many seconds before it actually expires.
EXPIRY_MARGIN = 30.0
#: Wazuh's default token TTL, used when `exp` cannot be read.
DEFAULT_TTL = 900.0


def _jwt_expiry(token: str) -> float | None:
    """Read `exp` out of a JWT payload without verifying the signature.

    Only used to schedule proactive refresh; a 401 still triggers a retry, so
    a malformed token here is harmless.
    """
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return None
    exp = payload.get("exp")
    return float(exp) if isinstance(exp, (int, float)) else None


class ManagerClient(BaseClient):
    """Talks to the Manager API, handling JWT acquisition and refresh."""

    label = "Wazuh Manager API"

    def __init__(self, creds: ManagerCreds, settings: Settings):
        super().__init__(creds.url, verify=settings.ssl_context, timeout=settings.timeout)
        self._creds = creds
        self._settings = settings
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._version: str | None = None

    # --- auth ---------------------------------------------------------------

    async def _authenticate(self) -> str:
        response = await self._send(
            "POST", AUTH_PATH, auth=(self._creds.user, self._creds.password)
        )
        if response.status_code in (401, 403):
            raise AuthError(
                f"Wazuh Manager API rejected user {self._creds.user!r} "
                f"(HTTP {response.status_code}). Check WAZUH_API_USER / "
                "WAZUH_API_PASSWORD, and that the user has an RBAC role assigned."
            )
        body = self._decode(response, context="authentication")
        token = (body or {}).get("data", {}).get("token")
        if not isinstance(token, str) or not token:
            raise AuthError("Wazuh Manager API returned no token from authentication")

        expiry = _jwt_expiry(token)
        self._token = token
        self._token_expires_at = expiry if expiry else time.time() + DEFAULT_TTL
        log.debug("Acquired Wazuh JWT, expires in %.0fs", self._token_expires_at - time.time())
        return token

    async def _bearer(self) -> str:
        """Return a valid token, refreshing under a lock to avoid a stampede."""
        async with self._lock:
            if self._token and time.time() < self._token_expires_at - EXPIRY_MARGIN:
                return self._token
            return await self._authenticate()

    def _invalidate(self) -> None:
        self._token = None
        self._token_expires_at = 0.0

    # --- requests -----------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> Any:
        """Send an authenticated request, retrying once on an expired token."""
        if not path.startswith("/"):
            path = "/" + path
        context = f"{method} {path}"

        token = await self._bearer()
        response = await self._send(
            method, path, params=params, json=json,
            headers={"Authorization": f"Bearer {token}"},
        )

        if response.status_code == 401:
            # Token was revoked or the TTL estimate was wrong: re-auth once.
            log.debug("Got 401 on %s; refreshing token and retrying", context)
            self._invalidate()
            token = await self._bearer()
            response = await self._send(
                method, path, params=params, json=json,
                headers={"Authorization": f"Bearer {token}"},
            )

        return self._decode(response, context=context)

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params=params)

    # --- envelope helpers ---------------------------------------------------

    @staticmethod
    def unwrap(body: Any) -> dict[str, Any]:
        """Normalise the standard Wazuh `{data: {affected_items, ...}}` envelope.

        Returns a dict with `items`, `total`, `failed` and `message` keys so
        callers do not each re-implement the same digging.
        """
        data = (body or {}).get("data", {}) if isinstance(body, dict) else {}
        if not isinstance(data, dict):
            return {"items": [], "total": 0, "failed": [], "message": None}

        items = data.get("affected_items")
        if items is None:
            # Some endpoints (e.g. /manager/stats) return the payload directly.
            scalar = {k: v for k, v in data.items() if k not in _ENVELOPE_KEYS}
            items = [scalar] if scalar else []

        failed = data.get("failed_items") or []
        return {
            "items": items if isinstance(items, list) else [items],
            "total": data.get("total_affected_items", len(items) if isinstance(items, list) else 1),
            "failed": failed,
            "message": (body or {}).get("message") if isinstance(body, dict) else None,
        }

    async def list(self, path: str, **params: Any) -> dict[str, Any]:
        """GET an endpoint and return its unwrapped envelope."""
        return self.unwrap(await self.get(path, **params))

    # --- version ------------------------------------------------------------

    async def version(self) -> str:
        """Cached manager version string, e.g. `4.9.2`.

        Used to route features that moved between releases (notably the
        vulnerability detector, which left the API in 4.8).
        """
        if self._version is None:
            info = await self.list("/manager/info")
            raw = (info["items"][0] if info["items"] else {}).get("version", "")
            self._version = str(raw).lstrip("v")
        return self._version

    async def version_tuple(self) -> tuple[int, ...]:
        raw = await self.version()
        parts: list[int] = []
        for chunk in raw.split(".")[:3]:
            digits = "".join(c for c in chunk if c.isdigit())
            if not digits:
                break
            parts.append(int(digits))
        if not parts:
            raise UpstreamError(f"Could not parse Wazuh manager version from {raw!r}")
        return tuple(parts)


_ENVELOPE_KEYS = frozenset(
    {"affected_items", "total_affected_items", "failed_items", "total_failed_items"}
)
