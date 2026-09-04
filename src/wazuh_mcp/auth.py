"""Bearer-token authentication for the HTTP transport.

A shared static token, not OAuth. The SDK's `BearerAuthBackend` extracts the
`Authorization: Bearer …` header and hands the value to `verify_token`; a None
return produces a 401 carrying the protected-resource metadata URL.
"""

from __future__ import annotations

import hashlib
import logging
import secrets

from mcp.server.auth.provider import AccessToken, TokenVerifier

log = logging.getLogger(__name__)

#: Scope granted to any valid token. The tools do their own authorisation via
#: WAZUH_ALLOW_WRITE, so there is nothing finer to express here.
DEFAULT_SCOPE = "wazuh"


class StaticTokenVerifier(TokenVerifier):
    """Verifies a presented token against a fixed set of accepted secrets.

    Tokens are compared as SHA-256 digests with `secrets.compare_digest`, so
    the comparison runs in constant time over a fixed length and neither the
    token's content nor its length leaks through timing.
    """

    def __init__(self, tokens: list[str], *, resource: str | None = None):
        if not tokens:
            raise ValueError("StaticTokenVerifier requires at least one token")
        self._resource = resource
        # Map digest -> a short stable label, so logs and AccessToken.client_id
        # can identify which token was used without ever revealing it.
        self._accepted: dict[bytes, str] = {}
        for index, token in enumerate(tokens):
            digest = _digest(token)
            self._accepted[digest] = f"token-{index + 1}-{digest.hex()[:8]}"

    async def verify_token(self, token: str) -> AccessToken | None:
        presented = _digest(token)
        for digest, label in self._accepted.items():
            if secrets.compare_digest(presented, digest):
                return AccessToken(
                    token=token,
                    client_id=label,
                    scopes=[DEFAULT_SCOPE],
                    resource=self._resource,
                )
        # Never log the presented value: a mistyped token is often a real one.
        log.warning("Rejected a bearer token that matched no configured secret")
        return None

    @property
    def token_labels(self) -> list[str]:
        """Stable labels for the configured tokens, safe to log."""
        return list(self._accepted.values())


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
