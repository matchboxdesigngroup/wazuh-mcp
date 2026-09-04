"""Error types surfaced to MCP clients as readable messages."""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError


class WazuhMCPError(ToolError):
    """Base class for all errors this server raises deliberately.

    Subclassing the SDK's `ToolError` is what makes these messages reach the
    model. Anything else escaping a tool is treated as a crash and the client
    is told only "Error executing tool <name>", so the diagnostic text we go to
    the trouble of writing would be discarded.
    """


class ConfigError(WazuhMCPError):
    """Required configuration is missing or malformed."""


class AuthError(WazuhMCPError):
    """Credentials were rejected by Wazuh."""


class UpstreamError(WazuhMCPError):
    """Wazuh returned an error response."""

    def __init__(self, message: str, *, status: int | None = None, detail: object = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class NotFoundError(UpstreamError):
    """The requested resource does not exist upstream."""


class WriteDisabledError(WazuhMCPError):
    """A state-changing tool was called while write mode is disabled."""

    def __init__(self, action: str):
        super().__init__(
            f"Refusing to {action}: this server is running read-only. "
            "Set WAZUH_ALLOW_WRITE=true to enable state-changing tools."
        )
