"""Builds the MCP server and registers every tool module."""

from __future__ import annotations

import logging
import sys

from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl
from starlette.routing import Route

from .auth import StaticTokenVerifier
from .config import Settings
from .context import WazuhContext
from .tools import MODULES

log = logging.getLogger("wazuh_mcp")

INSTRUCTIONS = """\
This server queries a remote Wazuh deployment: the Manager API for \
configuration, agents, rules and inventory, and the Wazuh Indexer \
(OpenSearch) for alerts and vulnerability state.

Choosing a tool:
- `wazuh_health` first when asked whether Wazuh is healthy, or to orient \
before an investigation.
- `wazuh_search_alerts` for individual alerts; `wazuh_alert_stats` when the \
question is "top N" or "how many by X"; `wazuh_alert_timeline` for trend and \
spikes. Prefer the aggregation tools over fetching alerts and counting them.
- `wazuh_generate_report` when the user wants a shareable report rather than \
raw records; it returns a markdown rendering alongside the data.
- `wazuh_list_agents` / `wazuh_get_agent` for endpoint state, \
`wazuh_agent_inventory` for what is installed or listening on a host, and \
`wazuh_find_software` to locate a package across the whole fleet.
- `wazuh_api_request` and `wazuh_indexer_query` are read-only escape hatches \
for anything the dedicated tools do not cover.

Conventions:
- Time arguments accept relative forms ('30m', '24h', '7d') or ISO-8601. \
Alert queries default to the last 24 hours; reports default to 7 days.
- Severity maps to Wazuh rule levels: critical 15+, high 12-14, medium 7-11, \
low 4-6, info 0-3.
- Agent IDs are zero-padded to three digits; agent 000 is the manager itself.
- Results are paged. When a response includes `next_offset`, more matches \
exist than were returned.

State-changing tools (agent restart, active response, on-demand scans) are \
disabled unless the server is configured with write access. Active response \
affects production endpoints — confirm with the user before invoking it.
"""


def transport_security_for(settings: Settings) -> TransportSecuritySettings:
    """DNS-rebinding protection for the HTTP transport.

    Passed to `run_streamable_http_async`, not to the constructor. Behind a
    reverse proxy the Host header is whatever the proxy forwards, so the
    allowlist has to include the public name as well as the bind address.
    """
    allowlist = settings.host_allowlist
    return TransportSecuritySettings(
        allowed_hosts=allowlist,
        allowed_origins=[
            origin
            for host in allowlist
            for origin in (f"https://{host}", f"http://{host}")
        ],
    )


#: The only unauthenticated path this app adds beyond the SDK's own
#: `/.well-known/oauth-protected-resource/<mcp path>` route. Exact match, no prefix.
ROOT_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"


def _add_root_resource_metadata(server: MCPServer, settings: Settings) -> None:
    """Serve the RFC 9728 metadata at the un-suffixed well-known path too.

    Some clients probe the root form before (or instead of) the path-suffixed
    one; answering 200 spares them the fallback probes that trip Wazuh's
    web-error rules. Public by design: it only restates the URLs in the 401.
    """
    metadata = ProtectedResourceMetadata(
        resource=AnyHttpUrl(settings.public_url),
        authorization_servers=[AnyHttpUrl(settings.effective_issuer_url)],
    )
    handler = ProtectedResourceMetadataHandler(metadata)
    server._custom_starlette_routes.append(
        Route(
            ROOT_RESOURCE_METADATA_PATH,
            endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )
    )


def build_server(ctx: WazuhContext | None = None) -> tuple[MCPServer, WazuhContext]:
    """Construct the server and register all tools.

    Returns the context alongside the server so callers (and tests) can close
    the HTTP clients afterwards.
    """
    context = ctx or WazuhContext()

    logging.basicConfig(
        level=getattr(logging, context.settings.log_level, logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
        # stdout carries the MCP protocol on stdio transport, so logs must not
        # go anywhere near it.
        stream=sys.stderr,
    )

    kwargs: dict[str, object] = {}
    if context.settings.transport == "http":
        # Fails closed: no usable token means the server does not start.
        tokens = context.settings.require_http_auth()
        verifier = StaticTokenVerifier(tokens, resource=context.settings.public_url)
        kwargs["token_verifier"] = verifier
        # The SDK rejects a verifier without AuthSettings. No auth_server_provider
        # is passed, so no OAuth endpoints are created — these URLs only feed the
        # protected-resource metadata that a 401 points at. The SDK serves that
        # metadata, unauthenticated, at /.well-known/oauth-protected-resource/<path>.
        kwargs["auth"] = AuthSettings(
            issuer_url=context.settings.effective_issuer_url,
            resource_server_url=context.settings.public_url,
        )
        log.info(
            "HTTP transport: %d token(s) accepted (%s), Host allowlist %s",
            len(tokens), ", ".join(verifier.token_labels),
            ", ".join(context.settings.host_allowlist),
        )

    server = MCPServer(
        name="wazuh",
        title="Wazuh",
        version="0.1.0",
        instructions=INSTRUCTIONS,
        **kwargs,  # type: ignore[arg-type]
    )

    if context.settings.transport == "http":
        _add_root_resource_metadata(server, context.settings)

    for module in MODULES:
        module.register(server, context)

    for warning in context.settings.warnings():
        log.warning("%s", warning)

    if not context.has_manager() and not context.has_indexer():
        log.warning(
            "Neither the Manager API nor the Indexer is configured. Set "
            "WAZUH_API_URL/USER/PASSWORD and/or WAZUH_INDEXER_URL/USER/PASSWORD; "
            "every tool will otherwise return a configuration error."
        )
    else:
        log.info(
            "Configured backends: %s",
            ", ".join(
                filter(None, [
                    f"manager={context.settings.api_url}" if context.has_manager() else None,
                    f"indexer={context.settings.indexer_url}" if context.has_indexer() else None,
                ])
            ),
        )

    return server, context
