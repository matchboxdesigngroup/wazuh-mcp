"""Entry point: `wazuh-mcp` / `python -m wazuh_mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from pydantic import ValidationError

from .config import Settings, load_settings
from .context import WazuhContext
from .errors import WazuhMCPError
from .server import build_server, transport_security_for

log = logging.getLogger("wazuh_mcp")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wazuh-mcp",
        description=(
            "MCP server for a remote Wazuh deployment. Reads configuration from "
            "the environment or a .env file; the flags below override it."
        ),
    )
    parser.add_argument(
        "--transport", choices=("stdio", "http"),
        help="stdio for a local client, http to serve remote clients (default: stdio).",
    )
    parser.add_argument("--host", help="Address to bind for http (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, help="Port to bind for http (default: 8080).")
    parser.add_argument("--path", help="URL path to serve MCP on (default: /mcp).")
    return parser.parse_args(argv)


def settings_from(args: argparse.Namespace) -> Settings:
    """Apply CLI overrides on top of the environment-derived settings."""
    settings = load_settings()
    overrides = {
        "transport": args.transport,
        "bind_host": args.host,
        "bind_port": args.port,
        "http_path": args.path,
    }
    supplied = {k: v for k, v in overrides.items() if v is not None}
    return settings.model_copy(update=supplied) if supplied else settings


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        ctx = WazuhContext(settings_from(args))
        server, ctx = build_server(ctx)
    except (WazuhMCPError, ValidationError, ValueError) as exc:
        # Configuration problems must be legible: on stdio a traceback is all
        # the operator gets, and the client only reports "server failed".
        # ValueError covers the SDK's own auth-wiring checks. Anything else is
        # a bug and should surface with its traceback.
        print(f"wazuh-mcp: {exc}", file=sys.stderr)
        return 2

    try:
        asyncio.run(_serve(server, ctx))
    except KeyboardInterrupt:
        return 0
    except Exception:
        log.exception("wazuh-mcp exited with an error")
        return 1
    return 0


async def _serve(server: object, ctx: WazuhContext) -> None:
    settings = ctx.settings
    try:
        if settings.transport == "http":
            log.info(
                "Serving MCP over HTTP on %s:%s%s (public: %s)",
                settings.bind_host, settings.bind_port, settings.http_path,
                settings.public_url,
            )
            await server.run_streamable_http_async(  # type: ignore[attr-defined]
                host=settings.bind_host,
                port=settings.bind_port,
                streamable_http_path=settings.http_path,
                transport_security=transport_security_for(settings),
            )
        else:
            await server.run_stdio_async()  # type: ignore[attr-defined]
    finally:
        await ctx.aclose()


if __name__ == "__main__":
    sys.exit(main())
