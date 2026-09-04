"""Entry point: `wazuh-mcp` / `python -m wazuh_mcp`."""

from __future__ import annotations

import asyncio
import logging
import sys

from .server import build_server

log = logging.getLogger("wazuh_mcp")


def main() -> int:
    server, ctx = build_server()
    try:
        asyncio.run(_serve(server, ctx))
    except KeyboardInterrupt:
        return 0
    except Exception:
        log.exception("wazuh-mcp exited with an error")
        return 1
    return 0


async def _serve(server: object, ctx: object) -> None:
    try:
        await server.run_stdio_async()  # type: ignore[attr-defined]
    finally:
        await ctx.aclose()  # type: ignore[attr-defined]


if __name__ == "__main__":
    sys.exit(main())
