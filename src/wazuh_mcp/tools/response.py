"""Active-response tooling. Every tool here changes endpoint state."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import WazuhMCPError
from ..formatting import trim

#: Commands shipped with Wazuh. Custom scripts are allowed too, but naming the
#: built-ins in the schema keeps the common cases discoverable.
BUILTIN_COMMANDS = (
    "firewall-drop", "restart-wazuh", "disable-account", "host-deny",
    "route-null", "win_route-null", "netsh",
)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_active_response",
        title="Run an active-response command",
        description=(
            "Execute an active-response command on agents — blocking an IP with "
            "firewall-drop, disabling an account, null-routing a host. This "
            "changes the state of production endpoints and can cut off network "
            "access, so it requires WAZUH_ALLOW_WRITE=true and should be confirmed "
            "with a human before use."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=False,
            open_world_hint=True,
        ),
    )
    async def wazuh_active_response(
        command: Annotated[
            str,
            Field(description=(
                "Command to run. Built-ins: " + ", ".join(BUILTIN_COMMANDS) + ". "
                "A custom script configured on the agent may also be named."
            )),
        ],
        agent_ids: Annotated[
            list[str],
            Field(min_length=1, description=(
                "Agent IDs to run the command on. There is deliberately no "
                "'all agents' shortcut — name the targets explicitly."
            )),
        ],
        arguments: Annotated[
            list[str] | None,
            Field(description=(
                "Arguments for the command, e.g. ['1.2.3.4'] as the IP to block "
                "for firewall-drop."
            )),
        ] = None,
        custom: Annotated[
            bool,
            Field(description=(
                "True when 'command' is a custom script on the agent rather than "
                "a built-in Wazuh AR command."
            )),
        ] = False,
    ) -> dict[str, Any]:
        targets = ", ".join(agent_ids)
        ctx.require_write(f"run active response {command!r} on agents {targets}")

        if not command.strip():
            raise WazuhMCPError("An active-response command name is required")

        manager = await ctx.manager()
        ids = [_pad(a) for a in agent_ids]

        # Wazuh's own AR commands are invoked with a leading '!'; custom scripts
        # are named as configured.
        wire_command = command if custom or command.startswith("!") else f"!{command}"

        body: dict[str, Any] = {"command": wire_command}
        if arguments:
            body["arguments"] = arguments

        response = await manager.request(
            "PUT", "/active-response",
            params={"agents_list": ",".join(ids)}, json=body,
        )
        result = manager.unwrap(response)
        return {
            "command": wire_command,
            "arguments": arguments or [],
            "target_agents": ids,
            "accepted": trim(result["items"]),
            "failed": trim(result["failed"]),
            "message": result["message"],
            "warning": (
                "Wazuh queues active-response commands asynchronously; a successful "
                "response means the command was dispatched, not that it took effect. "
                "Verify on the endpoint or via subsequent alerts."
            ),
        }


def _pad(agent_id: str) -> str:
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text
