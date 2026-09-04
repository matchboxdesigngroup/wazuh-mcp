"""Tools covering the agent fleet: listing, detail, health and grouping."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import NotFoundError
from ..formatting import agent_status_counts, paged, pct, project, trim

AGENT_FIELDS = (
    "id", "name", "ip", "status", "version", "os.name", "os.version",
    "os.platform", "group", "node_name", "lastKeepAlive", "dateAdd",
    "group_config_status", "status_code",
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_list_agents",
        title="List Wazuh agents",
        description=(
            "List and filter agents enrolled with the Wazuh manager. Use this to "
            "answer 'which endpoints are disconnected', 'what agents are in group X', "
            "or 'which agents run an outdated version'. Supports server-side "
            "filtering, sorting and paging."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_list_agents(
        status: Annotated[
            list[Literal["active", "pending", "never_connected", "disconnected"]] | None,
            Field(description="Restrict to these connection states."),
        ] = None,
        group: Annotated[str | None, Field(description="Only agents in this group.")] = None,
        name: Annotated[str | None, Field(description="Exact agent name match.")] = None,
        ip: Annotated[str | None, Field(description="Exact agent IP match.")] = None,
        os_platform: Annotated[
            str | None, Field(description="OS platform, e.g. 'linux', 'windows', 'darwin'.")
        ] = None,
        version: Annotated[
            str | None, Field(description="Agent version, e.g. 'v4.9.0'.")
        ] = None,
        search: Annotated[
            str | None, Field(description="Free-text substring match across agent fields.")
        ] = None,
        query: Annotated[
            str | None,
            Field(
                description=(
                    "Raw Wazuh query filter for conditions the named arguments do not "
                    "cover, e.g. \"os.platform=linux;rule.level>10\". Use ';' for AND, "
                    "',' for OR."
                )
            ),
        ] = None,
        sort: Annotated[
            str | None,
            Field(description="Sort field prefixed with '-' for descending, e.g. '-lastKeepAlive'."),
        ] = None,
        limit: Annotated[int | None, Field(ge=1, description="Max agents to return.")] = 50,
        offset: Annotated[int, Field(ge=0, description="Paging offset.")] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit)
        result = await manager.list(
            "/agents",
            status=",".join(status) if status else None,
            group=group,
            name=name,
            ip=ip,
            version=version,
            search=search,
            q=_and_query(query, f"os.platform={os_platform}" if os_platform else None),
            sort=sort,
            select=",".join(AGENT_FIELDS),
            limit=capped,
            offset=offset,
        )
        items = [project(a, AGENT_FIELDS) for a in result["items"]]
        return paged(items, total=result["total"], limit=capped, offset=offset)

    @server.tool(
        name="wazuh_get_agent",
        title="Get one agent in detail",
        description=(
            "Full picture of a single agent: registration and connection state, "
            "operating system, hardware, group membership and installed-package "
            "count. Start here when investigating a specific endpoint."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_get_agent(
        agent_id: Annotated[
            str, Field(description="Agent ID, e.g. '001'. Zero-padded to 3 digits if shorter.")
        ],
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _normalise_agent_id(agent_id)

        base = await manager.list("/agents", agents_list=agent_id)
        if not base["items"]:
            raise NotFoundError(f"No agent with ID {agent_id!r} is registered")
        agent = base["items"][0]

        # Syscollector data is absent for pending/never-connected agents and for
        # agents with the module disabled, so tolerate failures per-component.
        os_info, hardware, packages = await asyncio.gather(
            manager.list(f"/syscollector/{agent_id}/os"),
            manager.list(f"/syscollector/{agent_id}/hardware"),
            manager.list(f"/syscollector/{agent_id}/packages", limit=1),
            return_exceptions=True,
        )

        out: dict[str, Any] = {"agent": trim(agent)}
        if _ok(os_info) and os_info["items"]:
            out["os_inventory"] = trim(os_info["items"][0])
        if _ok(hardware) and hardware["items"]:
            out["hardware"] = trim(hardware["items"][0])
        if _ok(packages):
            out["installed_packages"] = packages["total"]

        unavailable = [
            label
            for label, value in (("os", os_info), ("hardware", hardware), ("packages", packages))
            if not _ok(value)
        ]
        if unavailable:
            out["inventory_unavailable"] = (
                f"No syscollector data for: {', '.join(unavailable)}. "
                "The agent may be disconnected or have the module disabled."
            )
        return out

    @server.tool(
        name="wazuh_agent_summary",
        title="Fleet health summary",
        description=(
            "Aggregate health of the whole agent fleet: connection-state counts, "
            "OS distribution, agents on outdated versions and agents with no group. "
            "The fastest way to answer 'how healthy is my deployment'."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_agent_summary() -> dict[str, Any]:
        manager = await ctx.manager()
        status, os_summary, outdated, no_group, groups = await asyncio.gather(
            manager.list("/agents/summary/status"),
            manager.list("/agents/summary/os"),
            manager.list("/agents/outdated", limit=ctx.clamp(20)),
            manager.list("/agents/no_group", limit=1, select="id"),
            manager.list("/groups", limit=ctx.clamp(100), select="name,count"),
            return_exceptions=True,
        )

        out: dict[str, Any] = {}

        if _ok(status) and status["items"]:
            counts = agent_status_counts(status["items"][0])
            total = counts["total"]
            connection = counts["connection"]
            out["total_agents"] = total
            out["by_status"] = connection
            out["percent_by_status"] = {k: pct(v, total) for k, v in connection.items()}
            if counts["configuration"]:
                out["config_sync"] = counts["configuration"]
            # The manager counts itself as agent 000 and is always "active".
            out["note"] = "Counts include agent 000, the manager itself."

        if _ok(os_summary):
            out["os_platforms"] = os_summary["items"]

        if _ok(outdated):
            out["outdated_agent_count"] = outdated["total"]
            out["outdated_sample"] = [
                project(a, ("id", "name", "version", "os.platform")) for a in outdated["items"]
            ]

        if _ok(no_group):
            out["agents_without_group"] = no_group["total"]

        if _ok(groups):
            out["groups"] = [project(g, ("name", "count")) for g in groups["items"]]

        failed = [
            label
            for label, value in (
                ("status", status), ("os", os_summary), ("outdated", outdated),
                ("no_group", no_group), ("groups", groups),
            )
            if not _ok(value)
        ]
        if failed:
            out["partial"] = f"Could not read: {', '.join(failed)}"
        return out

    @server.tool(
        name="wazuh_list_groups",
        title="List agent groups",
        description=(
            "List configured agent groups with their member counts and "
            "configuration checksums. Pass a group name to list its members instead."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_list_groups(
        group: Annotated[
            str | None,
            Field(description="If set, list the agents belonging to this group."),
        ] = None,
        limit: Annotated[int | None, Field(ge=1)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit, default=100)
        if group:
            result = await manager.list(
                f"/groups/{group}/agents",
                limit=capped, offset=offset, select=",".join(AGENT_FIELDS),
            )
            items = [project(a, AGENT_FIELDS) for a in result["items"]]
            return paged(
                items, total=result["total"], limit=capped, offset=offset,
                extra={"group": group},
            )
        result = await manager.list("/groups", limit=capped, offset=offset)
        return paged(result["items"], total=result["total"], limit=capped, offset=offset)

    @server.tool(
        name="wazuh_agent_config",
        title="Read an agent's applied configuration",
        description=(
            "Fetch the configuration a running agent has actually loaded for one "
            "module — useful for confirming a group change or centralised config "
            "reached the endpoint. Common pairs: component='syscheck' "
            "configuration='syscheck', component='wmodules' configuration='wmodules', "
            "component='agent' configuration='client'."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_agent_config(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
        component: Annotated[
            Literal["agent", "agentless", "analysis", "auth", "com", "csyslog",
                    "integrator", "logcollector", "mail", "monitor", "request",
                    "syscheck", "wazuh-db", "wmodules"],
            Field(description="Wazuh daemon or component to read."),
        ],
        configuration: Annotated[
            str, Field(description="Configuration section, e.g. 'syscheck', 'client', 'wmodules'.")
        ],
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _normalise_agent_id(agent_id)
        result = await manager.list(
            f"/agents/{agent_id}/config/{component}/{configuration}"
        )
        return {"agent_id": agent_id, "component": component,
                "configuration": configuration, "config": trim(result["items"])}

    @server.tool(
        name="wazuh_restart_agents",
        title="Restart Wazuh agents",
        description=(
            "Restart one or more agents. This interrupts monitoring on the target "
            "endpoints while they come back up, and requires WAZUH_ALLOW_WRITE=true."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=False
        ),
    )
    async def wazuh_restart_agents(
        agent_ids: Annotated[
            list[str],
            Field(min_length=1, description="Agent IDs to restart, e.g. ['001', '002']."),
        ],
    ) -> dict[str, Any]:
        ctx.require_write(f"restart agents {', '.join(agent_ids)}")
        manager = await ctx.manager()
        ids = [_normalise_agent_id(a) for a in agent_ids]
        body = await manager.request(
            "PUT", "/agents/restart", params={"agents_list": ",".join(ids)}
        )
        result = manager.unwrap(body)
        return {
            "restarted": [a.get("id", a) if isinstance(a, dict) else a for a in result["items"]],
            "failed": trim(result["failed"]),
            "message": result["message"],
        }


# --- helpers ----------------------------------------------------------------


def _ok(value: Any) -> bool:
    """Whether a gathered coroutine returned a result rather than an exception."""
    return not isinstance(value, BaseException)


def _normalise_agent_id(agent_id: str) -> str:
    """Wazuh agent IDs are zero-padded to three digits."""
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text


def _and_query(*parts: str | None) -> str | None:
    """Join Wazuh `q` fragments with the AND separator."""
    kept = [p for p in parts if p]
    return ";".join(kept) if kept else None
