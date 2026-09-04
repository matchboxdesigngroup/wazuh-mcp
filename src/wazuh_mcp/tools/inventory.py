"""System inventory tools built on syscollector."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import UpstreamError
from ..formatting import paged, project, trim

#: Per-component field projections, keeping output readable.
COMPONENT_FIELDS: dict[str, tuple[str, ...]] = {
    "hardware": ("board_serial", "cpu.name", "cpu.cores", "cpu.mhz",
                 "ram.total", "ram.free", "ram.usage"),
    "os": ("hostname", "architecture", "os.name", "os.version", "os.codename",
           "sysname", "release", "version"),
    "packages": ("name", "version", "architecture", "vendor", "format",
                 "install_time", "size", "location", "description"),
    "ports": ("protocol", "local.ip", "local.port", "remote.ip", "remote.port",
              "state", "process", "pid"),
    "processes": ("pid", "ppid", "name", "cmd", "state", "euser", "ruser",
                  "nice", "vm_size", "start_time"),
    "netaddr": ("iface", "proto", "address", "netmask", "broadcast"),
    "netiface": ("name", "adapter", "type", "state", "mtu", "mac",
                 "rx_bytes", "tx_bytes"),
    "netproto": ("iface", "type", "gateway", "dhcp"),
    "hotfixes": ("hotfix",),
}

#: Sensible default sort per component.
COMPONENT_SORT = {
    "packages": "name",
    "processes": "-vm_size",
    "ports": "local.port",
    "hotfixes": "-hotfix",
}

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_agent_inventory",
        title="Read an agent's system inventory",
        description=(
            "Read collected inventory from one endpoint: installed packages, "
            "running processes, listening ports, network interfaces and addresses, "
            "hardware, OS or Windows hotfixes. Use it for questions like 'what is "
            "listening on this host', 'is package X installed', or 'what patches "
            "are missing'."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_agent_inventory(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
        component: Annotated[
            Literal["hardware", "os", "packages", "ports", "processes",
                    "netaddr", "netiface", "netproto", "hotfixes"],
            Field(description="Which inventory component to read."),
        ],
        search: Annotated[
            str | None,
            Field(description=(
                "Substring match across the component's fields, e.g. 'openssl' "
                "for packages or 'nginx' for processes."
            )),
        ] = None,
        query: Annotated[
            str | None,
            Field(description=(
                "Raw Wazuh query filter for precise conditions, e.g. "
                "'local.port=443' for ports or 'state=LISTENING'."
            )),
        ] = None,
        sort: Annotated[
            str | None, Field(description="Sort field, '-' prefix for descending.")
        ] = None,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _pad(agent_id)
        capped = ctx.clamp(limit)

        try:
            result = await manager.list(
                f"/syscollector/{agent_id}/{component}",
                search=search, q=query,
                sort=sort or COMPONENT_SORT.get(component),
                limit=capped, offset=offset,
            )
        except UpstreamError as exc:
            raise UpstreamError(
                f"Could not read {component} inventory for agent {agent_id}: {exc}. "
                "Syscollector data is only present for agents that have connected "
                "and have the module enabled; 'hotfixes' is Windows-only."
            ) from exc

        fields = COMPONENT_FIELDS[component]
        items = [trim(project(row, fields), max_string=1500) for row in result["items"]]
        out = paged(
            items, total=result["total"], limit=capped, offset=offset,
            extra={"agent_id": agent_id, "component": component},
        )
        if not items:
            out["note"] = (
                f"No {component} inventory recorded for agent {agent_id}. "
                "The agent may never have connected, or syscollector may be "
                "disabled for it."
            )
        return out

    @server.tool(
        name="wazuh_find_software",
        title="Find software across the fleet",
        description=(
            "Search for a package across every agent at once — the tool for "
            "vulnerability response questions like 'which hosts have log4j "
            "installed' or 'who is still on OpenSSL 1.1.1'. Returns the matching "
            "package and version per agent."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_find_software(
        package: Annotated[
            str,
            Field(description="Package name or substring to search for, e.g. 'log4j'."),
        ],
        version: Annotated[
            str | None, Field(description="Optional exact version to match.")
        ] = None,
        agent_limit: Annotated[
            int,
            Field(ge=1, le=500, description=(
                "How many agents to scan when the fleet-wide endpoint is "
                "unavailable and results must be gathered agent by agent."
            )),
        ] = 100,
        limit: Annotated[int | None, Field(ge=1, description="Max matching rows to return.")] = 100,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit, default=100)
        conditions = [f"name~{package}"]
        if version:
            conditions.append(f"version={version}")
        query = ";".join(conditions)

        # The experimental endpoint answers across all agents in one call, but is
        # gated behind `experimental_features` in the API config.
        try:
            result = await manager.list(
                "/experimental/syscollector/packages", q=query, limit=capped,
                select="agent_id,name,version,architecture,vendor",
            )
        except UpstreamError:
            return await _find_software_per_agent(
                ctx, manager, query=query, agent_limit=agent_limit, capped=capped,
                package=package,
            )

        rows = [
            project(r, ("agent_id", "name", "version", "architecture", "vendor"))
            for r in result["items"]
        ]
        return {
            "package_query": package,
            "version_filter": version,
            "match_count": len(rows),
            "total_matching": result["total"],
            "affected_agents": len({r.get("agent_id") for r in rows if r.get("agent_id")}),
            "matches": rows,
            "source": "experimental fleet-wide endpoint",
        }


async def _find_software_per_agent(
    ctx: WazuhContext,
    manager: Any,
    *,
    query: str,
    agent_limit: int,
    capped: int,
    package: str,
) -> dict[str, Any]:
    """Fall back to querying each active agent's package inventory.

    Used when `/experimental/*` is disabled on the API, which is the default in
    hardened deployments.
    """
    agents = await manager.list(
        "/agents", status="active", select="id,name",
        limit=ctx.clamp(agent_limit, default=100), sort="id",
    )
    targets = [a for a in agents["items"] if a.get("id") != "000"]

    semaphore = asyncio.Semaphore(8)

    async def probe(agent: dict[str, Any]) -> list[dict[str, Any]]:
        async with semaphore:
            try:
                found = await manager.list(
                    f"/syscollector/{agent['id']}/packages",
                    q=query, limit=20, select="name,version,architecture,vendor",
                )
            except UpstreamError:
                return []
        return [
            {
                "agent_id": agent["id"],
                "agent_name": agent.get("name"),
                **project(row, ("name", "version", "architecture", "vendor")),
            }
            for row in found["items"]
        ]

    gathered = await asyncio.gather(*(probe(a) for a in targets), return_exceptions=True)
    rows: list[dict[str, Any]] = []
    for entry in gathered:
        if isinstance(entry, BaseException):
            continue
        rows.extend(entry)

    truncated = rows[:capped]
    return {
        "package_query": package,
        "match_count": len(truncated),
        "affected_agents": len({r["agent_id"] for r in truncated}),
        "matches": truncated,
        "source": "per-agent scan",
        "agents_scanned": len(targets),
        "note": (
            "The fleet-wide /experimental endpoint is disabled on this API, so "
            f"the {len(targets)} active agent(s) above were queried individually. "
            "Raise agent_limit to cover more of a large fleet."
        ),
    }


def _pad(agent_id: str) -> str:
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text
