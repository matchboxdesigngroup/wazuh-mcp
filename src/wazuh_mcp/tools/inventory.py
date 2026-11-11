"""System inventory tools built on syscollector."""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import UpstreamError, WazuhMCPError
from ..formatting import paged, project, trim
from ..query import validate_wql_value

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
        capped = ctx.clamp(limit, default=100)
        package = validate_wql_value(package, field="package")
        if version:
            version = validate_wql_value(version, field="version")
        conditions = [f"name~{package}"]
        if version:
            conditions.append(f"version={version}")
        query = ";".join(conditions)
        manager = await ctx.manager()

        # The experimental endpoint answers across all agents in one call, but is
        # gated behind `experimental_features` in the API config.
        try:
            result = await manager.list(
                "/experimental/syscollector/packages", q=query, limit=capped,
                select="agent_id,name,version,architecture,vendor",
            )
        except UpstreamError as exc:
            if not _experimental_endpoint_unavailable(exc):
                raise
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
    scan_limit = ctx.clamp(agent_limit, default=100)
    agents = await manager.list(
        "/agents", status="active", select="id,name,status",
        # Include agent 000 in the API page so the configured limit can still
        # be used for real endpoint scans after excluding the manager.
        limit=scan_limit + 1, sort="id",
    )
    targets = [a for a in agents["items"] if a.get("id") != "000"]
    active_agents_truncated = (
        len(targets) > scan_limit
        or int(agents.get("total") or len(agents["items"])) > len(agents["items"])
    )
    targets = targets[:scan_limit]

    inactive_agents_skipped: int | None = None
    status_error: str | None = None
    try:
        status = await manager.list("/agents/summary/status")
        if status["items"]:
            summary = status["items"][0]
            if isinstance(summary, dict):
                connection = summary.get("connection", summary)
                if isinstance(connection, dict):
                    total = summary.get("total", connection.get("total", 0))
                    active = connection.get("active", 0)
                    if isinstance(total, int) and isinstance(active, int):
                        inactive_agents_skipped = max(0, total - active)
    except WazuhMCPError as exc:
        # Keep a useful per-agent result if the optional status summary is not
        # available, but make the missing coverage count explicit.
        status_error = str(exc)

    semaphore = asyncio.Semaphore(8)

    async def probe(
        agent: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], int, bool]:
        async with semaphore:
            found = await manager.list(
                f"/syscollector/{agent['id']}/packages",
                q=query, limit=20, select="name,version,architecture,vendor",
            )
        rows = [
            {
                "agent_id": agent["id"],
                "agent_name": agent.get("name"),
                **project(row, ("name", "version", "architecture", "vendor")),
            }
            for row in found["items"]
        ]
        total = int(found.get("total") or len(found["items"]))
        return rows, total, total > len(found["items"])

    gathered = await asyncio.gather(*(probe(a) for a in targets), return_exceptions=True)
    rows: list[dict[str, Any]] = []
    agents_failed: list[dict[str, str]] = []
    total_matching = 0
    per_agent_truncated = False
    for agent, entry in zip(targets, gathered):
        if isinstance(entry, asyncio.CancelledError):
            raise entry
        if isinstance(entry, Exception):
            agents_failed.append({
                "agent_id": str(agent.get("id", "")),
                "agent_name": str(agent.get("name") or ""),
                "error": str(entry),
            })
            continue
        if isinstance(entry, BaseException):
            raise entry
        agent_rows, agent_total, agent_truncated = entry
        rows.extend(agent_rows)
        total_matching += agent_total
        per_agent_truncated = per_agent_truncated or agent_truncated

    truncated = rows[:capped]
    truncation_reasons: list[str] = []
    if active_agents_truncated:
        truncation_reasons.append("agent_limit")
    if per_agent_truncated:
        truncation_reasons.append("per_agent_package_limit")
    if len(rows) > capped:
        truncation_reasons.append("result_limit")
    if agents_failed:
        truncation_reasons.append("agent_failures")
    if inactive_agents_skipped:
        truncation_reasons.append("inactive_agents_skipped")
    if status_error is not None or inactive_agents_skipped is None:
        truncation_reasons.append("agent_status_unavailable")
    is_truncated = bool(truncation_reasons)

    note = (
        "The fleet-wide /experimental endpoint is unavailable, so only active "
        f"agents were scanned (up to {scan_limit})."
    )
    if inactive_agents_skipped:
        note += f" {inactive_agents_skipped} inactive agent(s) were skipped."
    if inactive_agents_skipped is None:
        note += " The API could not report how many inactive agents were skipped."
    if agents_failed:
        note += f" {len(agents_failed)} agent request(s) failed; see agents_failed."
    if is_truncated:
        note += " Results are partial; see truncation_reasons."

    return {
        "package_query": package,
        "match_count": len(truncated),
        "total_matching": total_matching,
        "affected_agents": len({r["agent_id"] for r in truncated}),
        "matches": truncated,
        "source": "per-agent scan",
        "agents_scanned": len(targets),
        "agents_failed": agents_failed,
        "inactive_agents_skipped": inactive_agents_skipped,
        "truncated": is_truncated,
        "truncation_reasons": truncation_reasons,
        "note": note,
    }


def _experimental_endpoint_unavailable(exc: UpstreamError) -> bool:
    """Whether Wazuh explicitly says the experimental endpoint is unavailable."""
    if exc.status == 404:
        return True

    message = re.sub(r"[^a-z0-9]+", " ", f"{exc} {exc.detail!s}".casefold()).strip()
    return re.search(
        r"\bexperimental features? (?:are |is |have been |has been )?disabled\b",
        message,
    ) is not None


def _pad(agent_id: str) -> str:
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text
