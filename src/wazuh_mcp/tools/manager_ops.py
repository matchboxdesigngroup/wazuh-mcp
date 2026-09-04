"""Manager and cluster operations: health, daemons, stats, logs, raw API access."""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import WazuhMCPError
from ..formatting import agent_status_counts, classify_daemons, paged, project, trim

#: Paths that return secrets. Blocked from the raw-request tool so agent keys
#: and API tokens cannot be pulled into a model's context by accident.
SECRET_PATH_RE = re.compile(
    r"^/(?:agents/[^/]+/key|security/user/authenticate)", re.IGNORECASE
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_health",
        title="Overall deployment health",
        description=(
            "One-call situational awareness: manager version and uptime, the state "
            "of every Wazuh daemon, cluster status, agent connection counts and "
            "Indexer cluster health. Call this first when asked 'is Wazuh healthy' "
            "or when starting an investigation."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_health() -> dict[str, Any]:
        out: dict[str, Any] = {}
        tasks: dict[str, Any] = {}

        if ctx.has_manager():
            manager = await ctx.manager()
            tasks = {
                "info": manager.list("/manager/info"),
                "status": manager.list("/manager/status"),
                "agents": manager.list("/agents/summary/status"),
                "cluster": manager.list("/cluster/status"),
            }
            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            results = dict(zip(tasks.keys(), gathered))

            info = results["info"]
            if not isinstance(info, BaseException) and info["items"]:
                out["manager"] = project(
                    info["items"][0],
                    ("version", "type", "compilation_date", "max_agents", "installation_date"),
                )

            cluster = results["cluster"]
            cluster_enabled = False
            if not isinstance(cluster, BaseException) and cluster["items"]:
                out["cluster"] = cluster["items"][0]
                cluster_enabled = cluster["items"][0].get("enabled") == "yes"

            status = results["status"]
            if not isinstance(status, BaseException) and status["items"]:
                daemons = classify_daemons(
                    status["items"][0], cluster_enabled=cluster_enabled
                )
                out["daemons"] = daemons
                out["daemons_healthy"] = daemons["healthy"]
                if "warning" in daemons:
                    out["daemon_warning"] = daemons["warning"]

            agents = results["agents"]
            if not isinstance(agents, BaseException) and agents["items"]:
                counts = agent_status_counts(agents["items"][0])
                out["agents"] = {"total": counts["total"], **counts["connection"]}
                if counts["configuration"]:
                    out["agent_config_sync"] = counts["configuration"]

            errors = {k: str(v) for k, v in results.items() if isinstance(v, BaseException)}
            if errors:
                out["manager_errors"] = errors
        else:
            out["manager"] = "not configured (set WAZUH_API_URL/USER/PASSWORD)"

        if ctx.has_indexer():
            try:
                indexer = await ctx.indexer()
                health = await indexer.health()
                out["indexer"] = project(
                    health,
                    ("cluster_name", "status", "number_of_nodes",
                     "active_shards", "unassigned_shards"),
                )
                if health.get("status") in ("yellow", "red"):
                    out["indexer_warning"] = (
                        f"Indexer cluster status is {health['status']}: "
                        f"{health.get('unassigned_shards', 0)} unassigned shard(s)."
                    )
            except WazuhMCPError as exc:
                out["indexer"] = f"unreachable: {exc}"
        else:
            out["indexer"] = "not configured (set WAZUH_INDEXER_URL/USER/PASSWORD)"

        out["read_only_mode"] = not ctx.settings.allow_write
        return out

    @server.tool(
        name="wazuh_cluster_status",
        title="Cluster nodes and health check",
        description=(
            "Detailed cluster view: whether clustering is enabled, each node's "
            "role and address, and the manager's own healthcheck output including "
            "per-node sync status and agent distribution."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_cluster_status() -> dict[str, Any]:
        manager = await ctx.manager()
        status, nodes, healthcheck, local = await asyncio.gather(
            manager.list("/cluster/status"),
            manager.list("/cluster/nodes", limit=ctx.clamp(100)),
            manager.list("/cluster/healthcheck"),
            manager.list("/cluster/local/info"),
            return_exceptions=True,
        )
        out: dict[str, Any] = {}
        if not isinstance(status, BaseException) and status["items"]:
            out["status"] = status["items"][0]
            if status["items"][0].get("enabled") == "no":
                out["note"] = (
                    "Clustering is disabled; this is a single-node deployment and "
                    "node-level details below will be empty."
                )
        if not isinstance(local, BaseException) and local["items"]:
            out["local_node"] = local["items"][0]
        if not isinstance(nodes, BaseException):
            out["nodes"] = [
                project(n, ("name", "type", "version", "ip"))
                for n in nodes["items"]
            ]
        if not isinstance(healthcheck, BaseException):
            out["healthcheck"] = trim(healthcheck["items"])
        return out

    @server.tool(
        name="wazuh_manager_logs",
        title="Read manager logs",
        description=(
            "Read and filter ossec.log entries from the manager. Use this to "
            "diagnose ingestion problems, integration failures or daemon errors — "
            "filter to level='error' to see only what is broken."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_manager_logs(
        level: Annotated[
            Literal["critical", "debug", "debug2", "error", "info", "warning"] | None,
            Field(description="Only entries at this log level."),
        ] = None,
        tag: Annotated[
            str | None,
            Field(description="Only entries from this daemon, e.g. 'wazuh-modulesd'."),
        ] = None,
        search: Annotated[
            str | None, Field(description="Free-text substring match in the message.")
        ] = None,
        summary: Annotated[
            bool,
            Field(description=(
                "Return per-daemon counts by level instead of individual lines — "
                "the fast way to see where errors are concentrated."
            )),
        ] = False,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        if summary:
            result = await manager.list("/manager/logs/summary")
            return {"summary_by_daemon": trim(result["items"])}

        capped = ctx.clamp(limit)
        result = await manager.list(
            "/manager/logs",
            level=level, tag=tag, search=search,
            limit=capped, offset=offset, sort="-timestamp",
        )
        items = [
            trim(project(e, ("timestamp", "tag", "level", "description")), max_string=1500)
            for e in result["items"]
        ]
        return paged(items, total=result["total"], limit=capped, offset=offset)

    @server.tool(
        name="wazuh_manager_stats",
        title="Manager throughput statistics",
        description=(
            "Event-processing statistics from the manager: analysisd queue usage "
            "and event rates, remoted reception counts, or hourly/weekly alert "
            "volumes. Use analysisd stats to spot dropped events and queue "
            "saturation."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_manager_stats(
        kind: Annotated[
            Literal["analysisd", "remoted", "hourly", "weekly", "logcollector"],
            Field(description=(
                "'analysisd' for rule-engine and queue metrics (best for capacity "
                "problems), 'remoted' for agent-communication counters, 'hourly' / "
                "'weekly' for alert volume shape."
            )),
        ] = "analysisd",
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        path = {
            "analysisd": "/manager/stats/analysisd",
            "remoted": "/manager/stats/remoted",
            "hourly": "/manager/stats/hourly",
            "weekly": "/manager/stats/weekly",
            "logcollector": "/manager/stats/logcollector",
        }[kind]
        result = await manager.list(path)
        out: dict[str, Any] = {"kind": kind, "stats": trim(result["items"])}

        if kind == "analysisd" and result["items"]:
            stats = result["items"][0]
            pressure = {
                name: stats.get(name)
                for name in (
                    "event_queue_usage", "rule_matching_queue_usage",
                    "alerts_queue_usage", "firewall_queue_usage",
                    "statistical_queue_usage", "archives_queue_usage",
                )
                if stats.get(name) is not None
            }
            saturated = {k: v for k, v in pressure.items() if _as_float(v) >= 0.8}
            out["queue_usage"] = pressure
            if saturated:
                out["warning"] = (
                    "Queue usage at or above 80% (events may be dropped): "
                    + ", ".join(f"{k}={v}" for k, v in saturated.items())
                )
            dropped = stats.get("events_dropped")
            if dropped:
                out["events_dropped"] = dropped
        return out

    @server.tool(
        name="wazuh_manager_config",
        title="Read manager configuration",
        description=(
            "Read the manager's running ossec.conf configuration, optionally "
            "narrowed to one section. Use this to confirm what is actually "
            "enabled — which modules, integrations, log sources or remote settings."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_manager_config(
        section: Annotated[
            str | None,
            Field(description=(
                "Configuration section to read, e.g. 'global', 'remote', "
                "'syscheck', 'vulnerability-detection', 'wodle', 'integration'. "
                "Omit for the whole configuration, which can be large."
            )),
        ] = None,
        field: Annotated[
            str | None, Field(description="Specific field within the section.")
        ] = None,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        result = await manager.list(
            "/manager/configuration", section=section, field=field
        )
        return {
            "section": section or "all",
            "configuration": trim(result["items"], max_string=8000),
        }

    @server.tool(
        name="wazuh_api_request",
        title="Call any read-only Manager API endpoint",
        description=(
            "Escape hatch for Manager API endpoints without a dedicated tool — "
            "for example /agents/stats/distinct, /tasks/status, /security/users, "
            "/overview/agents, or /experimental/* inventory endpoints. GET only, "
            "so it cannot change state. Prefer the purpose-built tools when one "
            "fits; they shape their output for readability."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_api_request(
        path: Annotated[
            str,
            Field(description=(
                "API path beginning with '/', e.g. '/overview/agents' or "
                "'/syscollector/001/processes'. Do not include the host or port."
            )),
        ],
        params: Annotated[
            dict[str, Any] | None,
            Field(description=(
                "Query parameters, e.g. {'limit': 10, 'q': 'status=active'}. "
                "Wazuh list endpoints accept limit, offset, select, sort, search and q."
            )),
        ] = None,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        clean = path.strip()
        if not clean.startswith("/"):
            clean = "/" + clean
        if "://" in clean or ".." in clean:
            raise WazuhMCPError(f"Invalid API path: {path!r}. Pass a path, not a URL.")
        if SECRET_PATH_RE.match(clean):
            raise WazuhMCPError(
                f"Refusing to fetch {clean}: that endpoint returns credentials "
                "(agent keys or API tokens), which should not be read into a "
                "model's context. Use the Wazuh CLI or dashboard directly."
            )

        body = await manager.request("GET", clean, params=params or None)
        result = manager.unwrap(body)
        return paged(
            [trim(i, max_string=4000) for i in result["items"]],
            total=result["total"],
            limit=int((params or {}).get("limit") or 0),
            offset=int((params or {}).get("offset") or 0),
            extra={"path": clean, "message": result["message"]},
        )


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
