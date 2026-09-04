"""Vulnerability tools, routed across the 4.8 backend change.

Wazuh 4.8 replaced the Vulnerability Detector's API endpoints
(`GET /vulnerability/{agent_id}`) with vulnerability *state* documents in the
`wazuh-states-vulnerabilities-*` Indexer index. Both layouts are supported and
selected from the manager's reported version, falling back to whichever
backend actually answers.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..clients.indexer import hits_of, total_of
from ..context import WazuhContext
from ..errors import ConfigError, UpstreamError, WazuhMCPError
from ..formatting import buckets_to_rows, paged, project, trim
from ..query import build_bool, term_or_terms

#: Version at which vulnerability state moved to the Indexer.
INDEXER_STATE_SINCE = (4, 8)

STATE_FIELDS = (
    "agent.id", "agent.name", "vulnerability.id", "vulnerability.severity",
    "vulnerability.score.base", "vulnerability.score.version",
    "vulnerability.published_at", "vulnerability.detected_at",
    "vulnerability.category", "vulnerability.classification",
    "vulnerability.description", "vulnerability.reference",
    "package.name", "package.version", "package.architecture",
)

API_FIELDS = (
    "cve", "name", "version", "architecture", "severity", "cvss3_score",
    "cvss2_score", "detection_time", "published", "updated", "status",
    "condition", "title",
)

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Untriaged")

#: Wazuh writes a literal "-" when a CVE has no severity assigned yet. On a real
#: deployment this is a large slice of the data, so it must be surfaced under a
#: readable label rather than dropped from the breakdown.
UNSCORED_SEVERITY = "-"
UNSCORED_LABEL = "Untriaged"


def normalise_severity(value: Any) -> str:
    """Map a raw severity bucket key to a readable label."""
    if value is None:
        return UNSCORED_LABEL
    text = str(value).strip()
    return UNSCORED_LABEL if text in ("", UNSCORED_SEVERITY) else text


def order_severity_counts(buckets: list[dict[str, Any]]) -> dict[str, int]:
    """Fold severity buckets into a known-first ordering, dropping nothing.

    Anything unrecognised is appended rather than filtered out, so the counts
    always reconcile with the total number of findings.
    """
    counts: dict[str, int] = {}
    for bucket in buckets:
        label = normalise_severity(bucket.get("key"))
        counts[label] = counts.get(label, 0) + int(bucket.get("count", 0) or 0)
    ordered = {key: counts.pop(key) for key in SEVERITY_ORDER if key in counts}
    ordered.update(dict(sorted(counts.items())))
    return ordered

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


async def uses_indexer_state(ctx: WazuhContext) -> bool:
    """Whether this deployment keeps vulnerability state in the Indexer."""
    if not ctx.has_manager():
        return True
    try:
        manager = await ctx.manager()
        return await manager.version_tuple() >= INDEXER_STATE_SINCE
    except (UpstreamError, WazuhMCPError):
        # If the version is unreadable, prefer the Indexer when it is configured
        # since every currently supported release stores state there.
        return ctx.has_indexer()


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_vulnerabilities",
        title="List detected vulnerabilities",
        description=(
            "List CVEs Wazuh has detected on endpoints, filterable by agent, "
            "severity, CVE ID and package. Answers 'what critical CVEs do we have', "
            "'is CVE-2024-3094 anywhere in the estate', or 'which vulnerable "
            "packages are on this host'. Works on both 4.8+ (Indexer state) and "
            "earlier (Manager API) deployments."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_vulnerabilities(
        agent_id: Annotated[
            list[str] | None,
            Field(description="Restrict to these agent IDs. Omit for the whole fleet (4.8+ only)."),
        ] = None,
        severity: Annotated[
            list[Literal["Critical", "High", "Medium", "Low", "Untriaged"]] | None,
            Field(description="Restrict to these severities."),
        ] = None,
        cve: Annotated[
            list[str] | None, Field(description="Specific CVE IDs, e.g. ['CVE-2024-3094'].")
        ] = None,
        package: Annotated[
            str | None, Field(description="Package name to match, e.g. 'openssl'.")
        ] = None,
        min_score: Annotated[
            float | None, Field(ge=0, le=10, description="Minimum CVSS base score."),
        ] = None,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        if await uses_indexer_state(ctx):
            return await _list_from_indexer(
                ctx, agent_id=agent_id, severity=severity, cve=cve,
                package=package, min_score=min_score, limit=limit, offset=offset,
            )
        return await _list_from_api(
            ctx, agent_id=agent_id, severity=severity, cve=cve,
            package=package, min_score=min_score, limit=limit, offset=offset,
        )

    @server.tool(
        name="wazuh_vulnerability_summary",
        title="Summarise vulnerability exposure",
        description=(
            "Aggregate vulnerability exposure across the fleet: counts by "
            "severity, the most affected agents, the most common CVEs and the "
            "worst offending packages. Use this for exposure reporting and to "
            "decide where to look in detail."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_vulnerability_summary(
        agent_id: Annotated[
            list[str] | None, Field(description="Limit the summary to these agents.")
        ] = None,
        min_severity: Annotated[
            Literal["Critical", "High", "Medium", "Low"] | None,
            Field(description="Only count vulnerabilities at or above this severity."),
        ] = None,
        top: Annotated[int, Field(ge=1, le=100, description="Rows per breakdown.")] = 10,
    ) -> dict[str, Any]:
        if not await uses_indexer_state(ctx):
            return await _summary_from_api(ctx, agent_id=agent_id, top=top)

        indexer = await ctx.indexer()
        filters: list[dict[str, Any]] = []
        clause = term_or_terms("agent.id", agent_id)
        if clause:
            filters.append(clause)
        if min_severity:
            # Deliberately excludes unscored ("-") findings: an unassigned
            # severity cannot be said to meet a floor.
            allowed = SEVERITY_ORDER[: SEVERITY_ORDER.index(min_severity) + 1]
            filters.append({"terms": {"vulnerability.severity": list(allowed)}})

        body = {
            "query": build_bool(filters=filters),
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "by_agent": {
                    "terms": {"field": "agent.name", "size": top},
                    "aggs": {"critical": {
                        "filter": {"term": {"vulnerability.severity": "Critical"}}
                    }},
                },
                "by_cve": {
                    "terms": {"field": "vulnerability.id", "size": top},
                    "aggs": {"agents": {"cardinality": {"field": "agent.id"}}},
                },
                "by_package": {"terms": {"field": "package.name", "size": top}},
                "affected_agents": {"cardinality": {"field": "agent.id"}},
                "distinct_cves": {"cardinality": {"field": "vulnerability.id"}},
                "max_score": {"max": {"field": "vulnerability.score.base"}},
            },
        }
        response = await indexer.search(ctx.settings.vulnerability_index, body)
        aggs = response.get("aggregations") or {}

        by_agent = []
        for bucket in (aggs.get("by_agent") or {}).get("buckets") or []:
            by_agent.append({
                "agent": bucket.get("key"),
                "vulnerabilities": bucket.get("doc_count", 0),
                "critical": ((bucket.get("critical") or {}).get("doc_count", 0)),
            })

        by_cve = []
        for bucket in (aggs.get("by_cve") or {}).get("buckets") or []:
            by_cve.append({
                "cve": bucket.get("key"),
                "occurrences": bucket.get("doc_count", 0),
                "affected_agents": int((bucket.get("agents") or {}).get("value") or 0),
            })

        severity_counts = order_severity_counts(
            buckets_to_rows((aggs.get("by_severity") or {}).get("buckets") or [])
        )

        return {
            "source": "indexer",
            "index": ctx.settings.vulnerability_index,
            "total_findings": total_of(response),
            "affected_agents": int((aggs.get("affected_agents") or {}).get("value") or 0),
            "distinct_cves": int((aggs.get("distinct_cves") or {}).get("value") or 0),
            "highest_cvss": (aggs.get("max_score") or {}).get("value"),
            "by_severity": severity_counts,
            "most_affected_agents": by_agent,
            "most_common_cves": by_cve,
            "worst_packages": buckets_to_rows(
                (aggs.get("by_package") or {}).get("buckets") or [], key_name="package"
            ),
        }


# --- Indexer path (Wazuh 4.8+) ----------------------------------------------


async def _list_from_indexer(
    ctx: WazuhContext,
    *,
    agent_id: list[str] | None,
    severity: list[str] | None,
    cve: list[str] | None,
    package: str | None,
    min_score: float | None,
    limit: int | None,
    offset: int,
) -> dict[str, Any]:
    indexer = await ctx.indexer()
    capped = ctx.clamp(limit)

    filters: list[dict[str, Any]] = []
    for field, value in (
        ("agent.id", agent_id),
        ("vulnerability.severity", severity),
        ("vulnerability.id", cve),
    ):
        clause = term_or_terms(field, value)
        if clause:
            filters.append(clause)
    if min_score is not None:
        filters.append({"range": {"vulnerability.score.base": {"gte": min_score}}})

    must = []
    if package:
        must.append({"match_phrase_prefix": {"package.name": package}})

    body = {
        "query": build_bool(filters=filters, must=must),
        "size": capped,
        "from": offset,
        "sort": [
            {"vulnerability.score.base": {"order": "desc", "missing": "_last"}},
            {"vulnerability.id": {"order": "asc"}},
        ],
    }
    response = await indexer.search(ctx.settings.vulnerability_index, body)
    items = [trim(project(doc, STATE_FIELDS), max_string=600) for doc in hits_of(response)]
    return paged(
        items, total=total_of(response), limit=capped, offset=offset,
        extra={"source": "indexer", "index": ctx.settings.vulnerability_index},
    )


# --- Manager API path (Wazuh < 4.8) -----------------------------------------


async def _list_from_api(
    ctx: WazuhContext,
    *,
    agent_id: list[str] | None,
    severity: list[str] | None,
    cve: list[str] | None,
    package: str | None,
    min_score: float | None,
    limit: int | None,
    offset: int,
) -> dict[str, Any]:
    if not agent_id:
        raise WazuhMCPError(
            "This Wazuh version exposes vulnerabilities per agent through the "
            "Manager API, so agent_id is required. Call wazuh_list_agents first, "
            "or configure the Indexer for fleet-wide queries."
        )
    manager = await ctx.manager()
    capped = ctx.clamp(limit)

    conditions: list[str] = []
    if severity:
        conditions.append("(" + ",".join(f"severity={s}" for s in severity) + ")")
    if cve:
        conditions.append("(" + ",".join(f"cve={c}" for c in cve) + ")")
    if package:
        conditions.append(f"name~{package}")
    if min_score is not None:
        conditions.append(f"cvss3_score>{min_score}")

    per_agent: list[dict[str, Any]] = []
    total = 0
    for aid in agent_id:
        try:
            result = await manager.list(
                f"/vulnerability/{aid}",
                q=";".join(conditions) or None,
                limit=capped, offset=offset, sort="-cvss3_score",
            )
        except UpstreamError as exc:
            per_agent.append({"agent_id": aid, "error": str(exc)})
            continue
        total += result["total"]
        for row in result["items"]:
            entry = project(row, API_FIELDS)
            entry["agent.id"] = aid
            per_agent.append(trim(entry, max_string=600))

    return paged(
        per_agent, total=total, limit=capped, offset=offset,
        extra={"source": "manager_api", "note": (
            "Wazuh < 4.8 layout: results are gathered per agent from "
            "/vulnerability/{agent_id}."
        )},
    )


async def _summary_from_api(
    ctx: WazuhContext, *, agent_id: list[str] | None, top: int
) -> dict[str, Any]:
    manager = await ctx.manager()
    if not agent_id:
        agents = await manager.list("/agents", status="active", select="id", limit=ctx.clamp(200))
        agent_id = [a["id"] for a in agents["items"] if a.get("id") != "000"]
        if not agent_id:
            raise ConfigError("No active agents to summarise vulnerabilities for")

    severity_totals: dict[str, int] = {}
    per_agent: list[dict[str, Any]] = []
    for aid in agent_id[: ctx.clamp(top * 5, default=50)]:
        try:
            summary = await manager.list(f"/vulnerability/{aid}/summary/severity")
        except UpstreamError:
            continue
        counts = summary["items"][0] if summary["items"] else {}
        if not isinstance(counts, dict):
            continue
        agent_total = 0
        for key, value in counts.items():
            if isinstance(value, int):
                severity_totals[key] = severity_totals.get(key, 0) + value
                agent_total += value
        per_agent.append({"agent_id": aid, "vulnerabilities": agent_total,
                          "by_severity": counts})

    per_agent.sort(key=lambda r: r["vulnerabilities"], reverse=True)
    return {
        "source": "manager_api",
        "by_severity": severity_totals,
        "total_findings": sum(severity_totals.values()),
        "affected_agents": len([r for r in per_agent if r["vulnerabilities"]]),
        "most_affected_agents": per_agent[:top],
        "note": (
            "Wazuh < 4.8 layout: aggregated client-side from per-agent severity "
            "summaries, so only the agents sampled above are counted."
        ),
    }


__all__ = ["register", "uses_indexer_state"]
