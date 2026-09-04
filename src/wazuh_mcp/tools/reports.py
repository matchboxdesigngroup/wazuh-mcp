"""Composite reports: multi-source summaries rendered as markdown."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..clients.indexer import total_of
from ..context import WazuhContext
from ..errors import WazuhMCPError
from ..formatting import (
    agent_status_counts,
    buckets_to_rows,
    classify_daemons,
    pct,
    project,
    severity_of,
)
from ..query import build_bool, term_or_terms, time_range
from .vulnerabilities import order_severity_counts

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)

REPORT_TYPES = (
    "executive_summary", "threat_activity", "agent_health",
    "vulnerability_exposure", "compliance", "file_integrity", "authentication",
)

COMPLIANCE_FIELDS = {
    "pci_dss": "rule.pci_dss",
    "gdpr": "rule.gdpr",
    "hipaa": "rule.hipaa",
    "nist_800_53": "rule.nist_800_53",
    "tsc": "rule.tsc",
}


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_generate_report",
        title="Generate a Wazuh report",
        description=(
            "Build a ready-to-share report by combining several Wazuh sources into "
            "one narrative with a markdown rendering. Report types: "
            "executive_summary (posture overview for leadership), threat_activity "
            "(top threats, MITRE breakdown, attacking IPs), agent_health "
            "(connectivity and version drift), vulnerability_exposure (CVE "
            "exposure by severity and host), compliance (control coverage for a "
            "framework), file_integrity (FIM change activity), authentication "
            "(login failures and brute-force patterns). Use this instead of "
            "stitching many tool calls together by hand."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_generate_report(
        report_type: Annotated[
            Literal[
                "executive_summary", "threat_activity", "agent_health",
                "vulnerability_exposure", "compliance", "file_integrity",
                "authentication",
            ],
            Field(description="Which report to build."),
        ] = "executive_summary",
        start: Annotated[
            str | None,
            Field(description="Window start: relative ('7d', '24h') or ISO-8601. Defaults to 7d."),
        ] = None,
        end: Annotated[str | None, Field(description="Window end. Defaults to now.")] = None,
        framework: Annotated[
            Literal["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"] | None,
            Field(description="Required for report_type='compliance'."),
        ] = None,
        agent_id: Annotated[
            list[str] | None,
            Field(description="Scope the report to specific agents. Omit for the whole fleet."),
        ] = None,
        top: Annotated[
            int, Field(ge=1, le=50, description="Rows per breakdown table.")
        ] = 10,
    ) -> dict[str, Any]:
        window = {"start": start or "7d", "end": end or "now"}
        builder = {
            "executive_summary": _executive_summary,
            "threat_activity": _threat_activity,
            "agent_health": _agent_health,
            "vulnerability_exposure": _vulnerability_exposure,
            "compliance": _compliance,
            "file_integrity": _file_integrity,
            "authentication": _authentication,
        }[report_type]

        data = await builder(
            ctx, start=start, end=end, agent_id=agent_id, top=top, framework=framework
        )
        return {
            "report_type": report_type,
            "window": f"{window['start']} → {window['end']}",
            "scope": f"agents {', '.join(agent_id)}" if agent_id else "all agents",
            "data": data,
            "report_markdown": data.pop("_markdown", ""),
        }


# --- report builders --------------------------------------------------------


async def _executive_summary(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """Posture overview: fleet health, alert severity mix, worst offenders."""
    fleet_task = _fleet_snapshot(ctx) if ctx.has_manager() else _none()
    alerts_task = _severity_mix(ctx, start, end, agent_id) if ctx.has_indexer() else _none()
    rules_task = (
        _top_terms(ctx, "rule.description", start, end, agent_id, top, min_level=7)
        if ctx.has_indexer() else _none()
    )
    agents_task = (
        _top_terms(ctx, "agent.name", start, end, agent_id, top, min_level=7)
        if ctx.has_indexer() else _none()
    )
    vuln_task = _vuln_severity(ctx, agent_id) if ctx.has_indexer() else _none()

    fleet, severity, rules, agents, vulns = await asyncio.gather(
        fleet_task, alerts_task, rules_task, agents_task, vuln_task,
        return_exceptions=True,
    )

    data: dict[str, Any] = {
        "fleet": _unwrap(fleet),
        "alert_severity_mix": _unwrap(severity),
        "top_rules": _unwrap(rules),
        "noisiest_agents": _unwrap(agents),
        "vulnerability_severity": _unwrap(vulns),
    }

    lines = ["# Wazuh Executive Summary", "", f"**Window:** {start or '7d'} → {end or 'now'}", ""]

    fleet_data = data["fleet"]
    if isinstance(fleet_data, dict) and fleet_data.get("total_agents") is not None:
        total = fleet_data["total_agents"]
        active = fleet_data.get("by_status", {}).get("active", 0)
        lines += [
            "## Fleet",
            "",
            (
                f"- **{total}** agents registered, **{active}** active "
                f"({pct(active, total)}%)"
            ),
        ]
        for state in ("disconnected", "pending", "never_connected"):
            count = fleet_data.get("by_status", {}).get(state)
            if count:
                lines.append(f"- **{count}** {state.replace('_', ' ')}")
        if fleet_data.get("stopped_daemons"):
            lines.append(
                f"- ⚠️ Daemons not running: {', '.join(fleet_data['stopped_daemons'])}"
            )
        lines.append("")

    sev = data["alert_severity_mix"]
    if isinstance(sev, dict) and sev.get("total"):
        lines += ["## Alert volume", "", f"- **{sev['total']:,}** alerts in window"]
        for band in ("critical", "high", "medium", "low", "info"):
            count = sev.get("by_severity", {}).get(band)
            if count:
                lines.append(f"- {band.capitalize()}: **{count:,}** ({pct(count, sev['total'])}%)")
        lines.append("")

    lines += _table_section("Top rules (level 7+)", data["top_rules"], "rule.description")
    lines += _table_section("Noisiest agents (level 7+)", data["noisiest_agents"], "agent.name")

    vuln = data["vulnerability_severity"]
    if isinstance(vuln, dict) and vuln.get("by_severity"):
        lines += ["## Vulnerability exposure", ""]
        for key, count in vuln["by_severity"].items():
            lines.append(f"- {key}: **{count:,}** findings")
        lines.append("")

    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _threat_activity(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """What attacked us, how, and from where."""
    _require_indexer(ctx, "threat_activity")
    tactics, techniques, sources, targets, rules = await asyncio.gather(
        _top_terms(ctx, "rule.mitre.tactic", start, end, agent_id, top),
        _top_terms(ctx, "rule.mitre.technique", start, end, agent_id, top),
        _top_terms(ctx, "data.srcip", start, end, agent_id, top, min_level=5),
        _top_terms(ctx, "agent.name", start, end, agent_id, top, min_level=10),
        _top_terms(ctx, "rule.description", start, end, agent_id, top, min_level=10),
        return_exceptions=True,
    )
    data = {
        "mitre_tactics": _unwrap(tactics),
        "mitre_techniques": _unwrap(techniques),
        "top_source_ips": _unwrap(sources),
        "most_targeted_agents": _unwrap(targets),
        "top_high_severity_rules": _unwrap(rules),
    }
    lines = [
        "# Threat Activity Report", "",
        f"**Window:** {start or '7d'} → {end or 'now'}", "",
    ]
    lines += _table_section("MITRE tactics observed", data["mitre_tactics"], "rule.mitre.tactic")
    lines += _table_section("MITRE techniques observed", data["mitre_techniques"], "rule.mitre.technique")
    lines += _table_section("Top source IPs (level 5+)", data["top_source_ips"], "data.srcip")
    lines += _table_section("Most targeted agents (level 10+)", data["most_targeted_agents"], "agent.name")
    lines += _table_section("Top high-severity rules", data["top_high_severity_rules"], "rule.description")
    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _agent_health(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """Connectivity, version drift and grouping gaps."""
    _require_manager(ctx, "agent_health")
    manager = await ctx.manager()
    summary, outdated, stale, no_group = await asyncio.gather(
        manager.list("/agents/summary/status"),
        manager.list("/agents/outdated", limit=ctx.clamp(top, default=10),
                     select="id,name,version,os.platform"),
        manager.list("/agents", status="disconnected", limit=ctx.clamp(top, default=10),
                     select="id,name,ip,version,lastKeepAlive", sort="lastKeepAlive"),
        manager.list("/agents/no_group", limit=ctx.clamp(top, default=10), select="id,name"),
        return_exceptions=True,
    )

    counts: dict[str, Any] = {}
    total = 0
    config_sync: dict[str, Any] = {}
    if not isinstance(summary, BaseException) and summary["items"]:
        parsed = agent_status_counts(summary["items"][0])
        total = parsed["total"]
        counts = parsed["connection"]
        config_sync = parsed["configuration"]

    data: dict[str, Any] = {
        "total_agents": total,
        "by_status": counts,
        "outdated_count": 0 if isinstance(outdated, BaseException) else outdated["total"],
        "outdated_agents": [] if isinstance(outdated, BaseException) else [
            project(a, ("id", "name", "version", "os.platform")) for a in outdated["items"]
        ],
        "longest_disconnected": [] if isinstance(stale, BaseException) else [
            project(a, ("id", "name", "ip", "version", "lastKeepAlive")) for a in stale["items"]
        ],
        "ungrouped_count": 0 if isinstance(no_group, BaseException) else no_group["total"],
        "config_sync": config_sync,
    }

    lines = ["# Agent Health Report", "", f"**{total}** agents registered.", "", "## Connection state", ""]
    lines.append("| State | Agents | Share |")
    lines.append("| --- | --: | --: |")
    for state, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {state} | {count:,} | {pct(count, total)}% |")
    lines.append("")

    if data["outdated_agents"]:
        lines += [
            f"## Outdated agents ({data['outdated_count']} total)", "",
            "| ID | Name | Version | Platform |", "| --- | --- | --- | --- |",
        ]
        for a in data["outdated_agents"]:
            lines.append(
                f"| {a.get('id','')} | {a.get('name','')} | "
                f"{a.get('version','')} | {a.get('os.platform','')} |"
            )
        lines.append("")

    if data["longest_disconnected"]:
        lines += [
            "## Longest disconnected", "",
            "| ID | Name | IP | Last keepalive |", "| --- | --- | --- | --- |",
        ]
        for a in data["longest_disconnected"]:
            lines.append(
                f"| {a.get('id','')} | {a.get('name','')} | "
                f"{a.get('ip','')} | {a.get('lastKeepAlive','')} |"
            )
        lines.append("")

    not_synced = config_sync.get("not_synced")
    if not_synced:
        lines += [
            (
                f"⚠️ **{not_synced}** agent(s) have not synced their centralised "
                "configuration."
            ),
            "",
        ]

    if data["ungrouped_count"]:
        lines += [
            (
                f"⚠️ **{data['ungrouped_count']}** agent(s) belong to no "
                "group and may not be receiving centralised configuration."
            ),
            "",
        ]

    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _vulnerability_exposure(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """CVE exposure by severity, host and package."""
    _require_indexer(ctx, "vulnerability_exposure")
    indexer = await ctx.indexer()
    filters = [c for c in (term_or_terms("agent.id", agent_id),) if c]
    body = {
        "query": build_bool(filters=filters),
        "size": 0,
        "aggs": {
            "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "by_agent": {"terms": {"field": "agent.name", "size": top}},
            "by_cve": {
                "terms": {"field": "vulnerability.id", "size": top},
                "aggs": {"agents": {"cardinality": {"field": "agent.id"}}},
            },
            "by_package": {"terms": {"field": "package.name", "size": top}},
            "affected_agents": {"cardinality": {"field": "agent.id"}},
            "distinct_cves": {"cardinality": {"field": "vulnerability.id"}},
        },
    }
    response = await indexer.search(ctx.settings.vulnerability_index, body)
    aggs = response.get("aggregations") or {}
    total = total_of(response)

    by_severity = order_severity_counts(
        buckets_to_rows((aggs.get("by_severity") or {}).get("buckets") or [])
    )
    data: dict[str, Any] = {
        "total_findings": total,
        "affected_agents": int((aggs.get("affected_agents") or {}).get("value") or 0),
        "distinct_cves": int((aggs.get("distinct_cves") or {}).get("value") or 0),
        "by_severity": by_severity,
        "by_agent": buckets_to_rows((aggs.get("by_agent") or {}).get("buckets") or [], key_name="agent"),
        "top_cves": [
            {"cve": b.get("key"), "occurrences": b.get("doc_count"),
             "affected_agents": int((b.get("agents") or {}).get("value") or 0)}
            for b in (aggs.get("by_cve") or {}).get("buckets") or []
        ],
        "top_packages": buckets_to_rows(
            (aggs.get("by_package") or {}).get("buckets") or [], key_name="package"
        ),
    }

    lines = [
        "# Vulnerability Exposure Report", "",
        (
            f"**{data['total_findings']:,}** findings across "
            f"**{data['affected_agents']}** agents, "
            f"**{data['distinct_cves']:,}** distinct CVEs."
        ),
        "",
        "## By severity", "", "| Severity | Findings | Share |", "| --- | --: | --: |",
    ]
    for key, count in by_severity.items():
        lines.append(f"| {key} | {count:,} | {pct(count, total)}% |")
    lines.append("")

    if data["top_cves"]:
        lines += ["## Most widespread CVEs", "", "| CVE | Occurrences | Agents |", "| --- | --: | --: |"]
        for row in data["top_cves"]:
            lines.append(f"| {row['cve']} | {row['occurrences']:,} | {row['affected_agents']} |")
        lines.append("")

    lines += _table_section("Most affected agents", data["by_agent"], "agent")
    lines += _table_section("Most vulnerable packages", data["top_packages"], "package")
    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _compliance(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """Control coverage and hits for one compliance framework."""
    if not framework:
        raise WazuhMCPError(
            "report_type='compliance' needs a framework. Choose one of: "
            + ", ".join(COMPLIANCE_FIELDS)
        )
    _require_indexer(ctx, "compliance")
    field = COMPLIANCE_FIELDS[framework]
    indexer = await ctx.indexer()

    filters: list[dict[str, Any]] = [
        time_range(start, end, default_start="7d"),
        {"exists": {"field": field}},
    ]
    clause = term_or_terms("agent.id", agent_id)
    if clause:
        filters.append(clause)

    body = {
        "query": build_bool(filters=filters),
        "size": 0,
        "aggs": {
            "by_control": {
                "terms": {"field": field, "size": max(top, 25)},
                "aggs": {"agents": {"cardinality": {"field": "agent.id"}}},
            },
            "by_agent": {"terms": {"field": "agent.name", "size": top}},
            "by_level": {"terms": {"field": "rule.level", "size": 16}},
        },
    }
    response = await indexer.search(ctx.settings.alerts_index, body)
    aggs = response.get("aggregations") or {}
    total = total_of(response)

    controls = [
        {"control": b.get("key"), "alerts": b.get("doc_count"),
         "agents": int((b.get("agents") or {}).get("value") or 0)}
        for b in (aggs.get("by_control") or {}).get("buckets") or []
    ]
    levels = buckets_to_rows((aggs.get("by_level") or {}).get("buckets") or [], key_name="level")

    data: dict[str, Any] = {
        "framework": framework,
        "total_alerts_mapped": total,
        "controls_triggered": len(controls),
        "by_control": controls,
        "by_agent": buckets_to_rows((aggs.get("by_agent") or {}).get("buckets") or [], key_name="agent"),
        "by_rule_level": [
            {**row, "severity": severity_of(row["level"])} for row in levels
        ],
    }

    label = framework.upper().replace("_", " ")
    lines = [
        f"# {label} Compliance Report", "",
        f"**Window:** {start or '7d'} → {end or 'now'}", "",
        (
            f"**{total:,}** alerts mapped to **{len(controls)}** distinct "
            f"{label} controls."
        ),
        "",
    ]
    if controls:
        lines += ["## Controls triggered", "", "| Control | Alerts | Agents |", "| --- | --: | --: |"]
        for row in controls[:max(top, 25)]:
            lines.append(f"| {row['control']} | {row['alerts']:,} | {row['agents']} |")
        lines.append("")
    lines += _table_section("Agents generating mapped alerts", data["by_agent"], "agent")
    lines.append(
        "> Alert counts show which controls are *generating findings*, not an "
        "attestation of compliance. Pair this with SCA policy scores "
        "(wazuh_sca_policies) for configuration-level assessment."
    )
    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _file_integrity(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """FIM change activity from syscheck alerts."""
    _require_indexer(ctx, "file_integrity")
    paths, events, agents = await asyncio.gather(
        _top_terms(ctx, "syscheck.path", start, end, agent_id, top, rule_group=["syscheck"]),
        _top_terms(ctx, "syscheck.event", start, end, agent_id, 10, rule_group=["syscheck"]),
        _top_terms(ctx, "agent.name", start, end, agent_id, top, rule_group=["syscheck"]),
        return_exceptions=True,
    )
    data = {
        "most_changed_paths": _unwrap(paths),
        "event_types": _unwrap(events),
        "most_active_agents": _unwrap(agents),
    }
    lines = [
        "# File Integrity Report", "",
        f"**Window:** {start or '7d'} → {end or 'now'}", "",
    ]
    lines += _table_section("Change events by type", data["event_types"], "syscheck.event")
    lines += _table_section("Most frequently changed paths", data["most_changed_paths"], "syscheck.path")
    lines += _table_section("Agents with most FIM activity", data["most_active_agents"], "agent.name")
    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


async def _authentication(
    ctx: WazuhContext, *, start: str | None, end: str | None,
    agent_id: list[str] | None, top: int, framework: str | None,
) -> dict[str, Any]:
    """Authentication failures, targeted accounts and attacking sources."""
    _require_indexer(ctx, "authentication")
    failures, sources, users, targets, brute = await asyncio.gather(
        _top_terms(ctx, "rule.description", start, end, agent_id, top,
                   rule_group=["authentication_failed"]),
        _top_terms(ctx, "data.srcip", start, end, agent_id, top,
                   rule_group=["authentication_failed"]),
        _top_terms(ctx, "data.dstuser", start, end, agent_id, top,
                   rule_group=["authentication_failed"]),
        _top_terms(ctx, "agent.name", start, end, agent_id, top,
                   rule_group=["authentication_failed"]),
        _top_terms(ctx, "data.srcip", start, end, agent_id, top,
                   rule_group=["authentication_failures"]),
        return_exceptions=True,
    )
    data = {
        "failure_reasons": _unwrap(failures),
        "attacking_sources": _unwrap(sources),
        "targeted_accounts": _unwrap(users),
        "affected_agents": _unwrap(targets),
        "brute_force_sources": _unwrap(brute),
    }
    lines = [
        "# Authentication Report", "",
        f"**Window:** {start or '7d'} → {end or 'now'}", "",
    ]
    lines += _table_section("Failure reasons", data["failure_reasons"], "rule.description")
    lines += _table_section("Source IPs by failed attempts", data["attacking_sources"], "data.srcip")
    lines += _table_section("Repeated-failure sources (brute force)", data["brute_force_sources"], "data.srcip")
    lines += _table_section("Targeted accounts", data["targeted_accounts"], "data.dstuser")
    lines += _table_section("Affected agents", data["affected_agents"], "agent.name")
    data["_markdown"] = "\n".join(lines).rstrip() + "\n"
    return data


# --- shared query pieces ----------------------------------------------------


async def _top_terms(
    ctx: WazuhContext,
    field: str,
    start: str | None,
    end: str | None,
    agent_id: list[str] | None,
    size: int,
    *,
    min_level: int | None = None,
    rule_group: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Terms aggregation over alerts, with a `.keyword` retry."""
    from .alerts import _agg_with_keyword_fallback, build_alert_filters

    indexer = await ctx.indexer()
    filters = build_alert_filters(
        start=start, end=end, agent_id=agent_id,
        rule_group=rule_group, min_level=min_level, default_start="7d",
    )
    response, _ = await _agg_with_keyword_fallback(
        indexer, ctx.settings.alerts_index, build_bool(filters=filters),
        field, size, None, 1,
    )
    buckets = ((response.get("aggregations") or {}).get("grouped") or {}).get("buckets") or []
    return buckets_to_rows(buckets, key_name=field)


async def _severity_mix(
    ctx: WazuhContext, start: str | None, end: str | None, agent_id: list[str] | None
) -> dict[str, Any]:
    """Alert counts split into the conventional severity bands."""
    from .alerts import build_alert_filters

    indexer = await ctx.indexer()
    filters = build_alert_filters(
        start=start, end=end, agent_id=agent_id, default_start="7d"
    )
    body = {
        "query": build_bool(filters=filters),
        "size": 0,
        "aggs": {
            "bands": {
                "range": {
                    "field": "rule.level",
                    "keyed": True,
                    "ranges": [
                        {"key": "info", "from": 0, "to": 4},
                        {"key": "low", "from": 4, "to": 7},
                        {"key": "medium", "from": 7, "to": 12},
                        {"key": "high", "from": 12, "to": 15},
                        {"key": "critical", "from": 15},
                    ],
                }
            }
        },
    }
    response = await indexer.search(ctx.settings.alerts_index, body)
    raw = ((response.get("aggregations") or {}).get("bands") or {}).get("buckets") or {}
    by_severity = {
        key: int((value or {}).get("doc_count") or 0) for key, value in raw.items()
    }
    return {"total": total_of(response), "by_severity": by_severity}


async def _vuln_severity(ctx: WazuhContext, agent_id: list[str] | None) -> dict[str, Any]:
    indexer = await ctx.indexer()
    filters = [c for c in (term_or_terms("agent.id", agent_id),) if c]
    body = {
        "query": build_bool(filters=filters),
        "size": 0,
        "aggs": {"by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}}},
    }
    response = await indexer.search(ctx.settings.vulnerability_index, body)
    buckets = ((response.get("aggregations") or {}).get("by_severity") or {}).get("buckets") or []
    return {
        "total": total_of(response),
        "by_severity": order_severity_counts(buckets_to_rows(buckets)),
    }


async def _fleet_snapshot(ctx: WazuhContext) -> dict[str, Any]:
    manager = await ctx.manager()
    summary, status = await asyncio.gather(
        manager.list("/agents/summary/status"),
        manager.list("/manager/status"),
        return_exceptions=True,
    )
    out: dict[str, Any] = {}
    if not isinstance(summary, BaseException) and summary["items"]:
        parsed = agent_status_counts(summary["items"][0])
        out["total_agents"] = parsed["total"]
        out["by_status"] = parsed["connection"]
    if not isinstance(status, BaseException) and status["items"]:
        daemons = classify_daemons(status["items"][0])
        # Only core daemons belong in a summary aimed at leadership.
        out["stopped_daemons"] = daemons.get("core_not_running", [])
    return out


# --- helpers ----------------------------------------------------------------


async def _none() -> None:
    return None


def _unwrap(value: Any) -> Any:
    """Turn a gathered exception into an inline error note."""
    if isinstance(value, BaseException):
        return {"error": str(value)}
    return value


def _table_section(title: str, rows: Any, key_field: str) -> list[str]:
    """Render a bucket list as a markdown table, or nothing if empty."""
    if not isinstance(rows, Sequence) or not rows:
        return []
    total = sum(r.get("count", 0) for r in rows if isinstance(r, dict)) or 1
    lines = [f"## {title}", "", "| Value | Count | Share |", "| --- | --: | --: |"]
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = row.get(key_field, row.get("key", "—"))
        count = row.get("count", 0)
        text = str(key).replace("|", "\\|")
        if len(text) > 90:
            text = text[:87] + "…"
        lines.append(f"| {text} | {count:,} | {pct(count, total)}% |")
    lines.append("")
    return lines


def _require_indexer(ctx: WazuhContext, report: str) -> None:
    if not ctx.has_indexer():
        raise WazuhMCPError(
            f"The '{report}' report reads alert and state data from the Wazuh "
            "Indexer, which is not configured. Set WAZUH_INDEXER_URL, "
            "WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
        )


def _require_manager(ctx: WazuhContext, report: str) -> None:
    if not ctx.has_manager():
        raise WazuhMCPError(
            f"The '{report}' report reads from the Wazuh Manager API, which is "
            "not configured. Set WAZUH_API_URL, WAZUH_API_USER and "
            "WAZUH_API_PASSWORD."
        )
