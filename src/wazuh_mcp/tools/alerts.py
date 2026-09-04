"""Tools for searching and aggregating alerts in the Wazuh Indexer."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..clients.indexer import hits_of, total_of
from ..context import WazuhContext
from ..errors import UpstreamError
from ..formatting import buckets_to_rows, dig, paged, project, severity_of, trim
from ..query import (
    SEVERITY_BANDS,
    auto_interval,
    build_bool,
    interval_key,
    parse_time,
    query_string,
    severity_clause,
    term_or_terms,
    time_range,
)

#: Compact projection returned by default — enough to triage without flooding
#: the context with every field of every alert.
SUMMARY_FIELDS = (
    "timestamp", "agent.id", "agent.name", "agent.ip", "rule.id", "rule.level",
    "rule.description", "rule.groups", "rule.mitre.id", "rule.mitre.technique",
    "rule.mitre.tactic", "location", "decoder.name", "data.srcip", "data.srcuser",
    "data.dstuser", "syscheck.path", "syscheck.event", "full_log",
)

#: Fields that reliably exist as keywords in the Wazuh alerts template.
AGGREGATABLE = (
    "rule.id", "rule.level", "rule.description", "rule.groups",
    "rule.mitre.id", "rule.mitre.technique", "rule.mitre.tactic",
    "agent.id", "agent.name", "agent.ip", "location", "decoder.name",
    "data.srcip", "data.srcuser", "data.dstuser", "data.win.system.eventID",
    "syscheck.path", "syscheck.event", "manager.name",
    "rule.pci_dss", "rule.gdpr", "rule.hipaa", "rule.nist_800_53", "rule.tsc",
)

FIELDDATA_ERROR = re.compile(r"fielddata|not supported on field|illegal_argument", re.IGNORECASE)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def build_alert_filters(
    *,
    start: str | None,
    end: str | None,
    agent_id: str | list[str] | None = None,
    agent_name: str | list[str] | None = None,
    rule_id: str | list[str] | None = None,
    rule_group: str | list[str] | None = None,
    severity: str | None = None,
    min_level: int | None = None,
    max_level: int | None = None,
    mitre_id: str | list[str] | None = None,
    src_ip: str | list[str] | None = None,
    compliance: str | None = None,
    default_start: str = "24h",
) -> list[dict[str, Any]]:
    """Assemble the filter clauses shared by every alert-shaped tool."""
    filters: list[dict[str, Any]] = [
        time_range(start, end, default_start=default_start)
    ]

    for field, value in (
        ("agent.id", agent_id),
        ("agent.name", agent_name),
        ("rule.id", rule_id),
        ("rule.groups", rule_group),
        ("rule.mitre.id", mitre_id),
        ("data.srcip", src_ip),
    ):
        clause = term_or_terms(field, value)
        if clause:
            filters.append(clause)

    if severity:
        filters.append(severity_clause(severity))

    if min_level is not None or max_level is not None:
        bounds: dict[str, int] = {}
        if min_level is not None:
            bounds["gte"] = min_level
        if max_level is not None:
            bounds["lte"] = max_level
        filters.append({"range": {"rule.level": bounds}})

    if compliance:
        # Any alert tagged with the framework at all, regardless of control.
        filters.append({"exists": {"field": f"rule.{compliance}"}})

    return filters


async def search_alerts_raw(
    ctx: WazuhContext,
    *,
    filters: list[dict[str, Any]],
    text: str | None = None,
    size: int,
    offset: int = 0,
    sort_field: str = "timestamp",
    descending: bool = True,
    index: str | None = None,
) -> dict[str, Any]:
    """Run a search and return the raw OpenSearch response."""
    indexer = await ctx.indexer()
    must = [c for c in (query_string(text),) if c]
    body: dict[str, Any] = {
        "query": build_bool(filters=filters, must=must),
        "size": size,
        "from": offset,
        "sort": [{sort_field: {"order": "desc" if descending else "asc"}}],
    }
    return await indexer.search(index or ctx.settings.alerts_index, body)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_search_alerts",
        title="Search Wazuh alerts",
        description=(
            "Search security alerts in the Wazuh Indexer over a time window. This "
            "is the main tool for questions like 'show me critical alerts in the "
            "last hour', 'what fired on server-db-01 yesterday', 'find SSH brute "
            "force attempts', or 'alerts matching MITRE T1110'. Returns a compact "
            "projection of each alert by default."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_search_alerts(
        start: Annotated[
            str | None,
            Field(description=(
                "Window start: relative like '24h', '7d', '30m', or ISO-8601 like "
                "'2026-08-01T00:00:00Z'. Defaults to 24 hours ago."
            )),
        ] = None,
        end: Annotated[
            str | None, Field(description="Window end. Defaults to now.")
        ] = None,
        severity: Annotated[
            Literal["critical", "high", "medium", "low", "info"] | None,
            Field(description=(
                "Severity band by rule level: critical=15+, high=12-14, "
                "medium=7-11, low=4-6, info=0-3."
            )),
        ] = None,
        min_level: Annotated[
            int | None, Field(ge=0, le=16, description="Minimum rule.level, inclusive.")
        ] = None,
        max_level: Annotated[
            int | None, Field(ge=0, le=16, description="Maximum rule.level, inclusive.")
        ] = None,
        agent_id: Annotated[
            list[str] | None, Field(description="Restrict to these agent IDs.")
        ] = None,
        agent_name: Annotated[
            list[str] | None, Field(description="Restrict to these agent names (exact).")
        ] = None,
        rule_id: Annotated[
            list[str] | None, Field(description="Restrict to these rule IDs.")
        ] = None,
        rule_group: Annotated[
            list[str] | None,
            Field(description=(
                "Restrict to these rule groups, e.g. 'authentication_failed', "
                "'web', 'syscheck', 'sca', 'vulnerability-detector'."
            )),
        ] = None,
        mitre_id: Annotated[
            list[str] | None, Field(description="MITRE technique IDs, e.g. ['T1110'].")
        ] = None,
        src_ip: Annotated[
            list[str] | None, Field(description="Restrict to these source IPs.")
        ] = None,
        text: Annotated[
            str | None,
            Field(description=(
                "Lucene query over alert text, e.g. 'failed password', "
                "'rule.description:*sudo*', or 'data.srcport:22 AND NOT agent.id:000'."
            )),
        ] = None,
        full_documents: Annotated[
            bool,
            Field(description=(
                "Return every field of each alert instead of the compact "
                "projection. Much larger output; use for deep inspection of a "
                "handful of alerts."
            )),
        ] = False,
        sort_ascending: Annotated[
            bool, Field(description="Oldest first instead of newest first.")
        ] = False,
        limit: Annotated[int | None, Field(ge=1, description="Max alerts to return.")] = 25,
        offset: Annotated[int, Field(ge=0, description="Paging offset.")] = 0,
    ) -> dict[str, Any]:
        capped = ctx.clamp(limit, default=25)
        filters = build_alert_filters(
            start=start, end=end, agent_id=agent_id, agent_name=agent_name,
            rule_id=rule_id, rule_group=rule_group, severity=severity,
            min_level=min_level, max_level=max_level, mitre_id=mitre_id, src_ip=src_ip,
        )
        response = await search_alerts_raw(
            ctx, filters=filters, text=text, size=capped, offset=offset,
            descending=not sort_ascending,
        )
        docs = hits_of(response)
        total = total_of(response)

        if full_documents:
            items: list[dict[str, Any]] = [trim(d) for d in docs]
        else:
            items = []
            for doc in docs:
                row = project(doc, SUMMARY_FIELDS)
                level = dig(doc, "rule.level")
                if level is not None:
                    row["severity"] = severity_of(level)
                items.append(trim(row, max_string=600))

        return paged(
            items, total=total, limit=capped, offset=offset,
            extra={
                "window": _window_label(start, end),
                "index": ctx.settings.alerts_index,
            },
        )

    @server.tool(
        name="wazuh_alert_stats",
        title="Aggregate alerts by field",
        description=(
            "Group alerts by one or two fields and return counts — the tool for "
            "'top 10 rules today', 'which agents are noisiest', 'alert counts by "
            "MITRE tactic', or 'top source IPs per agent'. Far cheaper than "
            "fetching alerts and counting them yourself."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_alert_stats(
        group_by: Annotated[
            str,
            Field(description=(
                "Field to group by. Common choices: rule.description, rule.id, "
                "rule.level, rule.groups, agent.name, rule.mitre.technique, "
                "rule.mitre.tactic, data.srcip, location, decoder.name."
            )),
        ] = "rule.description",
        then_by: Annotated[
            str | None,
            Field(description="Optional second grouping field, nested inside the first."),
        ] = None,
        start: Annotated[str | None, Field(description="Window start. Defaults to 24h ago.")] = None,
        end: Annotated[str | None, Field(description="Window end. Defaults to now.")] = None,
        severity: Annotated[
            Literal["critical", "high", "medium", "low", "info"] | None, Field()
        ] = None,
        min_level: Annotated[int | None, Field(ge=0, le=16)] = None,
        agent_id: Annotated[list[str] | None, Field()] = None,
        rule_group: Annotated[list[str] | None, Field()] = None,
        text: Annotated[str | None, Field(description="Lucene query to narrow the set.")] = None,
        top: Annotated[
            int, Field(ge=1, le=200, description="Number of buckets for the first field."),
        ] = 10,
        top_nested: Annotated[
            int, Field(ge=1, le=50, description="Buckets for the second field."),
        ] = 5,
    ) -> dict[str, Any]:
        indexer = await ctx.indexer()
        filters = build_alert_filters(
            start=start, end=end, agent_id=agent_id, rule_group=rule_group,
            severity=severity, min_level=min_level,
        )
        must = [c for c in (query_string(text),) if c]
        query = build_bool(filters=filters, must=must)

        response, resolved = await _agg_with_keyword_fallback(
            indexer, ctx.settings.alerts_index, query, group_by, top, then_by, top_nested
        )

        agg = (response.get("aggregations") or {}).get("grouped") or {}
        # Rows stay keyed by the field the caller asked for even when the
        # aggregation had to run on a .keyword subfield, so callers do not have
        # to branch on which field name came back.
        rows = buckets_to_rows(agg.get("buckets") or [], key_name=group_by, sub_agg="nested")
        out: dict[str, Any] = {
            "group_by": group_by,
            "total_alerts_in_window": total_of(response),
            "buckets": rows,
            "window": _window_label(start, end),
        }
        if then_by:
            out["then_by"] = then_by
        other = agg.get("sum_other_doc_count")
        if other:
            out["alerts_outside_top_buckets"] = other
        if resolved["adjusted"]:
            out["aggregated_field"] = resolved["group_by"]
            out["note"] = (
                f"Aggregated on {resolved['group_by']} because {group_by} is "
                "analysed text and cannot be grouped directly. Bucket keys are "
                f"still labelled {group_by}."
            )
        return out

    @server.tool(
        name="wazuh_alert_timeline",
        title="Alert volume over time",
        description=(
            "Bucket alert counts into time intervals to show trend and spikes — "
            "'was there a spike overnight', 'alert volume per hour this week'. "
            "Optionally splits each interval by a field such as severity or agent."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_alert_timeline(
        start: Annotated[str | None, Field(description="Window start. Defaults to 24h ago.")] = None,
        end: Annotated[str | None, Field(description="Window end. Defaults to now.")] = None,
        interval: Annotated[
            str | None,
            Field(description=(
                "Bucket size such as '5m', '1h', '1d'. Chosen automatically from "
                "the window length when omitted."
            )),
        ] = None,
        split_by: Annotated[
            str | None,
            Field(description="Optional field to break each bucket down by, e.g. 'rule.level'."),
        ] = None,
        severity: Annotated[
            Literal["critical", "high", "medium", "low", "info"] | None, Field()
        ] = None,
        min_level: Annotated[int | None, Field(ge=0, le=16)] = None,
        agent_id: Annotated[list[str] | None, Field()] = None,
        rule_group: Annotated[list[str] | None, Field()] = None,
        text: Annotated[str | None, Field()] = None,
        split_top: Annotated[int, Field(ge=1, le=20)] = 5,
    ) -> dict[str, Any]:
        indexer = await ctx.indexer()
        start_dt = parse_time(start or "24h")
        end_dt = parse_time(end) if end else parse_time("now")
        chosen = interval or auto_interval(start_dt, end_dt)

        filters = build_alert_filters(
            start=start, end=end, agent_id=agent_id, rule_group=rule_group,
            severity=severity, min_level=min_level,
        )
        must = [c for c in (query_string(text),) if c]

        histogram: dict[str, Any] = {
            "date_histogram": {
                "field": "timestamp",
                interval_key(chosen): chosen,
                "min_doc_count": 0,
            }
        }
        if split_by:
            histogram["aggs"] = {
                "nested": {"terms": {"field": split_by, "size": split_top}}
            }

        body = {
            "query": build_bool(filters=filters, must=must),
            "size": 0,
            "aggs": {"timeline": histogram},
        }
        response = await indexer.search(ctx.settings.alerts_index, body)
        buckets = ((response.get("aggregations") or {}).get("timeline") or {}).get("buckets") or []
        rows = buckets_to_rows(buckets, key_name="time", sub_agg="nested")
        counts = [r["count"] for r in rows] or [0]

        return {
            "interval": chosen,
            "window": _window_label(start, end),
            "total_alerts": total_of(response),
            "buckets": rows,
            "peak": {"count": max(counts), "at": rows[counts.index(max(counts))]["time"]} if rows else None,
            "split_by": split_by,
        }

    @server.tool(
        name="wazuh_indexer_query",
        title="Run a raw Indexer query",
        description=(
            "Escape hatch: send a raw OpenSearch query DSL body to a Wazuh index "
            "for anything the purpose-built alert tools cannot express — unusual "
            "aggregations, scripted fields, composite queries. Restricted to "
            "wazuh-* indices and read-only _search."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_indexer_query(
        body: Annotated[
            dict[str, Any],
            Field(description=(
                "OpenSearch query DSL body, e.g. "
                '{"query": {"match_all": {}}, "size": 5, "aggs": {...}}. '
                "Always set an explicit small 'size' unless you only need aggregations."
            )),
        ],
        index: Annotated[
            str | None,
            Field(description=(
                "Index pattern to search. Defaults to the configured alerts index. "
                "Must start with a wazuh-* prefix."
            )),
        ] = None,
    ) -> dict[str, Any]:
        indexer = await ctx.indexer()
        target = index or ctx.settings.alerts_index
        response = await indexer.search(target, body)
        out: dict[str, Any] = {"index": target, "total_matching": total_of(response)}
        docs = hits_of(response)
        if docs:
            out["hits"] = [trim(d, max_string=800) for d in docs]
        if response.get("aggregations"):
            out["aggregations"] = trim(response["aggregations"])
        return out

    @server.tool(
        name="wazuh_list_indices",
        title="List Wazuh indices",
        description=(
            "List the wazuh-* indices with health, document counts and sizes, plus "
            "Indexer cluster health. Use this to confirm what data exists and how "
            "far back it goes before querying."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_list_indices(
        pattern: Annotated[
            str, Field(description="Index pattern to list. Must be within wazuh-*.")
        ] = "wazuh-*",
    ) -> dict[str, Any]:
        indexer = await ctx.indexer()
        indices = await indexer.indices(pattern)
        try:
            health = await indexer.health()
        except UpstreamError:
            health = {}
        return {
            "cluster_status": health.get("status"),
            "nodes": health.get("number_of_nodes"),
            "index_count": len(indices),
            "indices": indices,
            "configured_alerts_index": ctx.settings.alerts_index,
        }


# --- helpers ----------------------------------------------------------------


async def _agg_with_keyword_fallback(
    indexer: Any,
    index: str,
    query: dict[str, Any],
    group_by: str,
    top: int,
    then_by: str | None,
    top_nested: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Aggregate, retrying on `.keyword` when a field turns out to be text.

    The Wazuh alerts template has changed which fields are keyword versus text
    across releases, so rather than hard-coding a guess we let the Indexer tell
    us and retry once.
    """
    attempts = [(group_by, then_by)]
    fallback = (_keywordise(group_by), _keywordise(then_by))
    if fallback != (group_by, then_by):
        attempts.append(fallback)

    last: UpstreamError | None = None
    for outer, inner in attempts:
        terms: dict[str, Any] = {
            "terms": {"field": outer, "size": top, "order": {"_count": "desc"}}
        }
        if inner:
            terms["aggs"] = {"nested": {"terms": {"field": inner, "size": top_nested}}}
        body = {"query": query, "size": 0, "aggs": {"grouped": terms}}
        try:
            response = await indexer.search(index, body)
        except UpstreamError as exc:
            if not FIELDDATA_ERROR.search(str(exc)):
                raise
            last = exc
            continue
        return response, {
            "group_by": outer,
            "then_by": inner,
            "adjusted": (outer, inner) != (group_by, then_by),
        }

    raise UpstreamError(
        f"Cannot aggregate on {group_by!r}"
        + (f" / {then_by!r}" if then_by else "")
        + f": {last}. Try the '.keyword' subfield, or one of: "
        + ", ".join(AGGREGATABLE[:10])
    )


def _keywordise(field: str | None) -> str | None:
    if not field or field.endswith(".keyword"):
        return field
    return f"{field}.keyword"


def _window_label(start: str | None, end: str | None) -> str:
    return f"{start or '24h ago'} → {end or 'now'}"


__all__ = ["SEVERITY_BANDS", "build_alert_filters", "register", "search_alerts_raw"]
