"""Configuration-assessment and integrity tools: SCA, FIM (syscheck), rootcheck."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import NotFoundError, UpstreamError
from ..formatting import paged, pct, project, trim

POLICY_FIELDS = (
    "policy_id", "name", "description", "references", "score",
    "pass", "fail", "invalid", "total_checks", "start_scan", "end_scan",
)

CHECK_FIELDS = (
    "id", "title", "result", "reason", "description", "rationale", "remediation",
    "condition", "compliance", "file", "directory", "process", "registry",
    "command", "references",
)

FIM_FIELDS = (
    "file", "type", "size", "perm", "uid", "gid", "uname", "gname",
    "md5", "sha1", "sha256", "mtime", "date", "changes", "arch", "value.name",
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_sca_policies",
        title="SCA policy scores for an agent",
        description=(
            "List an agent's Security Configuration Assessment policies with pass/"
            "fail counts and hardening scores — CIS benchmarks and similar. Use "
            "this to answer 'how well hardened is this host' before drilling into "
            "individual failed checks."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_sca_policies(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _pad(agent_id)
        result = await manager.list(f"/sca/{agent_id}", limit=ctx.clamp(100))
        if not result["items"]:
            return {
                "agent_id": agent_id,
                "policies": [],
                "note": (
                    "No SCA results for this agent. The agent may be disconnected, "
                    "have the SCA module disabled, or not yet have completed a scan."
                ),
            }
        policies = []
        for policy in result["items"]:
            row = project(policy, POLICY_FIELDS)
            total = policy.get("total_checks") or 0
            if total:
                row["pass_rate_percent"] = pct(policy.get("pass") or 0, total)
            policies.append(trim(row, max_string=1200))
        policies.sort(key=lambda p: p.get("score", 0))
        return {
            "agent_id": agent_id,
            "policy_count": result["total"],
            "policies": policies,
            "note": "Sorted worst score first.",
        }

    @server.tool(
        name="wazuh_sca_checks",
        title="SCA checks within a policy",
        description=(
            "List the individual configuration checks in one SCA policy, including "
            "the remediation text for each. Filter to result='failed' to get an "
            "actionable hardening list for a host."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_sca_checks(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
        policy_id: Annotated[
            str,
            Field(description=(
                "Policy ID from wazuh_sca_policies, e.g. 'cis_debian10' or "
                "'cis_win2019_enterprise'."
            )),
        ],
        result: Annotated[
            Literal["passed", "failed", "not applicable"] | None,
            Field(description="Filter by outcome. 'failed' is the actionable set."),
        ] = "failed",
        search: Annotated[
            str | None, Field(description="Free-text match across check titles and text.")
        ] = None,
        include_remediation: Annotated[
            bool,
            Field(description=(
                "Include rationale and remediation prose. Informative but verbose; "
                "turn off when you only need the list of failures."
            )),
        ] = True,
        limit: Annotated[int | None, Field(ge=1)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _pad(agent_id)
        capped = ctx.clamp(limit, default=25)
        response = await manager.list(
            f"/sca/{agent_id}/checks/{policy_id}",
            result=result, search=search, limit=capped, offset=offset,
        )
        fields = CHECK_FIELDS if include_remediation else tuple(
            f for f in CHECK_FIELDS if f not in ("rationale", "remediation", "description")
        )
        items = [trim(project(c, fields), max_string=2000) for c in response["items"]]
        return paged(
            items, total=response["total"], limit=capped, offset=offset,
            extra={"agent_id": agent_id, "policy_id": policy_id, "result_filter": result},
        )

    @server.tool(
        name="wazuh_fim_findings",
        title="File integrity monitoring findings",
        description=(
            "Query File Integrity Monitoring (syscheck) state for an agent: which "
            "monitored files and registry keys exist, their hashes, permissions and "
            "how many times they have changed. Use it to answer 'was this binary "
            "modified' or 'what changed in /etc'."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_fim_findings(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
        file_path: Annotated[
            str | None,
            Field(description="Exact monitored path, e.g. '/etc/passwd'."),
        ] = None,
        search: Annotated[
            str | None, Field(description="Substring match on the path, e.g. 'ssh'.")
        ] = None,
        entry_type: Annotated[
            Literal["file", "registry_key", "registry_value"] | None,
            Field(description="Restrict to files or Windows registry entries."),
        ] = None,
        hash_value: Annotated[
            str | None,
            Field(description="Find entries by md5, sha1 or sha256 digest."),
        ] = None,
        changed_only: Annotated[
            bool,
            Field(description="Only entries that have changed at least once since baseline."),
        ] = False,
        limit: Annotated[int | None, Field(ge=1)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _pad(agent_id)
        capped = ctx.clamp(limit, default=25)

        last_scan_task = manager.list(f"/syscheck/{agent_id}/last_scan")
        findings_task = manager.list(
            f"/syscheck/{agent_id}",
            file=file_path, search=search, type=entry_type, hash=hash_value,
            q="changes>0" if changed_only else None,
            limit=capped, offset=offset, sort="-date",
        )
        last_scan, findings = await asyncio.gather(
            last_scan_task, findings_task, return_exceptions=True
        )

        if isinstance(findings, BaseException):
            raise findings

        items = [trim(project(f, FIM_FIELDS), max_string=800) for f in findings["items"]]
        out = paged(
            items, total=findings["total"], limit=capped, offset=offset,
            extra={"agent_id": agent_id},
        )
        if not isinstance(last_scan, BaseException) and last_scan["items"]:
            out["last_scan"] = last_scan["items"][0]
        if not items:
            out["note"] = (
                "No FIM entries matched. Check that syscheck is enabled for this "
                "agent and that the path is inside a monitored directory."
            )
        return out

    @server.tool(
        name="wazuh_rootcheck",
        title="Rootcheck / policy-monitoring findings",
        description=(
            "Read rootcheck findings for an agent — rootkit signatures, hidden "
            "processes and legacy policy-monitoring hits. Note this is Wazuh's "
            "older assessment module; SCA (wazuh_sca_checks) is the modern "
            "equivalent and usually more useful."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_rootcheck(
        agent_id: Annotated[str, Field(description="Agent ID, e.g. '001'.")],
        status: Annotated[
            Literal["all", "outstanding", "solved"] | None,
            Field(description="'outstanding' shows findings still present."),
        ] = "outstanding",
        search: Annotated[str | None, Field(description="Substring match on the finding text.")] = None,
        limit: Annotated[int | None, Field(ge=1)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        agent_id = _pad(agent_id)
        capped = ctx.clamp(limit, default=25)
        try:
            result = await manager.list(
                f"/rootcheck/{agent_id}",
                status=status, search=search, limit=capped, offset=offset,
            )
        except NotFoundError as exc:
            raise NotFoundError(
                "The rootcheck API is not available on this manager (it was "
                "removed in newer Wazuh releases). Use wazuh_sca_checks for "
                f"configuration assessment instead. Original error: {exc}"
            ) from exc

        items = [
            trim(project(r, ("log", "status", "date_first", "date_last", "pci_dss", "cis")),
                 max_string=1200)
            for r in result["items"]
        ]
        return paged(
            items, total=result["total"], limit=capped, offset=offset,
            extra={"agent_id": agent_id, "status_filter": status},
        )

    @server.tool(
        name="wazuh_run_scan",
        title="Trigger a FIM or SCA scan",
        description=(
            "Ask agents to start a syscheck (FIM) scan now instead of waiting for "
            "the schedule. This puts load on the target endpoints and requires "
            "WAZUH_ALLOW_WRITE=true."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, idempotent_hint=False
        ),
    )
    async def wazuh_run_scan(
        agent_ids: Annotated[
            list[str], Field(min_length=1, description="Agent IDs to scan, e.g. ['001'].")
        ],
    ) -> dict[str, Any]:
        ctx.require_write(f"start a syscheck scan on agents {', '.join(agent_ids)}")
        manager = await ctx.manager()
        ids = [_pad(a) for a in agent_ids]
        try:
            body = await manager.request(
                "PUT", "/syscheck", params={"agents_list": ",".join(ids)}
            )
        except UpstreamError as exc:
            raise UpstreamError(
                f"Could not start the scan: {exc}. The API user needs the "
                "syscheck:run permission."
            ) from exc
        result = manager.unwrap(body)
        return {
            "requested_agents": ids,
            "accepted": trim(result["items"]),
            "failed": trim(result["failed"]),
            "message": result["message"],
        }


def _pad(agent_id: str) -> str:
    text = str(agent_id).strip()
    return text.zfill(3) if text.isdigit() else text
