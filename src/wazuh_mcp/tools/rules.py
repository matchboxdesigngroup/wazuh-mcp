"""Detection-content tools: rules, decoders, CDB lists and MITRE mappings."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from ..context import WazuhContext
from ..errors import NotFoundError
from ..formatting import paged, project, severity_of, trim

RULE_FIELDS = (
    "id", "level", "description", "groups", "filename", "relative_dirname",
    "status", "gdpr", "pci_dss", "hipaa", "nist_800_53", "tsc", "mitre", "gpg13",
)

DECODER_FIELDS = (
    "name", "filename", "relative_dirname", "status", "position", "parent", "details",
)

#: The Manager API spells this requirement with hyphens, unlike the others.
COMPLIANCE_PARAMS = {
    "pci_dss": "pci_dss",
    "gdpr": "gdpr",
    "hipaa": "hipaa",
    "nist_800_53": "nist-800-53",
    "tsc": "tsc",
    "mitre": "mitre",
}

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def register(server: Any, ctx: WazuhContext) -> None:
    @server.tool(
        name="wazuh_list_rules",
        title="Search detection rules",
        description=(
            "Search the manager's ruleset. Use this to explain why an alert fired, "
            "to find every rule covering a compliance control ('which rules map to "
            "PCI DSS 10.2.4'), or to audit which high-severity rules are enabled."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_list_rules(
        rule_ids: Annotated[
            list[str] | None, Field(description="Specific rule IDs, e.g. ['5710', '5712'].")
        ] = None,
        level: Annotated[
            str | None,
            Field(description="Exact level ('10') or an inclusive range ('10-15')."),
        ] = None,
        group: Annotated[
            str | None,
            Field(description="Rule group, e.g. 'authentication_failed', 'syscheck', 'sca'."),
        ] = None,
        filename: Annotated[
            str | None, Field(description="Rule file, e.g. '0095-sshd_rules.xml'.")
        ] = None,
        status: Annotated[
            Literal["enabled", "disabled", "all"] | None,
            Field(description="Rule status filter."),
        ] = None,
        compliance: Annotated[
            Literal["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "mitre"] | None,
            Field(description="Compliance framework to filter on, paired with compliance_value."),
        ] = None,
        compliance_value: Annotated[
            str | None,
            Field(description=(
                "Specific control within the framework, e.g. '10.2.4' for pci_dss "
                "or 'T1110' for mitre. Omit to match any rule tagged with the framework."
            )),
        ] = None,
        search: Annotated[
            str | None, Field(description="Free-text substring across rule fields.")
        ] = None,
        query: Annotated[
            str | None, Field(description="Raw Wazuh query filter, e.g. 'level>=10;status=enabled'.")
        ] = None,
        sort: Annotated[str | None, Field(description="Sort field, '-' prefix for descending.")] = None,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit)

        params: dict[str, Any] = {
            "rule_ids": ",".join(rule_ids) if rule_ids else None,
            "level": level,
            "group": group,
            "filename": filename,
            "status": status,
            "search": search,
            "q": query,
            "sort": sort,
            "limit": capped,
            "offset": offset,
        }
        if compliance:
            # An empty string still selects "tagged with this framework at all".
            params[COMPLIANCE_PARAMS[compliance]] = compliance_value or ""

        result = await manager.list("/rules", **params)
        items = []
        for rule in result["items"]:
            row = project(rule, RULE_FIELDS)
            if "level" in row:
                row["severity"] = severity_of(row["level"])
            items.append(trim(row, max_string=800))
        return paged(items, total=result["total"], limit=capped, offset=offset)

    @server.tool(
        name="wazuh_get_rule",
        title="Get one rule with full detail",
        description=(
            "Fetch a single rule including its full XML definition, so you can "
            "explain exactly what conditions trigger it and what it is mapped to."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_get_rule(
        rule_id: Annotated[str, Field(description="Rule ID, e.g. '5710'.")],
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        result = await manager.list("/rules", rule_ids=rule_id)
        if not result["items"]:
            raise NotFoundError(f"No rule with ID {rule_id!r} exists in the ruleset")
        rule = result["items"][0]
        out: dict[str, Any] = {"rule": trim(rule)}
        out["severity"] = severity_of(rule.get("level"))

        filename = rule.get("filename")
        if filename:
            try:
                # download=true returns the file body rather than metadata.
                xml = await manager.request(
                    "GET", f"/rules/files/{filename}", params={"raw": "true"}
                )
                out["definition_file"] = filename
                out["file_contents"] = trim(xml, max_string=20000)
            except Exception:  # noqa: BLE001 - file read is a best-effort extra
                out["definition_file"] = filename
                out["file_contents_note"] = (
                    f"Could not read {filename}; the API user may lack "
                    "rules:read permission on rule files."
                )
        return out

    @server.tool(
        name="wazuh_rule_groups",
        title="List rule groups and compliance controls",
        description=(
            "Enumerate the rule groups in the ruleset, or every value present for "
            "one compliance framework. Useful for discovering valid filter values "
            "before calling wazuh_list_rules or wazuh_search_alerts."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_rule_groups(
        requirement: Annotated[
            Literal["groups", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "mitre"],
            Field(description="'groups' for rule groups, or a framework to list its controls."),
        ] = "groups",
        limit: Annotated[int | None, Field(ge=1)] = 500,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit, default=500)
        path = (
            "/rules/groups"
            if requirement == "groups"
            else f"/rules/requirement/{COMPLIANCE_PARAMS[requirement]}"
        )
        result = await manager.list(path, limit=capped)
        return {
            "requirement": requirement,
            "count": len(result["items"]),
            "total_matching": result["total"],
            "values": result["items"],
        }

    @server.tool(
        name="wazuh_list_decoders",
        title="Search log decoders",
        description=(
            "Search the decoders that parse raw logs into fields. Use this when an "
            "alert's fields look wrong or absent, to see how a log source is being "
            "parsed."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_list_decoders(
        decoder_names: Annotated[
            list[str] | None, Field(description="Specific decoder names, e.g. ['sshd'].")
        ] = None,
        filename: Annotated[str | None, Field(description="Decoder file name.")] = None,
        status: Annotated[Literal["enabled", "disabled", "all"] | None, Field()] = None,
        search: Annotated[str | None, Field(description="Free-text substring match.")] = None,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit)
        result = await manager.list(
            "/decoders",
            decoder_names=",".join(decoder_names) if decoder_names else None,
            filename=filename, status=status, search=search,
            limit=capped, offset=offset,
        )
        items = [trim(project(d, DECODER_FIELDS), max_string=1200) for d in result["items"]]
        return paged(items, total=result["total"], limit=capped, offset=offset)

    @server.tool(
        name="wazuh_mitre",
        title="Query the MITRE ATT&CK catalogue",
        description=(
            "Look up MITRE ATT&CK techniques, tactics, groups, software or "
            "mitigations from the manager's bundled catalogue. Use it to expand a "
            "technique ID seen in an alert into its description, tactics and "
            "mitigations."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_mitre(
        resource: Annotated[
            Literal["techniques", "tactics", "groups", "software", "mitigations", "references"],
            Field(description="Which part of the ATT&CK catalogue to query."),
        ] = "techniques",
        ids: Annotated[
            list[str] | None,
            Field(description=(
                "Specific IDs. Accepts the familiar ATT&CK numbers — ['T1110'] for "
                "techniques, ['TA0006'] for tactics, ['G0001'] for groups — as well "
                "as internal STIX ids like "
                "['attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298']."
            )),
        ] = None,
        search: Annotated[
            str | None, Field(description="Free-text search across names and descriptions.")
        ] = None,
        limit: Annotated[int | None, Field(ge=1)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit, default=20)
        params: dict[str, Any] = {
            "search": search, "limit": capped, "offset": offset,
        }
        if ids:
            # Wazuh's `*_ids` parameters match on internal STIX ids, not the
            # ATT&CK numbers everyone actually quotes — passing 'T1110' there
            # returns nothing at all rather than an error. Querying explicitly
            # against `external_id` / `id` handles either form, and mixtures.
            params["q"] = ",".join(_mitre_id_clause(i) for i in ids)
        result = await manager.list(f"/mitre/{resource}", **params)
        items = [trim(item, max_string=1500) for item in result["items"]]
        return paged(
            items, total=result["total"], limit=capped, offset=offset,
            extra={"resource": resource},
        )

    @server.tool(
        name="wazuh_cdb_lists",
        title="List CDB lists",
        description=(
            "List the CDB (constant database) lists used by rules for lookups such "
            "as known-bad IPs, allowed users or audit keys, optionally including "
            "their contents."
        ),
        annotations=READ_ONLY,
    )
    async def wazuh_cdb_lists(
        filename: Annotated[
            str | None, Field(description="Specific list file, e.g. 'audit-keys'.")
        ] = None,
        include_contents: Annotated[
            bool, Field(description="Include each list's key/value entries.")
        ] = False,
        limit: Annotated[int | None, Field(ge=1)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        manager = await ctx.manager()
        capped = ctx.clamp(limit)
        result = await manager.list(
            "/lists", filename=filename, limit=capped, offset=offset
        )
        items = []
        for entry in result["items"]:
            row = project(entry, ("filename", "relative_dirname"))
            if include_contents and isinstance(entry.get("items"), list):
                row["entries"] = trim(entry["items"])
            elif isinstance(entry.get("items"), list):
                row["entry_count"] = len(entry["items"])
            items.append(row)
        return paged(items, total=result["total"], limit=capped, offset=offset)


def _mitre_id_clause(identifier: str) -> str:
    """Build the right `q` clause for an ATT&CK number or a STIX id."""
    value = identifier.strip()
    # STIX ids carry a type prefix, e.g. `attack-pattern--<uuid>`.
    field = "id" if "--" in value else "external_id"
    return f"{field}={value}"
