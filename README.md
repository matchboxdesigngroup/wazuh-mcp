# wazuh-mcp

An MCP server for querying a remote [Wazuh](https://wazuh.com) deployment. It
talks to both halves of Wazuh — the **Manager API** (agents, rules, inventory,
configuration) and the **Wazuh Indexer** (alerts, vulnerability state) — and
exposes 34 tools plus a composite report generator.

Read-only by default. State-changing tools exist but stay disabled unless you
explicitly opt in.

## Why both backends

Wazuh splits its data in a way that trips people up: the Manager API knows
about agents, rules and inventory, but **historical alerts are not there** —
they live in the Indexer (OpenSearch). Anything resembling "what fired last
night" or "top threats this week" needs the Indexer. Configure both.

The 4.8 release also moved vulnerability detection results from the Manager API
into the Indexer. This server detects the manager version and routes
vulnerability queries to whichever backend actually holds the data, so the same
tool works across releases.

## Install

```bash
uv sync
```

## Configure

Copy `.env.example` to `.env` and fill it in, or set the variables in your MCP
client config.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `WAZUH_API_URL` | for Manager tools | — | e.g. `https://wazuh.example.com:55000` |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | for Manager tools | — | API credentials |
| `WAZUH_INDEXER_URL` | for alert tools | — | e.g. `https://wazuh.example.com:9200` |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` | for alert tools | — | Indexer credentials |
| `WAZUH_CA_BUNDLE` | no | — | Path to your Wazuh root CA (preferred over disabling TLS) |
| `WAZUH_VERIFY_SSL` | no | `true` | Set `false` only for self-signed labs |
| `WAZUH_ALLOW_WRITE` | no | `false` | Enables agent restart, scans, active response |
| `WAZUH_TIMEOUT` | no | `30` | Per-request timeout, seconds |
| `WAZUH_MAX_RESULTS` | no | `500` | Ceiling on any single result set |
| `WAZUH_ALERTS_INDEX` | no | `wazuh-alerts-*` | Alert index pattern |
| `WAZUH_VULNERABILITY_INDEX` | no | `wazuh-states-vulnerabilities-*` | Vulnerability state index |

Either backend can be configured alone. Tools needing a missing backend fail
with a message naming the exact variables to set, rather than a generic error.

### Least-privilege credentials

Create a dedicated Wazuh API user with a read-only RBAC role instead of reusing
`wazuh-wui`. If you never intend to enable `WAZUH_ALLOW_WRITE`, the role needs
only `read` actions — the server's read-only default and the API's own RBAC then
reinforce each other.

## Transports

**stdio** (default) for a local client — no token, no network surface.

**streamable HTTP** for remote clients, authenticated with a bearer token:

```bash
WAZUH_TRANSPORT=http WAZUH_PUBLIC_URL=https://wazuh.example.com/mcp \
WAZUH_AUTH_TOKENS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))') \
uv run wazuh-mcp
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAZUH_TRANSPORT` | `stdio` | `stdio` or `http` |
| `WAZUH_BIND_HOST` | `127.0.0.1` | Bind address; leave on loopback behind a proxy |
| `WAZUH_BIND_PORT` | `8080` | Bind port |
| `WAZUH_HTTP_PATH` | `/mcp` | URL path to serve on |
| `WAZUH_PUBLIC_URL` | — | Required for `http`; the URL clients reach |
| `WAZUH_AUTH_TOKENS` | — | Required for `http`; comma-separated to rotate |
| `WAZUH_ALLOWED_HOSTS` | from `public_url` | Accepted `Host` values |

The HTTP transport **fails closed**: it will not start without a token of at
least 32 characters, or without `WAZUH_PUBLIC_URL`. Requests arrive as
`Authorization: Bearer <token>`; anything else gets a 401 carrying the
protected-resource metadata URL. DNS-rebinding protection is on, so the `Host`
header must appear in the allowlist — a forged one gets 421.

Terminate TLS in front of it. A bearer token over plain HTTP is sent in clear
text, and binding to anything other than loopback logs a warning saying so.
See [deploy/DEPLOY.md](deploy/DEPLOY.md) for a systemd + nginx deployment,
including the point that running on the Wazuh host lets you close ports 55000
and 9200 entirely.

## Connect it

### Claude Code

```bash
claude mcp add wazuh --env WAZUH_API_URL=https://wazuh.example.com:55000 --env WAZUH_API_USER=wazuh-mcp --env WAZUH_API_PASSWORD=secret --env WAZUH_INDEXER_URL=https://wazuh.example.com:9200 --env WAZUH_INDEXER_USER=wazuh-mcp --env WAZUH_INDEXER_PASSWORD=secret -- uv run --directory /Users/lema/Projects/wazuh-mcp wazuh-mcp
```

### Claude Desktop / any stdio client

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/lema/Projects/wazuh-mcp", "wazuh-mcp"],
      "env": {
        "WAZUH_API_URL": "https://wazuh.example.com:55000",
        "WAZUH_API_USER": "wazuh-mcp",
        "WAZUH_API_PASSWORD": "secret",
        "WAZUH_INDEXER_URL": "https://wazuh.example.com:9200",
        "WAZUH_INDEXER_USER": "wazuh-mcp",
        "WAZUH_INDEXER_PASSWORD": "secret"
      }
    }
  }
}
```

## Tools

### Health and operations
| Tool | What it answers |
| --- | --- |
| `wazuh_health` | One call: manager version, daemon states, cluster, agent counts, Indexer health. Start here. |
| `wazuh_cluster_status` | Node roles, sync state, healthcheck detail |
| `wazuh_manager_logs` | `ossec.log` filtered by level/daemon, or a per-daemon error summary |
| `wazuh_manager_stats` | analysisd queue pressure and dropped events, remoted counters, alert volume |
| `wazuh_manager_config` | The running `ossec.conf`, by section |
| `wazuh_api_request` | Read-only escape hatch for any Manager API endpoint |

### Agents
| Tool | What it answers |
| --- | --- |
| `wazuh_list_agents` | Filter by status, group, OS, version, name, or a raw `q` filter |
| `wazuh_get_agent` | One endpoint in full: state, OS, hardware, package count |
| `wazuh_agent_summary` | Fleet health: status mix, OS spread, outdated, ungrouped |
| `wazuh_list_groups` | Groups and their members |
| `wazuh_agent_config` | The config an agent actually loaded (did the group change land?) |
| `wazuh_restart_agents` | **Write.** Restart agents |

### Alerts (Indexer)
| Tool | What it answers |
| --- | --- |
| `wazuh_search_alerts` | The main alert query: time window, severity, agent, rule, MITRE, source IP, free text |
| `wazuh_alert_stats` | "Top N by X" — one or two grouping levels, done server-side |
| `wazuh_alert_timeline` | Volume over time with automatic bucket sizing and peak detection |
| `wazuh_indexer_query` | Raw OpenSearch DSL, restricted to `wazuh-*` |
| `wazuh_list_indices` | What data exists and how far back |

### Vulnerabilities
| Tool | What it answers |
| --- | --- |
| `wazuh_vulnerabilities` | CVEs by agent, severity, CVE ID, package, CVSS floor |
| `wazuh_vulnerability_summary` | Exposure rollup: severity mix, worst hosts, most widespread CVEs |

### Detection content
| Tool | What it answers |
| --- | --- |
| `wazuh_list_rules` | Search the ruleset, including by compliance control |
| `wazuh_get_rule` | One rule plus its XML definition |
| `wazuh_rule_groups` | Valid rule groups, or every control in a framework |
| `wazuh_list_decoders` | How a log source is being parsed |
| `wazuh_mitre` | ATT&CK techniques, tactics, groups, software, mitigations |
| `wazuh_cdb_lists` | CDB lookup lists and their contents |

### Posture and inventory
| Tool | What it answers |
| --- | --- |
| `wazuh_sca_policies` | CIS-style hardening scores per policy, worst first |
| `wazuh_sca_checks` | Individual checks with remediation text; defaults to failures |
| `wazuh_fim_findings` | File integrity state, hashes, change counts |
| `wazuh_rootcheck` | Legacy rootkit / policy-monitoring findings |
| `wazuh_agent_inventory` | Packages, processes, ports, interfaces, hardware, hotfixes |
| `wazuh_find_software` | **Fleet-wide** package search — "who has log4j?" |
| `wazuh_run_scan` | **Write.** Trigger a FIM scan now |

### Reporting
`wazuh_generate_report` returns structured data **and** a rendered markdown
report. Types: `executive_summary`, `threat_activity`, `agent_health`,
`vulnerability_exposure`, `compliance` (PCI DSS / GDPR / HIPAA / NIST 800-53 /
TSC), `file_integrity`, `authentication`.

### Active response
`wazuh_active_response` — **Write, destructive.** Runs `firewall-drop`,
`disable-account`, `host-deny` and friends on named agents. Marked destructive
in its tool annotations so clients prompt before use.

## Conventions

- **Time** — relative (`30m`, `24h`, `7d`) or ISO-8601. Alert queries default to
  24 hours; reports to 7 days.
- **Severity** — maps to Wazuh rule levels: critical 15+, high 12–14,
  medium 7–11, low 4–6, info 0–3.
- **Agent IDs** — zero-padded to three digits automatically; `000` is the
  manager itself.
- **Paging** — list results carry `total_matching` and, when more exist,
  `next_offset`.

## Safety

- **Read-only by default.** Every state-changing tool checks `WAZUH_ALLOW_WRITE`
  *before* issuing any request, and is annotated with
  `read_only_hint=false` / `destructive_hint=true`.
- **Credential endpoints are blocked.** `wazuh_api_request` refuses
  `/agents/{id}/key` and the authentication endpoint, so agent keys and API
  tokens cannot be pulled into a model's context.
- **Index access is namespaced.** Raw Indexer queries are restricted to
  `wazuh-*` prefixes, with path-traversal patterns rejected, so a query cannot
  reach unrelated indices sharing the cluster.
- **Output is bounded.** Long strings are truncated and large containers
  summarised, so one broad query cannot flood the context window.

## Development

```bash
uv run pytest
```

```bash
uv run ruff check .
```

The suite runs against a mocked Wazuh (`respx`) and covers the JWT
refresh-on-401 path, envelope handling, `.keyword` aggregation fallback,
4.8 vulnerability routing, write gating, index guards and report rendering.

Verified end to end against a live **Wazuh 4.14.7** deployment. Version-specific
behaviour the mocks alone would have missed, now covered by regression tests:

- `/agents/summary/status` nests counts under `connection` / `configuration`;
  older releases returned one flat mapping. Both are parsed.
- `wazuh-agentlessd`, `wazuh-csyslogd`, `wazuh-maild`, `wazuh-reportd` and
  `wazuh-clusterd` are stopped in a healthy default install, so only stopped
  *core* daemons are reported as a problem.
- `vulnerability.severity` is the literal `"-"` for unscored CVEs — around a
  fifth of findings on a real host. It is relabelled `Untriaged` rather than
  dropped, so severity breakdowns reconcile with the total.
- The MITRE `*_ids` parameters match internal STIX ids, not ATT&CK numbers.
  Lookups query `external_id` / `id` so `T1595` and
  `attack-pattern--<uuid>` both work.

Tests construct settings with `_env_file=None` and strip inherited `WAZUH_*`
variables, so a populated `.env` cannot leak into them and quietly satisfy the
assertions that check for *missing* configuration.
