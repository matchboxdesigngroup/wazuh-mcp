# Deploying to matchbox-labs

The server runs on the Wazuh host itself and is published at
`https://wazuh.matchbox.host/mcp` through the existing nginx TLS terminator.
Clients authenticate with a bearer token.

```
client ──TLS──> nginx :443 ──plain──> wazuh-mcp :8080 ──loopback──> Wazuh API :55000
  Bearer token   wazuh.matchbox.host    127.0.0.1                   Indexer  :9200
```

**Running on the Wazuh host means 55000 and 9200 no longer need to face the
internet.** Both are reached over loopback. Closing them replaces two exposed
admin APIs with one authenticated endpoint — do that as step 7.

## 1. Create the service account and layout

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-mcp
sudo mkdir -p /opt/wazuh-mcp /etc/wazuh-mcp
```

## 2. Install the code

```bash
sudo git clone https://github.com/matchbox/wazuh-mcp.git /opt/wazuh-mcp
cd /opt/wazuh-mcp
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install .
sudo .venv/bin/wazuh-mcp --help    # confirms the entry point resolves
```

If the host has no access to this repo, `scp` a tarball of the working tree
instead — nothing in it is host-specific.

## 3. Generate a token and write the environment file

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

```bash
sudo cp /opt/wazuh-mcp/deploy/wazuh-mcp.env.example /etc/wazuh-mcp/wazuh-mcp.env
sudo chown root:wazuh-mcp /etc/wazuh-mcp/wazuh-mcp.env
sudo chmod 640 /etc/wazuh-mcp/wazuh-mcp.env
sudo nano /etc/wazuh-mcp/wazuh-mcp.env   # fill in the two passwords and the token
```

The token is the only thing protecting a security console, so the server
refuses to start on the HTTP transport if it is missing or shorter than 32
characters. Root owns the file; the service account only reads it.

## 4. Start the service

```bash
sudo cp /opt/wazuh-mcp/deploy/wazuh-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-mcp
sudo systemctl status wazuh-mcp --no-pager
```

Verify locally before touching nginx:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}'
```

`401` is the correct answer — the token is missing. Adding
`-H "Authorization: Bearer <token>"` should give `200`.

## 5. Publish it through nginx

Paste `deploy/nginx-mcp.conf` into the existing `server` block for
`wazuh.matchbox.host`. nginx matches prefix locations longest-first, so `/mcp`
wins over `location /` wherever you put it, and the Dashboard proxy is
unaffected.

```bash
sudo nginx -t && sudo systemctl reload nginx
```

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://wazuh.matchbox.host/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}'
```

## 6. Point a client at it

```json
{
  "mcpServers": {
    "wazuh": {
      "type": "http",
      "url": "https://wazuh.matchbox.host/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}
```

Client support for remote MCP servers and custom headers varies; check what
yours accepts. The endpoint is a standard streamable-HTTP MCP server.

## 7. Close the ports you no longer need

With the server on the Wazuh host, nothing outside needs 55000 or 9200:

```bash
sudo ufw delete allow 55000/tcp
sudo ufw delete allow 9200/tcp
sudo ufw status verbose
```

Also remove the matching rules from the DigitalOcean cloud firewall. Confirm
from elsewhere that both ports stop answering, and that `/mcp` still works.

## Operating it

**Logs** — `journalctl -u wazuh-mcp -f`. A rejected token logs a warning
without the presented value.

**Rotate a token** — list both in `WAZUH_AUTH_TOKENS`, restart, move clients
across, then remove the old one and restart again. No downtime.

```bash
sudo systemctl restart wazuh-mcp
```

**Upgrade** —

```bash
cd /opt/wazuh-mcp && sudo git pull && sudo .venv/bin/pip install . \
  && sudo systemctl restart wazuh-mcp
```

**Enabling writes** — set `WAZUH_ALLOW_WRITE=true` to allow agent restarts,
on-demand scans and active response. Active response executes commands on
monitored endpoints, so anyone holding the bearer token can then act on your
fleet. Leave it off unless you specifically need it.

## Notes on the hardening in the unit file

`ProtectSystem=strict` makes the filesystem read-only, `CapabilityBoundingSet=`
drops every capability, and `SystemCallFilter=@system-service` blocks
everything outside the usual service syscalls. The process only makes outbound
HTTP calls and listens on one port, so none of this constrains it.
`RestartPreventExitStatus=2` stops systemd from looping on a configuration
error, which exits 2 — those need a human, not a retry.
