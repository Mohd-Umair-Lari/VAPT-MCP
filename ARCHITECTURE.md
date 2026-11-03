# VAPT Architecture

## Flow

```text
Agent request
    -> agent_workflow.py
    -> explicit approval (HMAC-signed tokens)
    -> mcp_tools.py adapter
    -> vapt_mvp.py assessment engine
    -> local reports/*.json and reports/*.md
```

## Safety Boundaries

- **Target Scope**: User-supplied target URL (scheme://host:port). No hardcoded allowlist.
- **DNS Rebinding Protection**: All outbound connections resolve hostnames and validate IPs against private ranges (RFC 1918, RFC 4193, RFC 3927, RFC 6598, RFC 6890). Private IPs blocked by default.
- **Redirect Safety**: Maximum 5 redirects, each validated against scope and DNS rebinding checked.
- **Rate Limiting**: Configurable requests/second (default 3), per-host concurrency limit (default 2).
- **Global Request Budget**: Maximum 1000 requests per assessment run.
- **Response Size Limit**: 1 MB default, configurable.
- **Approval System**: HMAC-SHA256 signed tokens bound to target URL, single-use, 30-min TTL.
- **Command Harness**: Explicit argv lists only, strict target validation, 30s timeout, no shell.
- **Assessment**: Non-intrusive HTTP requests only by default. Active exploitation requires explicit approval.

## Main Files

| File | Purpose |
|---|---|
| `config.json` | Target and request settings (template: example.com:80) |
| `vapt_mvp.py` | Assessment engine and report writer |
| `http_client.py` | Scope-enforcing HTTP client with DNS rebinding protection |
| `active_vapt.py` | Detection and exploitation modules |
| `exploits.py` | Generic exploit payloads for common vulnerability classes |
| `crawler.py` | Web crawler for attack surface discovery |
| `approval.py` | HMAC-SHA256 signed approval tokens |
| `harness.py` | Constrained command execution with strict target validation |
| `orchestrator.py` | Full VAPT pipeline coordinator |
| `mcp_tools.py` | Restricted tool adapter for MCP |
| `mcp_server.py` | MCP JSON-RPC server |
| `agent_workflow.py` | Planning and approval gate |
| `automation.py` | Local run and report comparison helpers |
| `tests/` | Offline test suite |

## MCP Tools

- `vapt_get_scope` - Returns configured target and available checks
- `vapt_start_assessment` - Start assessment (passive/active modes)
- `vapt_detect` - Run recon and detection without exploitation
- `vapt_exploit` - Run active exploitation with approval token
- `vapt_crawl` - Deep crawling for attack surface discovery
- `vapt_list_active_actions` - List available exploit actions
- `request_exploit_approval` - Create HMAC-signed approval token
- `vapt_exec_command` - Run allowlisted commands (nmap, curl, httpx, jq, grep)
- `vapt_get_status` / `vapt_get_report` / `vapt_get_history` - Job management

## Active Exploit Categories

- **injection**: SQLi, command injection, LDAP injection, NoSQL injection, XXE
- **xss**: Reflected XSS
- **ssrf**: Server-Side Request Forgery
- **path_traversal**: Path/directory traversal
- **redirect**: Open redirect
- **config**: CORS, security headers, cookie security

## Configuration

Targets are specified via `--target` CLI argument or `target_url` MCP tool parameter.
Private IP targets allowed with `--allow-private` flag or `allow_private_ips` config.
