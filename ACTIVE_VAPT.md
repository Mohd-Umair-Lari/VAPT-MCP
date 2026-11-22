# Active VAPT — General Purpose Internet-Wide Security Scanner

This is a **general-purpose VAPT (Vulnerability Assessment and Penetration Testing) platform** that accepts any user-specified target URL, CIDR range, or ASN for scanning. It provides both passive (recon + detection) and active (exploitation) assessment capabilities.

## Key Features

- **Arbitrary Target Scanning**: Accept any URL (`https://target.com`), no hardcoded allowlist
- **Internet-Wide CIDR/ASN Scanning**: Scan entire network ranges with configurable rate/concurrency
- **Flexible Approval Gates**: Optional HMAC-SHA256 approval tokens; auto-approve mode for unattended runs
- **Single-Action Exploit Execution**: Run specific exploit modules (sqli, xss, ssrf, etc.) individually
- **Deep Crawling**: Attack surface discovery with form/parameter extraction and tech fingerprinting
- **MCP Server**: 14 tools for LLM/agent integration
- **Comprehensive Reporting**: JSON, Markdown, PDF reports with history comparison

## Three Phases

| Phase | Auto? | What it does |
|---|---|---|
| `recon` | yes | 80+ universal paths + 15 tech-specific + pattern-based discovery |
| `detect` | yes | Low-impact probes: SQL errors, reflected input, SSRF, missing headers, cookie flags |
| `exploit` | optional | 12 exploit modules across 6 categories: injection, XSS, SSRF, path traversal, redirect, config |

## Approval Gates (Configurable)

Exploitation can run with or without approval:
- **Auto-approve mode** (`auto_approve: true`): Runs immediately, no token needed
- **Token mode** (default): Requires `request_exploit_approval` + `vapt_exploit` with valid HMAC token
- **Config-driven**: Set `require_exploit_approval: false` in config to disable

## Files

| File | Purpose |
|---|---|
| `scope.py` | Dynamic scope definition (optional enforcement) |
| `http_client.py` | Rate-limited HTTP client (configurable security features) |
| `active_vapt.py` | Recon / detection / exploitation modules |
| `exploits.py` | 12 generic exploit payload modules |
| `crawler.py` | Deep crawl for attack surface discovery |
| `approval.py` | Exploit approval tokens (HMAC-SHA256) |
| `audit.py` | Append-only action log |
| `orchestrator.py` | Full pipeline with single-action + CIDR support |
| `internet_scanner.py` | Internet-wide CIDR/ASN scanner |
| `mcp_server.py` | MCP server with 14 tools |
| `cron_runner.py` | Scheduler entry point |

## Command Line Usage

```bash
# Passive scan only
python scripts/vapt_mvp.py --target https://example.com

# Full active scan with auto-approve
python scripts/orchestrator.py --target https://example.com --exploit --auto-approve

# Single exploit action
python scripts/orchestrator.py --target https://example.com --exploit --exploit-action sqli --auto-approve

# Enable deep crawling
python scripts/orchestrator.py --target https://example.com --crawl

# Internet-wide CIDR scan
python scripts/internet_scanner.py --cidrs 192.168.1.0/24 --rate 1000 --concurrent 100 --modules http,tls,ssh
```

## MCP Server (for LLM/Agent Integration)

`mcp_server.py` exposes 14 tools over stdio:

| Tool | Description |
|---|---|
| `vapt_get_scope` | Configured target and allowed checks |
| `vapt_start_assessment` | Start passive/active assessment with target_url |
| `vapt_detect` | Recon + detection without exploitation |
| `vapt_crawl` | Deep crawl for attack surface discovery |
| `vapt_exploit` | Active exploitation (auto_approve or token) |
| `vapt_list_active_actions` | List available exploit modules |
| `request_exploit_approval` | Create HMAC approval token |
| `vapt_scan_cidr` | Internet-wide CIDR/ASN scanning |
| `vapt_exec_command` | Run allowlisted CLI tools (nmap, sqlmap, nuclei, etc.) |
| `vapt_get_status/report/history` | Job status, reports, history |

Register with any MCP-capable host:

```json
{
  "mcpServers": {
    "vapt": {
      "command": "python",
      "args": ["<cloned-repo>/scripts/mcp_server.py"],
      "env": {
        "VAPT_ALLOW_PRIVATE_IPS": "true",
        "VAPT_RATE_PER_SECOND": "100",
        "VAPT_MAX_CONCURRENT": "50"
      }
    }
  }
}
```

## Scheduling

`cron_runner.py` is the single-shot command for schedulers. It runs recon + detect by default (exploitation off), writes reports, and prints JSON summary with change alerts.

```bash
python C:/Users/umair/projects/VAPT-MCP/cron_runner.py
```

## Security Controls (Configurable)

All safety features are **configurable**, not hardcoded:

| Control | Default | Config Via |
|---|---|---|
| Private IP blocking | Disabled | `allow_private_ips` |
| Rate limiting | 100 req/s | `rate_limit_per_second` |
| Max concurrent | 50 | `max_concurrent_per_host` |
| Max redirects | 20 | `max_redirects` |
| Max response | 10 MB | `max_response_bytes` |
| Request budget | 100,000 | `global_request_budget` |
| DNS rebinding protection | Disabled | `enable_dns_rebinding_protection` |
| Scope enforcement | Disabled | `enforce_scope` |

## Educational Use

This platform is designed for **authorized security testing** and **educational purposes**. Always ensure you have explicit permission before scanning any target. The configurable safety controls allow you to adapt the scanner for different environments (lab, internal network, internet-facing) while maintaining audit trails and approval gates where needed.
