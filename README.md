# VAPT Agent — Generalized Vulnerability Assessment & Penetration Testing

A production-ready, AI-agent-integratable VAPT framework with **passive** and **active** scanning modes, dynamic reconnaissance, cryptographic approval gates, and MCP/Hercules integration.

## 🎯 Overview

VAPT Agent is a **generalized, internet-wide** vulnerability assessment platform designed for:
- **AI Agent Integration** — First-class MCP (Model Context Protocol) support for Hermes, Claude, and other AI agents
- **Dual-Mode Scanning** — Passive reconnaissance + active exploitation with cryptographic approval gates
- **Dynamic Target Adaptation** — Technology-aware recon that adapts to WordPress, Spring, Django, APIs, etc.
- **Security-First Architecture** — DNS rebinding protection, HMAC-signed approvals, strict scope enforcement
- **Zero Dependencies** — Pure Python 3.10+ stdlib (optional: `requests` for active mode)

## ✨ Key Capabilities

| Feature | Passive Mode | Active Mode |
|---------|-------------|-------------|
| **Reconnaissance** | ✅ 80+ universal paths + tech-specific | ✅ Deep crawl + attack surface mapping |
| **Technology Detection** | ✅ 15+ frameworks (WP, Spring, Django, etc.) | ✅ Enhanced with active probing |
| **Security Headers** | ✅ CSP, HSTS, X-Frame, etc. | ✅ |
| **Cookie Analysis** | ✅ Secure, HttpOnly, SameSite | ✅ |
| **CORS Testing** | ✅ Origin reflection, wildcards | ✅ |
| **Redirect Analysis** | ✅ | ✅ |
| **SQL Injection** | Detection only | ✅ Exploitation with approval |
| **XSS** | Detection only | ✅ Reflected XSS with approval |
| **SSRF** | Detection only | ✅ Metadata service testing with approval |
| **Path Traversal** | ❌ | ✅ With approval |
| **Command Injection** | ❌ | ✅ With approval |
| **XXE** | ❌ | ✅ With approval |
| **NoSQL Injection** | ❌ | ✅ With approval |
| **LDAP Injection** | ❌ | ✅ With approval |
| **Open Redirect** | ❌ | ✅ With approval |
| **JWT None Algorithm** | ❌ | ✅ With approval |
| **IDOR** | ❌ | ✅ With approval |
| **Weak Credentials** | ❌ | ✅ With approval |
| **CORS Misconfig** | ✅ | ✅ |
| **Cryptographic Approvals** | N/A | ✅ HMAC-SHA256 tokens |

## 🚀 Quick Start

### Installation
```bash
# Clone and run - zero dependencies (stdlib only for passive)
git clone <repo>
cd VAPT-MCP

# Optional: install requests for active mode
pip install requests
```

### Passive Assessment (Safe, No Approval Needed)
```bash
# Assess any public target
python vapt_mvp.py --target https://example.com

# With custom output directory
python vapt_mvp.py --target https://api.example.com --report-dir ./my-reports

# Internal/private targets (requires explicit flag)
python vapt_mvp.py --target http://192.168.1.100:8080 --allow-private
```

### Active Assessment (Requires Approval)
```bash
# Full active scan with exploitation
python orchestrator.py --target https://example.com --exploit

# With crawling for attack surface discovery
python orchestrator.py --target https://example.com --exploit --crawl

# Specific exploit categories only
python orchestrator.py --target https://example.com --exploit --exploit-categories injection,xss,ssrf

# Internal targets
python orchestrator.py --target http://internal-app:8080 --exploit --allow-private
```

### MCP/Hercules Integration
```bash
# Start MCP server (stdio transport)
python mcp_server.py

# Configure in Hermes/hermes-config.yaml:
# servers:
#   vapt:
#     command: python
#     args: ["/path/to/VAPT-MCP/mcp_server.py"]
```

## 🔧 Configuration

### Target Specification
Targets are specified via CLI or MCP tools:
```bash
--target https://example.com:443    # Full URL with scheme
--target http://10.0.0.50:8080      # Internal with port
```

### Config File (`config.json`)
```json
{
  "target": {
    "scheme": "https",
    "host": "example.com",
    "port": 443,
    "base_path": "/"
  },
  "timeout_seconds": 10,
  "user_agent": "VAPT-Agent/1.0",
  "active": {
    "rate_limit_per_second": 3,
    "max_response_bytes": 1048576,
    "max_redirects": 5,
    "allow_private_ips": false,
    "max_concurrent_per_host": 2,
    "global_request_budget": 1000
  }
}
```

## 🤖 AI Agent Integration

### MCP Tools Available
| Tool | Description | Parameters |
|------|-------------|------------|
| `vapt_get_scope` | Get configured target & checks | — |
| `vapt_start_assessment` | Start async assessment | `mode`, `target_url`, `exploit_categories`, `crawl` |
| `vapt_get_status` | Check job status | `job_id` |
| `vapt_get_report` | Get completed report | `job_id` |
| `vapt_generate_pdf_report` | Generate a compact PDF report for a completed job | `job_id` |
| `vapt_detect` | Run recon + detection | `target_url` |
| `vapt_exploit` | Run active exploitation | `approval_token`, `confirmation`, `target_url`, `exploit_categories` |
| `vapt_crawl` | Deep crawl attack surface | `target_url`, `max_depth`, `max_pages` |
| `vapt_list_active_actions` | List available exploits | `target_url` |
| `request_exploit_approval` | Create approval token | `confirmation`, `target_url` |
| `vapt_exec_command` | Run allowlisted commands | `argv`, `mode`, `approval_token`, `target_url` |

### Agent Workflow (Programmatic)
```python
import agent_workflow
import llm_workflow

# Simple agent workflow
plan = agent_workflow.make_plan("run sql injection exploit", "https://target.com")
# Returns: {'status': 'awaiting_approval', 'action': 'vapt_exploit', ...}

# Execute with approval
result = agent_workflow.execute_approved(plan, approved=True)

# Or use LLM session state machine
session = llm_workflow.VaptSession("session-1")
plan = session.start("exploit the target with sql injection", "https://target.com")
result = session.approve(True)  # Runs passive assessment
```

### Approval Flow (Active Exploitation)
```python
import mcp_server
import approval

# 1. Request approval token
token_data = mcp_server.request_exploit_approval(
    confirmation="APPROVE ACTIVE TEST https://target.com",
    target_url="https://target.com"
)
token = token_data["token"]  # HMAC-SHA256 signed, 30-min TTL

# 2. Execute with token
result = mcp_server.vapt_exploit(
    approval_token=token,
    confirmation="APPROVE ACTIVE TEST https://target.com",
    target_url="https://target.com",
    exploit_categories="injection,xss,ssrf"
)
```

## 🛡️ Security Architecture

### Defense in Depth
1. **Scope Enforcement** — Every request validated against authorized target
2. **DNS Rebinding Protection** — Pre-connect IP resolution, private IP blocking (RFC 1918/4193/3927/6598)
3. **Redirect Safety** — Max 5 redirects, each validated against scope + DNS check
4. **Rate Limiting** — 3 req/s default, per-host concurrency (2), global budget (1000 req)
5. **Response Limits** — 1 MB default, configurable
6. **Cryptographic Approvals** — HMAC-SHA256 tokens bound to target URL, single-use, 30-min TTL
7. **Command Harness** — Explicit argv only, strict target validation, 30s timeout, no shell
7. **Approval Gates** — Explicit human confirmation phrase + cryptographic token

### Threat Model Coverage
| Threat | Mitigation |
|--------|------------|
| DNS Rebinding | Pre-connect resolution + private IP blocklist |
| Scope Escape | `Scope.require()` on every hop including redirects |
| Redirect Abuse | Max 5 redirects, each validated |
| Resource Exhaustion | Global budget, per-host semaphores, response limits |
| Token Forgery | HMAC-SHA256 with rotating secret |
| Token Replay | Single-use consumption, target binding |
| Command Injection | Explicit argv, allowlist, strict target parsing |
| Shell Escape | No shell, blocked interpreters, restricted PATH |

## 📁 Project Structure

```
VAPT-MCP/
├── vapt_mvp.py          # Passive assessment engine & CLI
├── orchestrator.py      # Full pipeline (recon→detect→exploit) & CLI
├── active_vapt.py       # Detection & exploitation modules
├── exploits.py          # 12 generic exploit modules
├── crawler.py           # Deep web crawler for attack surface
├── http_client.py       # Scope-enforcing HTTP client with security controls
├── scope.py             # Target scope definition & validation
├── approval.py          # HMAC-SHA256 approval token system
├── harness.py           # Constrained command execution
├── mcp_server.py        # MCP stdio server (Hercules/Hermes)
├── mcp_tools.py         # MCP tool adapter
├── agent_workflow.py    # Agent planning & approval gate
├── llm_workflow.py      # LLM session state machine
├── automation.py        # Report comparison & alerting
├── history.py           # Assessment history & change detection
├── audit.py             # Audit logging
├── scheduler.py         # Scheduled execution (disabled by default)
├── config.json          # Target & request configuration
├── tests/               # 44 passing unit tests
└── reports/             # Generated JSON/MD reports
```

## 🧪 Testing

```bash
# Run full test suite (44 tests)
python -m unittest discover tests -v

# Specific test modules
python -m unittest tests.test_active_vapt -v
python -m unittest tests.test_vapt_mvp -v
```

## 📊 Report Output

Reports generated as **JSON** (structured) + **Markdown** (human-readable):
- `reports/assessment-<timestamp>.json` — Passive assessment
- `reports/active-<timestamp>.json` — Active assessment with exploits
- `reports/history.json` — Assessment history with change alerts

## Harness integration guides

- [Hermes](HERMES_SETUP.md)
- [Claude Code](CLAUDE_CODE_SETUP.md)
- [OpenCode](OPENCODE_SETUP.md)
- [Codex](CODEX_SETUP.md)

These guides cover installation, stdio MCP registration, passive assessment, approval-gated active verification, job polling, and PDF report generation.

## 🐳 Docker Support

```dockerfile
# Dockerfile (create in project root)
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install requests
ENTRYPOINT ["python"]
```

```bash
# Build
docker build -t vapt-agent .

# Run passive
docker run --rm vapt-agent vapt_mvp.py --target https://example.com

# Run MCP server
docker run -i --rm vapt-agent mcp_server.py
```

## 🔌 Extending the Agent

### Adding New Exploit Modules
```python
# In exploits.py
def test_custom_vuln(client: HttpClient, endpoints: list[str] | None = None) -> list[Finding]:
    findings = []
    for endpoint in endpoints or ["/custom"]:
        resp = client.post(endpoint, json={"payload": "test"})
        if "vulnerable" in resp.text:
            findings.append(Finding(
                "custom-vuln", "Custom Vulnerability", "high",
                "Description...",
                [Evidence("response", {"status": resp.status})],
                remediation="Fix it."
            ))
    return findings

# Register in ALL_EXPLOIT_MODULES
ALL_EXPLOIT_MODULES.append(("custom", test_custom_vuln))
EXPLOIT_CATEGORIES["custom"] = ["custom"]
```

### Adding New Technology Paths
```python
# In active_vapt.py, add to TECHNOLOGY_PATHS
TECHNOLOGY_PATHS["myframework"] = [
    "/myframework/health",
    "/myframework/api",
    "/myframework/admin",
]
```

### Custom HTTP Client Configuration
```python
client = HttpClient(
    scope=Scope.from_url("https://target.com"),
    rate_limit_per_second=5.0,
    max_redirects=3,
    allow_private_ips=True,      # For internal testing
    max_concurrent_per_host=4,
    global_request_budget=2000,
    timeout=15.0
)
```

## ⚠️ Legal & Ethical Use

> **This tool is for authorized testing only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate laws including CFAA (US), Computer Misuse Act (UK), and similar legislation worldwide.

- ✅ Your own applications
- ✅ Client systems with signed engagement letters
- ✅ Bug bounty programs within scope
- ❌ Systems without authorization
- ❌ Production systems without maintenance windows
- ❌ Denial of service or destructive testing

## 📄 License

MIT License — See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`python -m unittest discover tests`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open Pull Request

## 📞 Support

- **Issues**: GitHub Issues for bugs/features
- **Security**: Report vulnerabilities privately via security@ email
- **Documentation**: See `ARCHITECTURE.md` for technical deep-dive

---

**VAPT Agent** — Built for security professionals, integrated for AI agents. 🛡️
