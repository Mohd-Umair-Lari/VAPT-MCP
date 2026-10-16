# Active VAPT, MCP server, and automation

This layer builds on the passive MVP. It adds an **active (attacking)** assessment
that can prove vulnerabilities on the authorized OWASP Juice Shop lab, an **MCP
server** so an LLM/agent can drive it, and a **cron entry point** so it can run on
a schedule.

## The one safety rule that never changes

Everything is hard-locked to `http://192.168.56.101:3000`.

- `scope.py` is the single source of truth for the authorized target.
- Every HTTP request goes through `http_client.py`, which refuses any other host,
  port, or scheme **before a byte leaves the process** — including redirects that
  try to leave scope.
- There is no production code path that points anywhere else. Tests use a local
  mock server through a separate `Scope.for_testing(...)`, never the real allowlist.

## Three phases

| Phase | Auto? | What it does |
|---|---|---|
| `recon` | yes | GET-only requests to well-known endpoints (`/robots.txt`, `/ftp`, search, …) |
| `detect` | yes | low-impact probes that *signal* a likely bug: SQL error on login, reflected search input, missing security headers, cookie flags |
| `exploit` | **no — needs approval** | actively proves impact: SQLi auth bypass (`' OR 1=1--`), weak/default creds, forged `alg:none` JWT, basket IDOR |

## The approval gate (why attacks never fire on a timer)

Recon and detection are safe to run unattended. Exploitation is not, so it is
gated by `approval.py`:

1. A human (or an LLM under human oversight) calls `request_exploit_approval`,
   which mints a short-lived token and records it.
2. Exploitation only runs when that exact token is passed back in.
3. An unattended scheduled run never requests a token, so it can only ever do
   recon + detect. Even if `config.json` sets `phases.exploit = true`, the run is
   still blocked without a valid token.

This is an **intent/audit gate**, not a lock against the machine's owner. Every
phase is appended to `reports/audit.log`.

## Files added

| File | Purpose |
|---|---|
| `scope.py` | The authorized-target allowlist (fail-closed) |
| `http_client.py` | Scope-enforcing, rate-limited HTTP client |
| `active_vapt.py` | Recon / detection / exploitation checks |
| `approval.py` | Exploit approval tokens + audit |
| `audit.py` | Append-only action log |
| `orchestrator.py` | Runs the full pipeline and writes reports/history |
| `mcp_server.py` | MCP server exposing the tools to an LLM/agent |
| `cron_runner.py` | Single-shot, auto-safe entry point for a scheduler |

## Running it from the command line

Recon + detection only (safe):

```bash
python orchestrator.py
```

Full assessment including the gated exploitation phase (a deliberate human run —
it mints and consumes an approval token for you and logs it):

```bash
python orchestrator.py --exploit
```

Reports land in `reports/` as paired `.json` and `.md` files, with a rolling
`history.json` and an `audit.log`.

## Using it as an MCP server plugin (plug into an LLM)

`mcp_server.py` speaks MCP over stdio and exposes five tools: `vapt_scope`,
`vapt_detect`, `request_exploit_approval`, `vapt_exploit`, and `vapt_history`.

Register it with any MCP-capable host (Claude Desktop, an agent framework, etc.):

```json
{
  "mcpServers": {
    "vapt-lab": {
      "command": "python",
      "args": ["C:\\Users\\umair\\projects\\VAPT-MCP\\mcp_server.py"]
    }
  }
}
```

A typical LLM conversation then looks like:

1. `vapt_detect` → safe recon + detection, returns findings.
2. `request_exploit_approval` → returns a token (the human confirms intent here).
3. `vapt_exploit` with that `approval_token` → runs the attack phase.

`vapt_exploit` refuses with a clear reason if the token is missing, wrong,
expired, or already used.

## Scheduling it (cron / hermes / Task Scheduler)

`cron_runner.py` is the single-shot command a scheduler should call. It forces
exploitation **off**, runs recon + detect, writes a report, and prints a JSON
summary with a change `alert` — ideal for piping into mail automation.

- A hermes cron job (or any OS cron) should run:

  ```bash
  python C:\Users\umair\projects\VAPT-MCP\cron_runner.py
  ```

- On Windows without hermes, Task Scheduler can run the same command on a timer.

For a **hermes-native plugin manifest**, share hermes' plugin format and the MCP
server above can be wrapped to match it. If hermes can load MCP servers directly,
use the JSON config shown earlier instead.

## What stays true

Active or automated, the tool only ever touches the authorized lab, exploitation
always requires a deliberate approval, and every action is logged. That is the
part that makes this a security *exercise* and not a weapon.
