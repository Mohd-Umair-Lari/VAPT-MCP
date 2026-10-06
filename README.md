# VAPT MVP — Phase 1

This is a small, lab-only baseline for the authorized OWASP Juice Shop target:
`http://192.168.56.101:3000/`.

It performs one ordinary HTTP `GET /`, records the UTC time, status, and response headers, checks common safe configuration issues, and writes structured findings with evidence, confidence, remediation, and summary counts. Recon checks three fixed public files: `robots.txt`, `sitemap.xml`, and `.well-known/security.txt`. It does not exploit, fuzz, crawl, or send intrusive requests.

## Run

Python 3.10+ is recommended. No third-party packages are required.

```text
python vapt_mvp.py
```

Reports are written to the local `reports/` folder beside `vapt_mvp.py` as matching `.json` and `.md` files. To use another output directory explicitly:

```text
python vapt_mvp.py --report-dir .\reports
```

The allowlist is in `config.json`. The runner refuses configurations other than the authorized lab host and port (`192.168.56.101:3000`). Keep this project limited to systems you own or have explicit permission to test.

## Phase 1 layout

- `config.json` — target allowlist and request settings
- `vapt_mvp.py` — CLI, assessment state, HTTP check, findings, evidence, and report writers
- `requirements.txt` — dependency declaration (empty apart from a note because stdlib is sufficient)

## Tests

Run the local test suite without contacting the lab target:

```text
python -m unittest discover -s tests -v
```

The tests cover target allowlisting, safe finding logic, summary generation, and report creation.

## Phase 9 tool adapter

`mcp_tools.py` exposes two restricted operations for an MCP bridge:

- `vapt_scope` — returns the authorized target and available safe checks.
- `vapt_assess` — runs the assessment and returns structured results plus report paths.

For a local JSON-line smoke test:

```text
echo {"name":"vapt_scope"} | python mcp_tools.py
```

The adapter does not provide shell execution, arbitrary URLs, exploitation, Hermes integration, or scheduling.

## Phase 10 agent workflow

`agent_workflow.py` converts a request into a plan and requires explicit approval before execution. Intrusive requests such as exploitation, payloads, brute force, and shell commands are rejected.

## Phase 11 automation helpers

`automation.py` supports opt-in local runs and report comparison. It identifies new, resolved, and unchanged findings. It does not install or start a background scheduler yet.

## Phase 14 interactive LLM workflow

`llm_workflow.py` provides a provider-neutral session state machine. An LLM host can submit a request, show the target and checks to the user, wait for explicit approval, and then receive the structured assessment result. The workflow rejects intrusive requests and never executes arbitrary model-generated code. A real model/provider connection is intentionally a separate integration step.

## Phase 15 scheduled execution

`schedule.json` is disabled by default. After enabling it, run one scheduled assessment with `python scheduler.py --once`, or start the explicitly foreground loop with `python scheduler.py`. No operating-system cron job is installed automatically.

## Phase 16 history and alerts

`history.py` stores compact assessment history in `reports/history.json`. Every tool-triggered and scheduled assessment now records its result, compares it with the previous run, and returns a structured alert only when findings change. External notifications are intentionally not connected yet.

## Final project files

- `ARCHITECTURE.md` — system flow and safety boundaries
- `DEMO.md` — short demonstration procedure
- `pyproject.toml` — optional packaging and command entry points

The project has no runtime dependencies beyond Python 3.10+.
