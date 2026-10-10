# Demonstration workflow

From the project directory:

```text
python vapt_mvp.py
python -m unittest discover -s tests -v
```

The first command checks the authorized Juice Shop lab and creates paired reports in `reports/`. The second command verifies the project without contacting the target.

For the restricted tool adapter:

```text
echo {"name":"vapt_scope"} | python mcp_tools.py
```

Review the target and obtain approval before running an assessment through an agent workflow.

## Active assessment, MCP server, and scheduling

Run the full pipeline (see [ACTIVE_VAPT.md](ACTIVE_VAPT.md) for details):

```text
python orchestrator.py            # recon + detection (safe, auto)
python orchestrator.py --exploit  # adds the gated exploitation phase (deliberate)
python cron_runner.py             # auto-safe single run for a scheduler
python mcp_server.py              # start the MCP server for an LLM/agent (stdio)
```

Verify everything offline, without contacting any target:

```text
python -m unittest discover -s tests -v
```

