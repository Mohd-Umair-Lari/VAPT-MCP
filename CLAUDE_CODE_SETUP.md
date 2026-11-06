# Claude Code setup

VAPT-MCP runs as a local stdio MCP server.

```bash
cd /path/to/VAPT-MCP
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Register this MCP server in Claude Code using the equivalent of:

```json
{
  "mcpServers": {
    "vapt": {
      "command": "/absolute/path/to/VAPT-MCP/.venv/bin/python",
      "args": ["/absolute/path/to/VAPT-MCP/mcp_server.py"]
    }
  }
}
```

On Windows, use `.venv\\Scripts\\python.exe` and absolute Windows paths.

Recommended prompt:

```text
Run a passive VAPT assessment against this explicitly authorized URL: https://your-domain.example
Poll the returned job_id, retrieve the report, and generate a PDF. Do not execute active verification.
```

Active verification requires listing actions and explicit operator approval before `vapt_exploit` is called. Reports are written to `reports/`.
