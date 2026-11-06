# OpenCode setup

Install the project dependencies:

```bash
cd /path/to/VAPT-MCP
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Add a local stdio MCP server named `vapt` with:

```json
{
  "command": "/absolute/path/to/VAPT-MCP/.venv/bin/python",
  "args": ["/absolute/path/to/VAPT-MCP/mcp_server.py"]
}
```

Use the Windows `.venv\\Scripts\\python.exe` path when applicable. Restart OpenCode and verify that the VAPT tools appear.

Run a passive job:

```text
Run a passive VAPT assessment against this authorized URL: https://your-domain.example
Call vapt_start_assessment, poll its job_id, call vapt_get_report, then call vapt_generate_pdf_report. Do not call vapt_exploit.
```

Active checks remain approval-gated. The PDF, JSON, and Markdown files are stored in `reports/`.
