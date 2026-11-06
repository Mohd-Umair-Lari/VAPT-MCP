# Codex setup

## Install

```powershell
cd C:\Users\umair\projects\VAPT-MCP
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## MCP registration

Configure a local stdio server with:

```text
Command: C:\Users\umair\projects\VAPT-MCP\.venv\Scripts\python.exe
Arguments: C:\Users\umair\projects\VAPT-MCP\mcp_server.py
Transport: stdio
```

Verify discovery:

```text
Show the available VAPT MCP tools without executing them.
```

Run a passive assessment:

```text
Run a passive VAPT assessment against this explicitly authorized URL: https://your-domain.example
Use target_url, poll the returned job_id, retrieve the report, and generate the PDF. Do not perform active verification.
```

For active verification, review the listed actions and provide explicit approval before execution. Always use the returned `job_id`, not the report's `assessment_id`, for status calls.
