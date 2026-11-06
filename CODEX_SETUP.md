# Codex setup

Clone the repository and install dependencies:

```bash
cd <cloned-repo>
python -m pip install -r requirements.txt
```

In Codex MCP settings, add a local stdio server. Replace `<cloned-repo>` with the absolute path to the user’s clone:

```text
Name: vapt
Command: <cloned-repo>/.venv/bin/python
Arguments: <cloned-repo>/mcp_server.py
Transport: stdio
```

On Windows, use `<cloned-repo>/.venv/Scripts/python.exe`. Reload MCP and ask Codex to list the VAPT tools without executing anything.
