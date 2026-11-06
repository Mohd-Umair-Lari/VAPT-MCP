# Claude Code setup

Clone the repository and install dependencies:

```bash
cd <cloned-repo>
python -m pip install -r requirements.txt
```

Create or edit `.mcp.json` in the cloned project:

```json
{
  "mcpServers": {
    "vapt": {
      "command": "<cloned-repo>/.venv/bin/python",
      "args": ["<cloned-repo>/mcp_server.py"]
    }
  }
}
```

On Windows, use `<cloned-repo>/.venv/Scripts/python.exe`. Restart Claude Code and verify that the VAPT tools are available.
