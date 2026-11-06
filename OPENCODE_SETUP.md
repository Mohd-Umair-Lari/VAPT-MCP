# OpenCode setup

Clone the repository and install dependencies:

```bash
cd <cloned-repo>
python -m pip install -r requirements.txt
```

In the OpenCode project configuration, usually `opencode.json`, add:

```json
{
  "mcp": {
    "vapt": {
      "type": "local",
      "command": [
        "<cloned-repo>/.venv/bin/python",
        "<cloned-repo>/mcp_server.py"
      ],
      "enabled": true
    }
  }
}
```

On Windows, use `<cloned-repo>/.venv/Scripts/python.exe`. Restart OpenCode and verify the VAPT tools appear.
