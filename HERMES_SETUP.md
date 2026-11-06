# Hermes setup

After cloning this repository, install its dependencies:

```bash
cd <cloned-repo>
python -m pip install -r requirements.txt
```

Edit Hermes’ configuration file:

```text
Windows: %LOCALAPPDATA%\hermes\config.yaml
Linux/macOS: ~/.config/hermes/config.yaml
```

Add the server under `mcp_servers:`. Replace `<cloned-repo>` with the absolute path to your clone:

```yaml
vapt:
  command: "<cloned-repo>/.venv/Scripts/python.exe"
  args:
    - "<cloned-repo>/mcp_server.py"
  timeout: 120
```

On Linux/macOS, use `<cloned-repo>/.venv/bin/python` instead.

Restart Hermes or run `/reload-mcp`, then ask it to list the VAPT tools without executing a scan.
