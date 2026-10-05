# VAPT MVP Architecture

## Flow

```text
Agent request
    -> agent_workflow.py
    -> explicit approval
    -> mcp_tools.py adapter
    -> vapt_mvp.py assessment engine
    -> local reports/*.json and reports/*.md
```

## Safety boundaries

- The target is fixed to `http://192.168.56.101:3000/`.
- The assessment uses ordinary, non-intrusive HTTP requests.
- No shell execution, arbitrary URLs, exploitation, fuzzing, or brute force is exposed.
- Reports are written beside the code in `reports/`.
- Automation compares findings but does not install a background scheduler.

## Main files

| File | Purpose |
|---|---|
| `config.json` | Target and request settings |
| `vapt_mvp.py` | Assessment engine and report writer |
| `mcp_tools.py` | Restricted tool adapter |
| `agent_workflow.py` | Planning and approval gate |
| `automation.py` | Local run and report comparison helpers |
| `tests/` | Offline test suite |
