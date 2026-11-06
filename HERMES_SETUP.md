# Hermes setup

## Install

```powershell
cd C:\Users\umair\projects\VAPT-MCP
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Configure `%LOCALAPPDATA%\hermes\config.yaml`

Use one canonical stdio server entry:

```yaml
mcp_servers:
  vapt:
    command: "C:/Users/umair/projects/VAPT-MCP/.venv/Scripts/python.exe"
    args:
      - "C:/Users/umair/projects/VAPT-MCP/mcp_server.py"
    timeout: 120
    connect_timeout: 10
    tools:
      include:
        - vapt_get_scope
        - vapt_start_assessment
        - vapt_get_status
        - vapt_get_report
        - vapt_generate_pdf_report
        - vapt_get_history
        - vapt_detect
        - vapt_list_active_actions
        - request_exploit_approval
        - vapt_exploit
        - vapt_crawl
        - vapt_exec_command
        - vapt_get_command_output
      resources: false
      prompts: false
```

Use an absolute Python path so Hermes uses the environment containing `reportlab`.

Reload MCP with `/reload-mcp`, then ask:

```text
List the VAPT MCP tools and explain each one. Do not execute a scan.
```

## Run

```text
Run a passive VAPT assessment against this authorized URL: https://your-domain.example
Use target_url for this run, poll the returned job_id, show the findings, and generate a PDF report. Do not perform active verification.
```

For active verification, Hermes must list actions first, request explicit approval, and use the same target-bound approval token and confirmation phrase.

## Troubleshooting

Use the returned `job_id` for status and report calls. The `assessment_id` inside a report is not a job ID.
