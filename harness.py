"""Constrained Kali command harness for VAPT assessments.

Commands are explicit argv lists, never shell strings. Only approved tools are
accepted, and network commands must explicitly target the configured host:port.
Active verification is disabled until the caller supplies a valid approval record.
"""
from __future__ import annotations

import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


# Only truly safe, non-Turing-complete tools
ALLOWED_TOOLS = {"nmap", "curl", "httpx", "jq", "grep"}
# Network tools that must target the authorized scope
NETWORK_TOOLS = {"nmap", "curl", "httpx"}
# Explicitly blocked dangerous commands
BLOCKED_TOKENS = {"rm", "shutdown", "reboot", "mkfs", "nc", "netcat", "bash", "sh", "powershell", "cmd", "python", "python3", "perl", "ruby", "php", "node", "awk", "sed"}


def _extract_target_from_argv(argv: list[str], tool: str) -> list[str]:
    """Extract target host:port from command arguments for validation.
    
    Returns list of target strings found in the command.
    """
    targets = []
    if tool == "nmap":
        # nmap: target is typically the last argument, or after -p
        for i, arg in enumerate(argv):
            if arg.startswith("-"):
                continue
            # Skip options and their arguments
            if i > 0 and argv[i-1].startswith("-"):
                continue
            # This might be a target
            if not arg.startswith("-") and (":" in arg or "/" in arg or arg.replace(".", "").isdigit()):
                targets.append(arg)
    elif tool in {"curl", "httpx"}:
        # curl/httpx: URL is typically after the command
        for arg in argv[1:]:
            if arg.startswith("http://") or arg.startswith("https://"):
                parsed = urlparse(arg)
                if parsed.hostname:
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    targets.append(f"{parsed.hostname}:{port}")
    return targets


@dataclass
class CommandJob:
    job_id: str
    argv: list[str]
    mode: str
    status: str = "queued"
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    error: str | None = None
    events: list[str] = field(default_factory=list)


class Harness:
    def __init__(self, target_host: str, target_port: int) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.target = f"{target_host}:{target_port}"
        self.jobs: dict[str, CommandJob] = {}
        self.lock = threading.Lock()

    def validate(self, argv: list[str], mode: str = "passive", approved: bool = False) -> None:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("command must be a non-empty argv list")
        executable = argv[0].rsplit("/", 1)[-1]
        if executable not in ALLOWED_TOOLS:
            raise ValueError(f"tool is not allowed: {executable}")
        lowered = {item.lower() for item in argv}
        if lowered & BLOCKED_TOKENS:
            raise ValueError("blocked command token")
        if mode not in {"passive", "active"}:
            raise ValueError("mode must be passive or active")
        if mode == "active" and not approved:
            raise ValueError("active verification requires explicit approval")
        
        # Network tools must EXPLICITLY target the authorized host:port
        # Parse arguments to find actual targets being used
        if executable in NETWORK_TOOLS:
            targets = _extract_target_from_argv(argv, executable)
            if not targets:
                raise ValueError(f"network command must explicitly include target host:port")
            # Verify ALL targets match the authorized target
            for target in targets:
                if target != self.target:
                    raise ValueError(f"network command targets {target}, but only {self.target} is authorized")

    def start(self, argv: list[str], mode: str = "passive", approved: bool = False) -> dict[str, Any]:
        self.validate(argv, mode, approved)
        job_id = "cmd-" + uuid.uuid4().hex[:12]
        job = CommandJob(job_id, argv, mode)
        with self.lock:
            self.jobs[job_id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return {"job_id": job_id, "status": "queued", "argv": argv, "mode": mode}

    def _run(self, job: CommandJob) -> None:
        try:
            with self.lock:
                job.status = "running"; job.events.append("started")
            # Use subprocess with no shell, explicit argv
            process = subprocess.Popen(
                job.argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # Security: no shell, limited env
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"}
            )
            stdout, stderr = process.communicate(timeout=30)
            with self.lock:
                job.stdout = stdout; job.stderr = stderr; job.return_code = process.returncode
                job.status = "completed" if process.returncode == 0 else "failed"; job.events.append("finished")
        except subprocess.TimeoutExpired:
            with self.lock:
                job.error = "command timed out after 30s"
                job.status = "failed"; job.events.append("timeout")
        except Exception as error:
            with self.lock:
                job.error = str(error); job.status = "failed"; job.events.append("error")

    def status(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            if job_id not in self.jobs: raise ValueError("Unknown command job_id")
            return vars(self.jobs[job_id]).copy()


# No default harness - must be created with explicit target
