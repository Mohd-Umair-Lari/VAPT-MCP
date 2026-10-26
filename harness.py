"""Constrained Kali command harness for the authorized lab target.

Commands are explicit argv lists, never shell strings. Only approved tools are
accepted, and network commands must include the configured target. Active
verification is disabled until the caller supplies an approval record.
"""
from __future__ import annotations

import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

ALLOWED_TOOLS = {"nmap", "curl", "httpx", "jq", "grep", "sed", "awk", "base64", "python3"}
NETWORK_TOOLS = {"nmap", "curl", "httpx"}
BLOCKED_TOKENS = {"rm", "shutdown", "reboot", "mkfs", "nc", "netcat", "bash", "sh", "powershell", "cmd"}


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
    def __init__(self, target_host: str = "192.168.56.102", target_port: int = 3000) -> None:
        self.target_host = target_host
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
        if executable in NETWORK_TOOLS and not any(self.target_host in item or self.target in item for item in argv):
            raise ValueError("network command must include the authorized target")

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
            process = subprocess.Popen(job.argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            with self.lock:
                job.stdout = stdout; job.stderr = stderr; job.return_code = process.returncode
                job.status = "completed" if process.returncode == 0 else "failed"; job.events.append("finished")
        except Exception as error:
            with self.lock:
                job.error = str(error); job.status = "failed"; job.events.append("error")

    def status(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            if job_id not in self.jobs: raise ValueError("Unknown command job_id")
            return vars(self.jobs[job_id]).copy()


DEFAULT_HARNESS = Harness()
