"""Explicitly started local scheduler for recurring safe assessments."""
from __future__ import annotations
import argparse, json, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import automation

@dataclass
class Schedule:
    enabled: bool = False
    interval_minutes: int = 60
    previous_report: str | None = None

def load_schedule(path: Path) -> Schedule:
    data = json.loads(path.read_text(encoding="utf-8")); interval = int(data.get("interval_minutes", 60))
    if interval < 1: raise ValueError("interval_minutes must be at least 1")
    return Schedule(bool(data.get("enabled", False)), interval, data.get("previous_report"))

def run_once(schedule: Schedule, runner: Callable[[str | None], dict[str, Any]] = automation.run_automation) -> dict[str, Any]:
    if not schedule.enabled: return {"status": "disabled", "message": "Scheduling is disabled in schedule.json."}
    run = runner(schedule.previous_report)
    return {"status": "completed", "run": run, "alert": run.get("assessment", {}).get("history", {}).get("alert")}

def run_foreground(schedule: Schedule, runner: Callable[[str | None], dict[str, Any]] = automation.run_automation,
                   sleep_fn: Callable[[float], None] = time.sleep, max_runs: int | None = None) -> list[dict[str, Any]]:
    if not schedule.enabled: return [{"status": "disabled", "message": "Scheduling is disabled in schedule.json."}]
    results = []; count = 0
    while max_runs is None or count < max_runs:
        run = runner(schedule.previous_report)
        results.append({"status": "completed", "run": run, "alert": run.get("assessment", {}).get("history", {}).get("alert")}); count += 1
        if max_runs is None or count < max_runs: sleep_fn(schedule.interval_minutes * 60)
    return results

def main() -> int:
    parser = argparse.ArgumentParser(description="Run the opt-in VAPT scheduler")
    parser.add_argument("--schedule", type=Path, default=Path(__file__).with_name("schedule.json")); parser.add_argument("--once", action="store_true")
    args = parser.parse_args(); schedule = load_schedule(args.schedule)
    print(json.dumps(run_once(schedule) if args.once else run_foreground(schedule), indent=2)); return 0

if __name__ == "__main__": raise SystemExit(main())
