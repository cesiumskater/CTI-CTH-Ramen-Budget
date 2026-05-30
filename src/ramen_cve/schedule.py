"""ramen_cve.schedule — emit a Windows Task Scheduler XML / cron line
for recurring runs, plus the `schedule` subcommand runner (Layer-4).
See README.md and src/ramen_cve/__init__.py."""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import date
from pathlib import Path

from .cache import Cache
from .constants import DEFAULT_CONFIG_DIR

_log = logging.getLogger(__name__)


def _parse_schedule_time(value: str) -> tuple[int, int]:
    """Parse an ``HH:MM`` 24-hour wall-clock string into ``(hour, minute)``.

    Raises ValueError with a clear message on bad shape so the schedule runner
    can surface it to the user.
    """
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).")
    try:
        h, m = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).") from exc
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"--time out of range: {value!r}. HH must be 0–23 and MM 0–59.")
    return h, m


def _entry_script_path() -> Path:
    """Return the absolute path to threat_intel_hunter.py for schedule commands.

    The package may live under src/ramen_cve/, so we walk one level up from
    DEFAULT_CONFIG_DIR.parent.parent.parent to find the repo root and then
    point at the script. Falls back to a relative name if the script can't
    be located on disk — e.g. when the package was pip-installed via wheel.
    """
    candidate = DEFAULT_CONFIG_DIR.parent.parent.parent / "threat_intel_hunter.py"
    if candidate.is_file():
        return candidate.resolve()
    return Path("threat_intel_hunter.py")


def _build_schedule_command(args: argparse.Namespace) -> tuple[str, list[str]]:
    """Build the (executable, argv) pair the schedule will invoke.

    Returns the Python interpreter path and the argv list that follows. The
    script path is absolute when possible so a scheduled task launched from
    SYSTEM context can still find it. --for-config NAME injects ``--config
    <NAME>`` into the argv so the scheduled run picks up the saved preset.
    """
    python_exec = args.python or sys.executable
    script = str(_entry_script_path())
    invoke = [script]
    if args.for_config:
        invoke.extend(["--config", args.for_config])
    return python_exec, invoke


def _emit_windows_task_xml(args: argparse.Namespace) -> str:
    """Return a Task Scheduler XML payload for the requested daily run.

    The XML is the minimum the Task Scheduler 2.0 schema requires for a
    DailyTrigger + Exec action. Import via:
        schtasks /Create /TN ramen-cve-daily /XML task.xml

    Hour / minute come from --time; the StartBoundary's date portion is today
    so the trigger fires from the next occurrence onward.
    """
    from xml.sax.saxutils import escape

    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    # Task Scheduler wants the executable and the argv list separated:
    cmd = python_exec
    cmd_args = " ".join(_quote_for_task_scheduler(a) for a in invoke)
    start_boundary = f"{date.today().isoformat()}T{h:02d}:{m:02d}:00"
    working_dir = str(_entry_script_path().parent if _entry_script_path().exists() else ".")
    task_name = args.task_name or "ramen-cve-daily"

    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        f'    <URI>\\{escape(task_name)}</URI>\n'
        '    <Author>ramen-cve</Author>\n'
        '    <Description>Daily CVE triage via threat_intel_hunter.py.</Description>\n'
        '  </RegistrationInfo>\n'
        '  <Triggers>\n'
        '    <CalendarTrigger>\n'
        f'      <StartBoundary>{start_boundary}</StartBoundary>\n'
        '      <Enabled>true</Enabled>\n'
        '      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n'
        '    </CalendarTrigger>\n'
        '  </Triggers>\n'
        '  <Principals>\n'
        '    <Principal id="Author">\n'
        '      <LogonType>InteractiveToken</LogonType>\n'
        '      <RunLevel>LeastPrivilege</RunLevel>\n'
        '    </Principal>\n'
        '  </Principals>\n'
        '  <Settings>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        '    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n'
        '    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n'
        '    <AllowHardTerminate>true</AllowHardTerminate>\n'
        '    <StartWhenAvailable>true</StartWhenAvailable>\n'
        '    <Enabled>true</Enabled>\n'
        '    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n'
        '  </Settings>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        f'      <Command>{escape(cmd)}</Command>\n'
        f'      <Arguments>{escape(cmd_args)}</Arguments>\n'
        f'      <WorkingDirectory>{escape(working_dir)}</WorkingDirectory>\n'
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>\n'
    )


def _quote_for_task_scheduler(value: str) -> str:
    """Quote one argv element for embedding in the Task Scheduler <Arguments>
    block. Wraps the value in double quotes if it contains whitespace or
    quote characters; leaves clean tokens untouched."""
    if not value:
        return '""'
    needs_quotes = any(c in value for c in (" ", "\t", "\"", "'"))
    if not needs_quotes:
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _emit_cron_line(args: argparse.Namespace) -> str:
    """Return a single crontab line that runs the tool daily at --time."""
    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    cmd_str = " ".join([python_exec, *invoke])
    return f"{m} {h} * * * {cmd_str}\n"


def _run_schedule(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the schedule subcommand: emit XML or a crontab line."""
    try:
        if args.action == "windows-task":
            payload = _emit_windows_task_xml(args)
        else:  # cron
            payload = _emit_cron_line(args)
    except ValueError as exc:
        _log.error(str(exc))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        _log.info("Wrote %s schedule → %s", args.action, args.output)
    else:
        sys.stdout.write(payload)
    return 0

