"""Run IDs, tool capture, and safe local subprocess execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .config import ProjectConfig, ensure_artifact_dirs


class ToolUnavailable(RuntimeError):
    """Raised when an external scanner or helper is not installed."""


class UnsafeCommand(RuntimeError):
    """Raised when a command appears to target a remote system."""


@dataclass(frozen=True)
class RunContext:
    """Resolved context for one pipeline execution."""

    config: ProjectConfig
    run_id: str
    artifact_dirs: dict[str, Path]

    def run_dir(self, artifact_kind: str) -> Path:
        path = self.artifact_dirs[artifact_kind] / self.run_id
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass(frozen=True)
class CommandResult:
    """Serializable subprocess result."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": round(self.duration_seconds, 6),
        }


def generate_run_id(now: datetime | None = None) -> str:
    """Create a sortable run ID with a short random suffix."""

    current = now or datetime.now(timezone.utc)
    return f"{current.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def create_run_context(config: ProjectConfig, run_id: str | None = None) -> RunContext:
    """Create artifact directories and return a run context."""

    return RunContext(
        config=config,
        run_id=run_id or generate_run_id(),
        artifact_dirs=ensure_artifact_dirs(config),
    )


def require_tool(executable: str) -> str:
    """Return the resolved executable path or raise ``ToolUnavailable``."""

    resolved = shutil.which(executable)
    if not resolved:
        raise ToolUnavailable(f"Required tool is not installed or not on PATH: {executable}")
    if os.name == "nt":
        resolved_path = Path(resolved)
        if not resolved_path.suffix:
            for suffix in (".cmd", ".exe", ".bat"):
                candidate = resolved_path.with_suffix(suffix)
                if candidate.exists():
                    return str(candidate)
    return resolved


def _assert_local_command(command: Sequence[str]) -> None:
    remote_markers = ("http://", "https://", "ssh://", "git://")
    for arg in command:
        lowered = arg.lower()
        if any(marker in lowered for marker in remote_markers):
            raise UnsafeCommand(
                "SupplyTrace-VEX only runs scanners against local paths or local images; "
                f"remote-looking argument blocked: {arg}"
            )


def safe_subprocess_run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 300,
    allowed_return_codes: Iterable[int] = (0,),
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a local command without a shell and capture stdout/stderr."""

    if isinstance(command, str):
        raise TypeError("Command must be a sequence of arguments, not a shell string")
    if not command:
        raise ValueError("Command must not be empty")

    command_tuple = tuple(str(item) for item in command)
    _assert_local_command(command_tuple)
    resolved_executable = require_tool(command_tuple[0])
    runnable_command = (resolved_executable, *command_tuple[1:])

    start = time.perf_counter()
    subprocess_env = dict(os.environ)
    if env:
        subprocess_env.update(dict(env))

    completed = subprocess.run(
        runnable_command,
        cwd=str(cwd) if cwd else None,
        env=subprocess_env,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        shell=False,
        check=False,
    )
    duration = time.perf_counter() - start
    result = CommandResult(
        command=runnable_command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_seconds=duration,
    )
    if completed.returncode not in set(allowed_return_codes):
        raise subprocess.CalledProcessError(
            completed.returncode,
            runnable_command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return result


def capture_tool_version(
    executable: str,
    version_args: Sequence[str] = ("--version",),
    timeout_seconds: int = 30,
) -> dict[str, object]:
    """Capture a tool version if the tool is available."""

    try:
        require_tool(executable)
    except ToolUnavailable:
        return {
            "tool": executable,
            "available": False,
            "version": None,
            "error": "not found on PATH",
        }
    try:
        result = safe_subprocess_run(
            (executable, *version_args),
            timeout_seconds=timeout_seconds,
            allowed_return_codes=(0, 1),
        )
    except Exception as exc:  # pragma: no cover - defensive audit path
        return {
            "tool": executable,
            "available": True,
            "version": None,
            "error": str(exc),
        }
    version = (result.stdout or result.stderr).strip().splitlines()
    return {
        "tool": executable,
        "available": True,
        "version": version[0] if version else "",
        "returncode": result.returncode,
    }


def write_json(path: Path, payload: object) -> Path:
    """Write stable, UTF-8 JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
