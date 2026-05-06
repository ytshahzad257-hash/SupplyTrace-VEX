"""pip-audit adapter for local requirements files."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.run_context import safe_subprocess_run

from .base import LocalCommandScanner


class PipAuditScanner(LocalCommandScanner):
    name = "pip_audit"
    executable = "pip-audit"
    version_args = ("--version",)
    success_exit_codes = (0, 1)

    def is_available(self) -> bool:
        if shutil.which(self.executable):
            return True
        try:
            __import__("pip_audit")
        except Exception:
            return False
        return True

    def capture_version(self) -> str | None:
        if shutil.which(self.executable):
            return super().capture_version()
        try:
            result = safe_subprocess_run(
                ["python", "-m", "pip_audit", "--version"],
                timeout_seconds=30,
                allowed_return_codes=(0,),
            )
        except Exception:
            return "available_version_unknown"
        first_line = (result.stdout or result.stderr).strip().splitlines()
        return first_line[0] if first_line else "available_version_unknown"

    def should_scan_case(self, target: Path) -> tuple[bool, str]:
        if not (
            (target / "requirements.lock").exists()
            or (target / "requirements.txt").exists()
            or (target / "requirements-dev.txt").exists()
        ):
            return False, "requirements-style file not present"
        return True, ""

    def command_for_case(self, target: Path, config: ProjectConfig | None = None) -> list[str]:
        requirements = target / "requirements.lock"
        if not requirements.exists():
            requirements = target / "requirements.txt"
        executable = self.executable if shutil.which(self.executable) else "python"
        command = [
            executable,
            "-r",
            requirements.name,
            "-f",
            "json",
            "--progress-spinner",
            "off",
            "--disable-pip",
            "--no-deps",
        ]
        if executable != self.executable:
            command = [executable, "-m", "pip_audit", *command[1:]]
        return command
