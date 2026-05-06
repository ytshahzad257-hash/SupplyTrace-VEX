"""OSV-Scanner adapter."""

from __future__ import annotations

from pathlib import Path

from supplytrace.config import ProjectConfig

from .base import LocalCommandScanner


class OsvScanner(LocalCommandScanner):
    name = "osv"
    executable = "osv-scanner"
    version_args = ("--version",)
    success_exit_codes = (0, 1)

    def command_for_case(self, target: Path, config: ProjectConfig | None = None) -> list[str]:
        command = [self.executable, "scan", "source", "--format", "json", "--recursive", str(target)]
        if not (config and config.allow_network_scanner_updates):
            command.append("--offline-vulnerabilities")
        return command
