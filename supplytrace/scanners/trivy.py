"""Trivy filesystem scanner adapter."""

from __future__ import annotations

from pathlib import Path

from supplytrace.config import ProjectConfig

from .base import LocalCommandScanner


class TrivyScanner(LocalCommandScanner):
    name = "trivy"
    executable = "trivy"
    version_args = ("--version",)
    success_exit_codes = (0,)

    def command_for_case(self, target: Path, config: ProjectConfig | None = None) -> list[str]:
        command = [self.executable, "fs", "--format", "json", "--scanners", "vuln"]
        if not (config and config.allow_network_scanner_updates):
            command.extend(["--skip-db-update", "--skip-java-db-update"])
        command.append(str(target))
        return command
