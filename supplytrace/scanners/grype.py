"""Grype scanner adapter."""

from __future__ import annotations

from pathlib import Path

from supplytrace.config import ProjectConfig

from .base import LocalCommandScanner


class GrypeScanner(LocalCommandScanner):
    name = "grype"
    executable = "grype"
    version_args = ("version",)
    success_exit_codes = (0,)

    def command_for_case(self, target: Path, config: ProjectConfig | None = None) -> list[str]:
        return [self.executable, f"dir:{target}", "-o", "json"]

    def environment_for_case(self, config: ProjectConfig, case_dir: Path) -> dict[str, str]:
        if config.allow_network_scanner_updates:
            return {}
        return {"GRYPE_DB_AUTO_UPDATE": "false"}
