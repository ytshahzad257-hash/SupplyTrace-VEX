"""npm audit adapter for local package-lock based projects."""

from __future__ import annotations

import json
from pathlib import Path

from supplytrace.config import ProjectConfig

from .base import LocalCommandScanner
from . import base as scanner_base


class NpmAuditScanner(LocalCommandScanner):
    name = "npm_audit"
    executable = "npm"
    version_args = ("--version",)
    success_exit_codes = (0, 1)

    def should_scan_case(self, target: Path) -> tuple[bool, str]:
        if not (target / "package.json").exists():
            return False, "package.json not present"
        return True, ""

    def command_for_case(self, target: Path, config: ProjectConfig | None = None) -> list[str]:
        command = [self.executable, "audit", "--json", "--package-lock-only"]
        if config and config.npm_audit_offline:
            command.append("--offline")
        return command

    def prepare_case(self, config: ProjectConfig, case_dir: Path) -> tuple[dict[str, object], list[str]]:
        """Ensure a local package-lock exists before running npm audit."""

        lockfile = case_dir / "package-lock.json"
        metadata: dict[str, object] = {
            "audit_mode": "offline" if config.npm_audit_offline else "online",
            "package_lock_present": lockfile.exists(),
            "lockfile_generated": False,
        }
        if lockfile.exists():
            return metadata, ["package-lock.json was present before npm audit."]

        resolved = self.resolved_executable() or self.executable
        command = [
            resolved,
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--fund=false",
        ]
        if config.npm_audit_offline:
            command.append("--offline")
        scanner_base.validate_local_command(command)
        try:
            scanner_base.safe_subprocess_run(
                command,
                cwd=case_dir,
                timeout_seconds=self.timeout_seconds,
                allowed_return_codes=(0,),
            )
        except Exception as exc:
            metadata["package_lock_present"] = lockfile.exists()
            return metadata, [f"package-lock.json generation failed: {exc}"]

        generated = lockfile.exists()
        metadata["package_lock_present"] = generated
        metadata["lockfile_generated"] = generated
        if generated:
            return metadata, ["package-lock.json was generated locally with npm install --package-lock-only."]
        return metadata, ["npm install --package-lock-only completed but package-lock.json was not created."]

    def metadata_from_result(
        self,
        config: ProjectConfig,
        case_dir: Path,
        result: scanner_base.CommandResult,
        output_path: str | None,
    ) -> dict[str, object]:
        """Extract npm-audit-specific execution metadata from raw JSON."""

        metadata: dict[str, object] = {
            "audit_mode": "offline" if config.npm_audit_offline else "online",
            "package_lock_present": (case_dir / "package-lock.json").exists(),
            "npm_exit_code": result.returncode,
        }
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            metadata["vulnerabilities_found_count"] = None
            return metadata
        metadata["vulnerabilities_found_count"] = _npm_vulnerability_count(payload)
        return metadata


def _npm_vulnerability_count(payload: dict[str, object]) -> int:
    """Count vulnerability records reported by npm audit without inferring extras."""

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        vulnerability_metadata = metadata.get("vulnerabilities")
        if isinstance(vulnerability_metadata, dict) and isinstance(vulnerability_metadata.get("total"), int):
            return int(vulnerability_metadata["total"])

    vulnerabilities = payload.get("vulnerabilities")
    if isinstance(vulnerabilities, dict):
        return len(vulnerabilities)

    advisories = payload.get("advisories")
    if isinstance(advisories, dict):
        return len(advisories)
    return 0
