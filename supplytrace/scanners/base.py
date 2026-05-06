"""Base classes and orchestration for local-only scanner adapters."""

from __future__ import annotations

import csv
import json
import shutil
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Protocol

from supplytrace.config import ProjectConfig, to_project_relative_path
from supplytrace.run_context import CommandResult, RunContext, UnsafeCommand, safe_subprocess_run, write_json


REMOTE_MARKERS = ("http://", "https://", "ssh://", "git://")

METADATA_FIELDS: tuple[str, ...] = (
    "case_id",
    "scanner_name",
    "ecosystem",
    "tool_available",
    "tool_version",
    "command",
    "started_at",
    "ended_at",
    "duration_seconds",
    "exit_code",
    "status",
    "stdout_path",
    "stderr_path",
    "output_path",
    "audit_mode",
    "package_lock_present",
    "lockfile_generated",
    "vulnerabilities_found_count",
    "npm_exit_code",
    "notes",
)


@dataclass(frozen=True)
class ScannerExecutionRecord:
    """Metadata for one scanner/case execution attempt."""

    case_id: str
    scanner_name: str
    ecosystem: str
    tool_available: bool
    tool_version: str | None
    command: list[str]
    started_at: str
    ended_at: str
    duration_seconds: float
    exit_code: int | None
    status: str
    stdout_path: str | None
    stderr_path: str | None
    output_path: str | None
    notes: str
    audit_mode: str | None = None
    package_lock_present: bool | None = None
    lockfile_generated: bool | None = None
    vulnerabilities_found_count: int | None = None
    npm_exit_code: int | None = None

    def to_json_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_csv_row(self) -> dict[str, object]:
        row = asdict(self)
        row["command"] = json.dumps(self.command)
        return row


class Scanner(Protocol):
    """Scanner adapter protocol."""

    name: str
    executable: str
    version_args: tuple[str, ...]
    success_exit_codes: tuple[int, ...]

    def is_available(self) -> bool:
        ...

    def capture_version(self) -> str | None:
        ...

    def scan_case(
        self,
        config: ProjectConfig,
        case_dir: Path,
        *,
        tool_available: bool,
        tool_version: str | None,
    ) -> ScannerExecutionRecord:
        ...


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_local_target(config: ProjectConfig, target: Path) -> Path:
    """Ensure a scanner target is a local generated testbed case path."""

    resolved = target.resolve()
    cases_root = config.cases_dir.resolve()
    try:
        resolved.relative_to(cases_root)
    except ValueError as exc:
        raise UnsafeCommand(f"scanner target is outside the local testbed: {target}") from exc
    if any(marker in str(resolved).lower() for marker in REMOTE_MARKERS):
        raise UnsafeCommand(f"scanner target contains a remote marker: {target}")
    if not resolved.is_dir():
        raise UnsafeCommand(f"scanner target is not a local directory: {target}")
    return resolved


def validate_local_command(command: Iterable[str]) -> None:
    """Reject command arguments that look like remote targets."""

    for arg in command:
        lowered = str(arg).lower()
        if any(marker in lowered for marker in REMOTE_MARKERS):
            raise UnsafeCommand(f"external scanner target blocked: {arg}")


def _is_json(text: str) -> bool:
    if not text.strip():
        return False
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return False
    return True


def _write_text(path: Path, text: str, config: ProjectConfig | None = None) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if config:
        return to_project_relative_path(path, config) or path.as_posix()
    return str(path)


def _metadata_str(value: object) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _metadata_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _metadata_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except ValueError:
        return None


class LocalCommandScanner:
    """Base adapter for local command-line scanners."""

    name = "base"
    executable = ""
    version_args: tuple[str, ...] = ("--version",)
    success_exit_codes: tuple[int, ...] = (0,)
    timeout_seconds = 600

    def is_available(self) -> bool:
        return bool(shutil.which(self.executable))

    def resolved_executable(self) -> str | None:
        return shutil.which(self.executable)

    def capture_version(self) -> str | None:
        resolved = self.resolved_executable()
        if not resolved:
            return None
        try:
            result = safe_subprocess_run(
                [resolved, *self.version_args],
                timeout_seconds=30,
                allowed_return_codes=(0, 1),
            )
        except Exception:
            return "available_version_unknown"
        lines = (result.stdout or result.stderr).strip().splitlines()
        return lines[0] if lines else "available_version_unknown"

    def should_scan_case(self, case_dir: Path) -> tuple[bool, str]:
        return True, ""

    def command_for_case(self, case_dir: Path, config: ProjectConfig | None = None) -> list[str]:
        raise NotImplementedError

    def environment_for_case(self, config: ProjectConfig, case_dir: Path) -> dict[str, str]:
        return {}

    def prepare_case(self, config: ProjectConfig, case_dir: Path) -> tuple[dict[str, object], list[str]]:
        """Prepare a local case before scanner execution and return metadata."""

        return {}, []

    def metadata_from_result(
        self,
        config: ProjectConfig,
        case_dir: Path,
        result: CommandResult,
        output_path: str | None,
    ) -> dict[str, object]:
        """Return scanner-specific metadata derived from command output."""

        return {}

    def output_dir(self, config: ProjectConfig) -> Path:
        path = config.artifacts_dir / "scanner_raw" / self.name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _record(
        self,
        *,
        case_id: str,
        ecosystem: str,
        tool_available: bool,
        tool_version: str | None,
        command: list[str],
        started_at: str,
        ended_at: str,
        duration_seconds: float,
        exit_code: int | None,
        status: str,
        stdout_path: str | None,
        stderr_path: str | None,
        output_path: str | None,
        notes: str,
        audit_mode: str | None = None,
        package_lock_present: bool | None = None,
        lockfile_generated: bool | None = None,
        vulnerabilities_found_count: int | None = None,
        npm_exit_code: int | None = None,
    ) -> ScannerExecutionRecord:
        return ScannerExecutionRecord(
            case_id=case_id,
            scanner_name=self.name,
            ecosystem=ecosystem,
            tool_available=tool_available,
            tool_version=tool_version,
            command=command,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=round(duration_seconds, 6),
            exit_code=exit_code,
            status=status,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            output_path=output_path,
            audit_mode=audit_mode,
            package_lock_present=package_lock_present,
            lockfile_generated=lockfile_generated,
            vulnerabilities_found_count=vulnerabilities_found_count,
            npm_exit_code=npm_exit_code,
            notes=notes,
        )

    def scan_case(
        self,
        config: ProjectConfig,
        case_dir: Path,
        *,
        tool_available: bool,
        tool_version: str | None,
    ) -> ScannerExecutionRecord:
        case_path = validate_local_target(config, case_dir)
        case_id = case_path.name
        ecosystem = ecosystem_for_case(case_path)
        scanner_dir = self.output_dir(config)
        started_at = utc_now()

        if not tool_available:
            ended_at = utc_now()
            return self._record(
                case_id=case_id,
                ecosystem=ecosystem,
                tool_available=False,
                tool_version=None,
                command=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_seconds=0.0,
                exit_code=None,
                status="unavailable",
                stdout_path=None,
                stderr_path=None,
                output_path=None,
                notes=f"{self.executable} is not installed or not on PATH; no scanner output was generated.",
            )

        applicable, reason = self.should_scan_case(case_path)
        if not applicable:
            ended_at = utc_now()
            return self._record(
                case_id=case_id,
                ecosystem=ecosystem,
                tool_available=True,
                tool_version=tool_version,
                command=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_seconds=0.0,
                exit_code=None,
                status="skipped_not_applicable",
                stdout_path=None,
                stderr_path=None,
                output_path=None,
                notes=reason,
            )

        command = self.command_for_case(case_path, config)
        resolved = self.resolved_executable()
        run_command = list(command)
        if resolved:
            run_command = [resolved, *command[1:]]
        validate_local_command(command)
        validate_local_command(run_command)
        stdout_path: str | None = None
        stderr_path: str | None = None
        output_path: str | None = None
        exit_code: int | None = None
        duration = 0.0
        notes = ""
        metadata: dict[str, object] = {}
        status = "failed"

        try:
            metadata, preparation_notes = self.prepare_case(config, case_path)
            result: CommandResult = safe_subprocess_run(
                run_command,
                cwd=case_path,
                timeout_seconds=self.timeout_seconds,
                allowed_return_codes=tuple(range(0, 256)),
                env=self.environment_for_case(config, case_path),
            )
            duration = result.duration_seconds
            exit_code = result.returncode
            stdout_path = _write_text(scanner_dir / f"{case_id}.stdout.txt", result.stdout, config)
            stderr_path = _write_text(scanner_dir / f"{case_id}.stderr.txt", result.stderr, config)
            if _is_json(result.stdout):
                output_path = _write_text(scanner_dir / f"{case_id}.json", result.stdout, config)
            metadata.update(self.metadata_from_result(config, case_path, result, output_path))
            if result.returncode in self.success_exit_codes and output_path:
                status = "success"
                notes = "Scanner command completed and produced JSON output."
            elif result.returncode in self.success_exit_codes:
                status = "failed"
                notes = "Scanner command completed but did not produce JSON output."
            else:
                status = "failed"
                notes = "Scanner command returned a non-success exit code; no findings are inferred from this status."
            if preparation_notes:
                notes = f"{notes} {' '.join(preparation_notes)}"
        except Exception as exc:
            notes = f"Scanner execution failed before producing a complete result: {exc}"
        ended_at = utc_now()

        return self._record(
            case_id=case_id,
            ecosystem=ecosystem,
            tool_available=True,
            tool_version=tool_version,
            command=command,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=duration,
            exit_code=exit_code,
            status=status,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            output_path=output_path,
            audit_mode=_metadata_str(metadata.get("audit_mode")),
            package_lock_present=_metadata_bool(metadata.get("package_lock_present")),
            lockfile_generated=_metadata_bool(metadata.get("lockfile_generated")),
            vulnerabilities_found_count=_metadata_int(metadata.get("vulnerabilities_found_count")),
            npm_exit_code=_metadata_int(metadata.get("npm_exit_code")),
            notes=notes,
        )


def get_scanners(names: Iterable[str]) -> list[Scanner]:
    """Instantiate scanner adapters by configured name."""

    from .grype import GrypeScanner
    from .npm_audit import NpmAuditScanner
    from .osv import OsvScanner
    from .pip_audit import PipAuditScanner
    from .trivy import TrivyScanner

    registry: dict[str, type[Scanner]] = {
        "osv": OsvScanner,
        "trivy": TrivyScanner,
        "grype": GrypeScanner,
        "npm-audit": NpmAuditScanner,
        "npm_audit": NpmAuditScanner,
        "pip-audit": PipAuditScanner,
        "pip_audit": PipAuditScanner,
    }
    scanners: list[Scanner] = []
    for name in names:
        if name not in registry:
            raise ValueError(f"Unknown scanner '{name}'. Known scanners: {', '.join(sorted(registry))}")
        scanners.append(registry[name]())
    return scanners


def discover_case_dirs(config: ProjectConfig) -> list[Path]:
    """Return generated local case directories."""

    if not config.cases_dir.exists():
        return []
    return sorted(path for path in config.cases_dir.glob("case_*") if path.is_dir())


def ecosystem_for_case(case_dir: Path) -> str:
    """Return the local case ecosystem from metadata or manifests."""

    metadata_path = case_dir / "metadata.json"
    if metadata_path.exists():
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            ecosystem = payload.get("ecosystem")
            if ecosystem:
                return str(ecosystem)
        except Exception:
            pass
    if (case_dir / "package.json").exists():
        return "nodejs"
    if (case_dir / "requirements.txt").exists() or (case_dir / "requirements.lock").exists():
        return "python"
    if (case_dir / "Dockerfile").exists():
        return "container"
    return "unknown"


def _write_metadata_csv(path: Path, records: list[ScannerExecutionRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(METADATA_FIELDS))
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.to_csv_row().get(field) for field in METADATA_FIELDS})


SUMMARY_FIELDS: tuple[str, ...] = (
    "scanner_name",
    "ecosystem",
    "status",
    "count",
    "tool_available",
    "tool_version",
    "notes",
)


def _write_scanner_summary(base_dir: Path, records: list[ScannerExecutionRecord], config: ProjectConfig) -> dict[str, object]:
    grouped: Counter[tuple[str, str, str, bool, str]] = Counter()
    for record in records:
        grouped[
            (
                record.scanner_name,
                record.ecosystem,
                record.status,
                record.tool_available,
                record.tool_version or "",
            )
        ] += 1

    rows: list[dict[str, object]] = []
    for (scanner_name, ecosystem, status, tool_available, version), count in sorted(grouped.items()):
        rows.append(
            {
                "scanner_name": scanner_name,
                "ecosystem": ecosystem,
                "status": status,
                "count": count,
                "tool_available": tool_available,
                "tool_version": version or None,
                "notes": "summarized from scanner_execution_metadata",
            }
        )

    csv_path = base_dir / "scanner_summary.csv"
    json_path = base_dir / "scanner_summary.json"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SUMMARY_FIELDS))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in SUMMARY_FIELDS})

    payload = {
        "scanner_summary_csv": to_project_relative_path(csv_path, config),
        "scanner_summary_json": to_project_relative_path(json_path, config),
        "rows": rows,
        "scanner_count": len({record.scanner_name for record in records}),
        "success_count": sum(1 for record in records if record.status == "success"),
        "unavailable_count": sum(1 for record in records if record.status == "unavailable"),
        "failed_count": sum(1 for record in records if record.status == "failed"),
        "skipped_not_applicable_count": sum(1 for record in records if record.status == "skipped_not_applicable"),
        "claim_scope": "Summary counts describe local scanner execution states, not vulnerability prevalence.",
    }
    write_json(json_path, payload)
    return payload


def run_scanner_pipeline(config: ProjectConfig, context: RunContext | None = None) -> dict[str, object]:
    """Run configured scanners against every generated local case."""

    base_dir = config.artifacts_dir / "scanner_raw"
    base_dir.mkdir(parents=True, exist_ok=True)
    case_dirs = discover_case_dirs(config)
    records: list[ScannerExecutionRecord] = []

    for scanner in get_scanners(config.scanners):
        tool_available = scanner.is_available()
        tool_version = scanner.capture_version() if tool_available else None
        for case_dir in case_dirs:
            records.append(
                scanner.scan_case(
                    config,
                    case_dir,
                    tool_available=tool_available,
                    tool_version=tool_version,
                )
            )

    metadata_json = base_dir / "scanner_execution_metadata.json"
    metadata_csv = base_dir / "scanner_execution_metadata.csv"
    payload = {
        "run_id": context.run_id if context else None,
        "case_count": len(case_dirs),
        "scanner_count": len(set(record.scanner_name for record in records)),
        "execution_count": len(records),
        "metadata_csv": to_project_relative_path(metadata_csv, config),
        "records": [record.to_json_dict() for record in records],
        "claim_scope": (
            "Scanner records reflect local command execution only. Missing tools, failed commands, "
            "and not-applicable cases do not imply vulnerability findings."
        ),
    }
    write_json(metadata_json, payload)
    _write_metadata_csv(metadata_csv, records)
    summary_payload = _write_scanner_summary(base_dir, records, config)
    write_json(base_dir / "index.json", payload)
    return {**payload, **summary_payload}


def scanner_results_to_payload(context: RunContext, results: list[ScannerExecutionRecord]) -> dict[str, object]:
    """Compatibility helper for older callers."""

    return {
        "run_id": context.run_id,
        "results": [result.to_json_dict() for result in results],
        "claim_scope": "Raw scanner records reflect local command execution only.",
    }
