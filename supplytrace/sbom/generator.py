"""SBOM generation for local SupplyTrace-VEX testbed cases."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from supplytrace import __version__
from supplytrace.config import ProjectConfig, to_project_relative_path
from supplytrace.run_context import RunContext, safe_subprocess_run, write_json
from supplytrace.sbom.parsers import components_from_manifests
from supplytrace.sbom.schema import SbomComponent, make_component, make_internal_sbom, utc_now


@dataclass(frozen=True)
class ExternalSbomTool:
    """External tool configuration for real SBOM output generation."""

    format_name: str
    output_dir_name: str
    executable: str
    output_argument: str


EXTERNAL_TOOLS: tuple[ExternalSbomTool, ...] = (
    ExternalSbomTool(
        format_name="syft",
        output_dir_name="syft",
        executable="syft",
        output_argument="syft-json",
    ),
    ExternalSbomTool(
        format_name="cyclonedx",
        output_dir_name="cyclonedx",
        executable="cyclonedx-py",
        output_argument="json",
    ),
    ExternalSbomTool(
        format_name="spdx",
        output_dir_name="spdx",
        executable="syft",
        output_argument="spdx-json",
    ),
)

METADATA_FIELDS: tuple[str, ...] = (
    "case_id",
    "case_hash",
    "component_count",
    "internal_path",
    "internal_tool_name",
    "internal_tool_version",
    "internal_tool_status",
    "syft_tool_name",
    "syft_tool_version",
    "syft_tool_status",
    "syft_path",
    "cyclonedx_tool_name",
    "cyclonedx_tool_version",
    "cyclonedx_tool_status",
    "cyclonedx_path",
    "spdx_tool_name",
    "spdx_tool_version",
    "spdx_tool_status",
    "spdx_path",
    "external_sbom_count",
    "sbom_completeness_score",
    "notes",
)

TOOL_SUMMARY_FIELDS: tuple[str, ...] = (
    "tool_name",
    "sbom_format",
    "status",
    "case_count",
    "generated_count",
    "unavailable_count",
    "error_count",
    "notes",
)


def discover_case_dirs(config: ProjectConfig) -> list[Path]:
    """Return generated local testbed case directories."""

    if not config.cases_dir.exists():
        return []
    return sorted(path for path in config.cases_dir.glob("case_*") if path.is_dir())


def case_hash(case_dir: Path) -> str:
    """Compute a deterministic hash over a case directory's files."""

    digest = hashlib.sha256()
    for path in sorted(item for item in case_dir.rglob("*") if item.is_file()):
        digest.update(path.relative_to(case_dir).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def components_from_case(case_dir: Path) -> list[dict[str, object]]:
    """Return parsed components in the dict shape expected by downstream modules."""

    components = []
    for item in components_from_manifests(case_dir):
        components.append(
            make_component(
                item.name,
                item.version,
                item.ecosystem,
                item.dependency_scope,
                package_manager=item.package_manager,
                direct_or_transitive=item.direct_or_transitive,
                source_manifest=item.source_manifest,
            )
        )
    return components


def _tool_version(executable: str) -> str | None:
    if executable == "cyclonedx-py" and importlib.util.find_spec("cyclonedx_py") is not None:
        try:
            result = safe_subprocess_run(
                [sys.executable, "-m", "cyclonedx_py", "--version"],
                timeout_seconds=30,
                allowed_return_codes=(0,),
            )
        except Exception:
            return "available_version_unknown"
        first_line = (result.stdout or result.stderr).strip().splitlines()
        return first_line[0] if first_line else "available_version_unknown"
    resolved = shutil.which(executable)
    if not resolved:
        return None
    try:
        result = safe_subprocess_run(
            [executable, "version"],
            timeout_seconds=30,
            allowed_return_codes=(0,),
        )
    except Exception:
        try:
            result = safe_subprocess_run(
                [executable, "--version"],
                timeout_seconds=30,
                allowed_return_codes=(0,),
            )
        except Exception:
            return "available_version_unknown"
    first_line = (result.stdout or result.stderr).strip().splitlines()
    return first_line[0] if first_line else "available_version_unknown"


def _sbom_dirs(config: ProjectConfig) -> dict[str, Path]:
    base = config.artifacts_dir / "sbom"
    dirs = {
        "base": base,
        "internal": base / "internal",
        "syft": base / "syft",
        "cyclonedx": base / "cyclonedx",
        "spdx": base / "spdx",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def _internal_notes(external_statuses: dict[str, dict[str, str | None]]) -> list[str]:
    notes = [
        "Internal fallback SBOM derived from local manifests only.",
        "This file is not external CycloneDX or SPDX tool output.",
    ]
    unavailable = [
        name
        for name, status in external_statuses.items()
        if status.get("tool_status") != "generated"
    ]
    if unavailable:
        notes.append(
            "External SBOM formats were not generated for all requested formats; see sbom_generation_metadata.csv."
        )
    return notes


def _validate_external_payload(format_name: str, payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if format_name == "cyclonedx":
        return payload.get("bomFormat") == "CycloneDX"
    if format_name == "spdx":
        return "spdxVersion" in payload or payload.get("SPDXID") == "SPDXRef-DOCUMENT"
    if format_name == "syft":
        return "artifacts" in payload or "source" in payload
    return False


def _try_generate_external(
    *,
    config: ProjectConfig,
    case_dir: Path,
    output_path: Path,
    tool: ExternalSbomTool,
) -> dict[str, str | None]:
    """Generate a real external SBOM if the configured tool is available."""

    tool_version = _tool_version(tool.executable)
    if tool.executable == "cyclonedx-py":
        requirements = case_dir / "requirements.txt"
        command = [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            requirements.name,
            "--of",
            "JSON",
            "--output-reproducible",
            "--no-validate",
            "-o",
            str(output_path),
        ]
    else:
        command = [tool.executable, f"dir:{case_dir}", "-o", tool.output_argument]
    if tool_version is None:
        return {
            "tool_name": tool.executable,
            "tool_version": None,
            "tool_status": "unavailable",
            "path": None,
            "generation_command": " ".join(command),
            "notes": f"{tool.executable} was not found on PATH; no {tool.format_name} file was created.",
        }
    if tool.executable == "cyclonedx-py" and not (case_dir / "requirements.txt").exists():
        return {
            "tool_name": tool.executable,
            "tool_version": tool_version,
            "tool_status": "not_applicable",
            "path": None,
            "generation_command": " ".join(command),
            "notes": "CycloneDX Python requirements generation applies only to cases with requirements.txt.",
        }

    try:
        result = safe_subprocess_run(
            command,
            cwd=case_dir,
            timeout_seconds=300,
            allowed_return_codes=(0,),
        )
        output_text = output_path.read_text(encoding="utf-8") if output_path.exists() else result.stdout
        if not output_text.strip():
            return {
                "tool_name": tool.executable,
                "tool_version": tool_version,
                "tool_status": "error_empty_output",
                "path": None,
                "generation_command": " ".join(command),
                "notes": f"{tool.executable} produced empty output; no {tool.format_name} file was created.",
            }
        payload = json.loads(output_text)
        if not _validate_external_payload(tool.format_name, payload):
            return {
                "tool_name": tool.executable,
                "tool_version": tool_version,
                "tool_status": "error_invalid_output",
                "path": None,
                "generation_command": " ".join(command),
                "notes": f"{tool.executable} output was not valid {tool.format_name} JSON.",
            }
        write_json(output_path, payload)
        return {
            "tool_name": tool.executable,
            "tool_version": tool_version,
            "tool_status": "generated",
            "path": to_project_relative_path(output_path, config),
            "generation_command": " ".join(command),
            "notes": "External SBOM file was generated from real tool output.",
        }
    except Exception as exc:
        return {
            "tool_name": tool.executable,
            "tool_version": tool_version,
            "tool_status": "error",
            "path": None,
            "generation_command": " ".join(command),
            "notes": f"{tool.executable} failed: {exc}",
        }


def _write_metadata_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(METADATA_FIELDS))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in METADATA_FIELDS})


def _row_for_case(
    *,
    case_id: str,
    config: ProjectConfig,
    hash_value: str,
    component_count: int,
    internal_path: Path,
    external_statuses: dict[str, dict[str, str | None]],
) -> dict[str, object]:
    syft = external_statuses["syft"]
    cyclonedx = external_statuses["cyclonedx"]
    spdx = external_statuses["spdx"]
    external_count = sum(1 for status in external_statuses.values() if status.get("tool_status") == "generated")
    completeness = round((1 + external_count) / 4, 6)
    notes = [
        "Internal fallback SBOM is always generated from local manifests.",
        str(syft.get("notes", "")),
        str(cyclonedx.get("notes", "")),
        str(spdx.get("notes", "")),
    ]
    return {
        "case_id": case_id,
        "case_hash": hash_value,
        "component_count": component_count,
        "internal_path": to_project_relative_path(internal_path, config),
        "internal_tool_name": "supplytrace-manifest-parser",
        "internal_tool_version": __version__,
        "internal_tool_status": "generated",
        "syft_tool_name": syft.get("tool_name"),
        "syft_tool_version": syft.get("tool_version"),
        "syft_tool_status": syft.get("tool_status"),
        "syft_path": syft.get("path"),
        "cyclonedx_tool_name": cyclonedx.get("tool_name"),
        "cyclonedx_tool_version": cyclonedx.get("tool_version"),
        "cyclonedx_tool_status": cyclonedx.get("tool_status"),
        "cyclonedx_path": cyclonedx.get("path"),
        "spdx_tool_name": spdx.get("tool_name"),
        "spdx_tool_version": spdx.get("tool_version"),
        "spdx_tool_status": spdx.get("tool_status"),
        "spdx_path": spdx.get("path"),
        "external_sbom_count": external_count,
        "sbom_completeness_score": completeness,
        "notes": " ".join(item for item in notes if item),
    }


def _write_tool_summary(path: Path, rows: list[dict[str, object]], case_count: int) -> list[dict[str, object]]:
    summary_rows: list[dict[str, object]] = []
    for format_name in ("internal", "syft", "cyclonedx", "spdx"):
        if format_name == "internal":
            status_values = ["generated" for _ in rows]
            tool_name = "supplytrace-manifest-parser"
        else:
            status_values = [str(row.get(f"{format_name}_tool_status") or "unknown") for row in rows]
            tool_name = str(next((row.get(f"{format_name}_tool_name") for row in rows if row.get(f"{format_name}_tool_name")), "syft"))
        generated_count = sum(1 for value in status_values if value == "generated")
        unavailable_count = sum(1 for value in status_values if value == "unavailable")
        error_count = sum(1 for value in status_values if value.startswith("error"))
        summary_rows.append(
            {
                "tool_name": tool_name,
                "sbom_format": format_name,
                "status": "generated" if generated_count == case_count else "partial" if generated_count else "unavailable_or_error",
                "case_count": case_count,
                "generated_count": generated_count,
                "unavailable_count": unavailable_count,
                "error_count": error_count,
                "notes": "external formats are generated only from real tool output" if format_name != "internal" else "internal fallback is manifest-derived",
            }
        )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(TOOL_SUMMARY_FIELDS))
        writer.writeheader()
        for row in summary_rows:
            writer.writerow({field: row.get(field) for field in TOOL_SUMMARY_FIELDS})
    return summary_rows


def generate_sboms(config: ProjectConfig, context: RunContext | None = None) -> dict[str, object]:
    """Generate SBOM artifacts for every local testbed case."""

    dirs = _sbom_dirs(config)
    records: list[dict[str, object]] = []
    metadata_rows: list[dict[str, object]] = []
    generated_at = utc_now()

    for case_dir in discover_case_dirs(config):
        case_id = case_dir.name
        parsed_components: list[SbomComponent] = components_from_manifests(case_dir)
        hash_value = case_hash(case_dir)

        external_statuses: dict[str, dict[str, str | None]] = {}
        for tool in EXTERNAL_TOOLS:
            output_path = dirs[tool.output_dir_name] / f"{case_id}.json"
            status = _try_generate_external(config=config, case_dir=case_dir, output_path=output_path, tool=tool)
            external_statuses[tool.format_name] = status

        internal_path = dirs["internal"] / f"{case_id}.json"
        internal_sbom = make_internal_sbom(
            case_id=case_id,
            generated_at=generated_at,
            tool_name="supplytrace-manifest-parser",
            tool_version=__version__,
            tool_status="generated",
            components=parsed_components,
            case_hash=hash_value,
            generation_command=["python", "-m", "supplytrace", "generate-sbom"],
            notes=_internal_notes(external_statuses),
        )
        write_json(internal_path, internal_sbom)

        row = _row_for_case(
            case_id=case_id,
            config=config,
            hash_value=hash_value,
            component_count=len(parsed_components),
            internal_path=internal_path,
            external_statuses=external_statuses,
        )
        metadata_rows.append(row)
        records.append(
            {
                "case_id": case_id,
                "component_count": len(parsed_components),
                "internal_path": to_project_relative_path(internal_path, config),
                "syft_status": external_statuses["syft"]["tool_status"],
                "syft_path": external_statuses["syft"]["path"],
                "cyclonedx_status": external_statuses["cyclonedx"]["tool_status"],
                "cyclonedx_path": external_statuses["cyclonedx"]["path"],
                "spdx_status": external_statuses["spdx"]["tool_status"],
                "spdx_path": external_statuses["spdx"]["path"],
            }
        )

    metadata_path = dirs["base"] / "sbom_generation_metadata.csv"
    tool_summary_path = dirs["base"] / "sbom_tool_summary.csv"
    _write_metadata_csv(metadata_path, metadata_rows)
    tool_summary_rows = _write_tool_summary(tool_summary_path, metadata_rows, len(records))
    index = {
        "run_id": context.run_id if context else None,
        "case_count": len(records),
        "metadata_csv": to_project_relative_path(metadata_path, config),
        "sbom_tool_summary_csv": to_project_relative_path(tool_summary_path, config),
        "sboms": records,
        "tool_summary": tool_summary_rows,
        "missing_external_sbom_warning": any(row.get("external_sbom_count") == 0 for row in metadata_rows),
        "claim_scope": (
            "Internal fallback SBOMs are generated from local manifests. "
            "Syft, CycloneDX, and SPDX files are written only when real external tool output is available."
        ),
    }
    write_json(dirs["base"] / "index.json", index)
    return index
