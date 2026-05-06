"""Evidence-readiness and publication-readiness audit helpers."""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from supplytrace.config import project_path_from_artifact_reference, to_project_relative_path
from supplytrace.run_context import RunContext, capture_tool_version, safe_subprocess_run, write_json


SUMMARY_FIELDS: tuple[str, ...] = ("check", "value", "status", "notes")
DEBUG_FIELDS: tuple[str, ...] = ("metric", "value", "status", "notes")
CHECKLIST_FIELDS: tuple[str, ...] = ("check_id", "check", "status", "evidence", "notes")
INVENTORY_FIELDS: tuple[str, ...] = ("path", "size_bytes", "category", "sha256_available", "notes")
TOOL_FIELDS: tuple[str, ...] = ("tool", "available", "version", "source", "notes")
PUBLICATION_SCORE_FIELDS: tuple[str, ...] = ("metric", "value", "status", "notes")

REMOTE_MARKER_RE = re.compile(r"https?://|ssh://|git://", re.IGNORECASE)


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default
    return payload if isinstance(payload, dict) else default


def _command_check(command: list[str], cwd: Path, timeout_seconds: int = 300) -> dict[str, Any]:
    try:
        result = safe_subprocess_run(command, cwd=cwd, timeout_seconds=timeout_seconds, allowed_return_codes=(0,))
        return {
            "status": "pass",
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
            "duration_seconds": result.duration_seconds,
        }
    except Exception as exc:
        return {"status": "fail", "returncode": None, "stdout": "", "stderr": str(exc), "duration_seconds": 0.0}


def _scanner_metadata(context: RunContext) -> list[dict[str, str]]:
    return _read_csv(context.config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.csv")


def _scanner_output_files(context: RunContext) -> list[Path]:
    base = context.config.artifacts_dir / "scanner_raw"
    paths: list[Path] = []
    for name in ("osv", "trivy", "grype", "npm_audit", "pip_audit"):
        scanner_dir = base / name
        if scanner_dir.exists():
            paths.extend(sorted(scanner_dir.glob("case_*.json")))
    return paths


def _unreferenced_scanner_outputs(context: RunContext, metadata: list[dict[str, str]]) -> list[Path]:
    referenced: set[Path] = set()
    raw_dir = context.config.artifacts_dir / "scanner_raw"
    for row in metadata:
        if row.get("status") != "success" or not row.get("output_path"):
            continue
        path = project_path_from_artifact_reference(context.config, row.get("output_path"))
        candidates = [path] if path is not None else []
        scanner_name = (row.get("scanner_name") or "").replace("-", "_")
        case_id = row.get("case_id") or ""
        if scanner_name and case_id:
            candidates.append(raw_dir / scanner_name / f"{case_id}.json")
        for candidate in candidates:
            if candidate and candidate.exists():
                referenced.add(candidate.resolve())
    return [path for path in _scanner_output_files(context) if path.resolve() not in referenced]


def _remote_scanner_command_rows(metadata: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in metadata:
        command = row.get("command") or ""
        if REMOTE_MARKER_RE.search(command):
            rows.append(row)
    return rows


def _tool_rows(context: RunContext) -> list[dict[str, Any]]:
    tools = [
        ("python", ("--version",)),
        ("node", ("--version",)),
        ("npm", ("--version",)),
        ("pip-audit", ("--version",)),
        ("osv-scanner", ("--version",)),
        ("trivy", ("--version",)),
        ("grype", ("version",)),
        ("syft", ("version",)),
        ("cyclonedx-py", ("--version",)),
        ("pytest", ("--version",)),
        ("docker", ("--version",)),
    ]
    rows = []
    for tool, args in tools:
        if tool == "pytest":
            result = _command_check([sys.executable, "-m", "pytest", "--version"], context.config.project_root, timeout_seconds=60)
            rows.append(
                {
                    "tool": tool,
                    "available": result["status"] == "pass",
                    "version": result["stdout"].strip().splitlines()[0] if result["stdout"].strip() else None,
                    "source": f"python -m pytest:{context.run_id}",
                    "notes": "" if result["status"] == "pass" else result["stderr"],
                }
            )
            continue
        if tool in {"pip-audit", "cyclonedx-py"}:
            result = capture_tool_version(tool, args)
            if not result.get("available"):
                module_name = "pip_audit" if tool == "pip-audit" else "cyclonedx_py"
                module_result = _command_check(
                    [sys.executable, "-m", module_name, *args],
                    context.config.project_root,
                    timeout_seconds=60,
                )
                rows.append(
                    {
                        "tool": tool,
                        "available": module_result["status"] == "pass",
                        "version": module_result["stdout"].strip().splitlines()[0]
                        if module_result["stdout"].strip()
                        else None,
                        "source": f"python -m {module_name}:{context.run_id}",
                        "notes": "" if module_result["status"] == "pass" else module_result["stderr"],
                    }
                )
                continue
            rows.append(
                {
                    "tool": tool,
                    "available": result.get("available"),
                    "version": result.get("version"),
                    "source": f"capture_tool_version:{context.run_id}",
                    "notes": result.get("error") or "",
                }
            )
            continue
        result = capture_tool_version(tool, args)
        rows.append(
            {
                "tool": tool,
                "available": result.get("available"),
                "version": result.get("version"),
                "source": f"capture_tool_version:{context.run_id}",
                "notes": result.get("error") or "",
            }
        )
    return rows


def _count_rows(path: Path) -> int:
    return len(_read_csv(path))


def _package_version_missing_count(context: RunContext) -> int:
    rows = _read_csv(context.config.artifacts_dir / "normalized" / "findings_normalized.csv")
    return sum(1 for row in rows if row.get("package_version") in (None, "", "unknown"))


def _absolute_path_count(context: RunContext) -> int:
    pattern = re.compile(r"(?:[A-Za-z]:\\|/home/|/Users/)")
    paths = [
        context.config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.csv",
        context.config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.json",
        context.config.artifacts_dir / "normalized" / "findings_normalized.csv",
        context.config.artifacts_dir / "normalized" / "findings_normalized.json",
        context.config.artifacts_dir / "normalized" / "normalization_summary.json",
        context.config.artifacts_dir / "sbom" / "sbom_generation_metadata.csv",
        context.config.artifacts_dir / "sbom" / "index.json",
        context.config.artifacts_dir / "vex" / "vex_summary.csv",
        context.config.artifacts_dir / "reports" / "report.md",
        context.config.artifacts_dir / "reports" / "report.html",
    ]
    total = 0
    for path in paths:
        if path.exists():
            total += len(pattern.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return total


def _real_metric_rows(context: RunContext) -> list[dict[str, str]]:
    metrics = _read_csv(context.config.artifacts_dir / "evaluation" / "metrics_summary.csv")
    result_metrics = {
        "precision",
        "recall",
        "f1",
        "false_positive_reduction",
        "actionable_findings_retained",
        "top5_actionability",
        "top10_actionability",
        "ndcg",
        "map",
    }
    return [
        row
        for row in metrics
        if row.get("metric") in result_metrics
        and row.get("status") == "ok"
        and row.get("value") not in ("", "not_available", None)
    ]


def _parser_coverage(context: RunContext) -> list[dict[str, str]]:
    return _read_csv(context.config.artifacts_dir / "normalized" / "parser_coverage_summary.csv")


def _zero_finding_reason(
    *,
    metadata: list[dict[str, str]],
    scanner_output_files: list[Path],
    coverage_rows: list[dict[str, str]],
    findings_count: int,
) -> str:
    if findings_count > 0:
        return "normalized findings are present"
    if not metadata:
        return "scanner execution metadata is missing; run-scans has not produced auditable evidence"
    status_counts = Counter(row.get("status") or "unknown" for row in metadata)
    if status_counts.get("success", 0) == 0:
        return f"no scanner executions succeeded; status counts are {dict(status_counts)}"
    if not scanner_output_files:
        return "scanner success metadata exists but no raw scanner JSON files were found"
    parsed_files = sum(int(row.get("raw_files_parsed") or 0) for row in coverage_rows)
    raw_records = sum(int(row.get("raw_finding_records") or 0) for row in coverage_rows)
    if parsed_files == 0:
        return "raw scanner JSON files exist, but normalization did not parse any of them"
    if raw_records == 0:
        successful = Counter(row.get("scanner_name") or "unknown" for row in metadata if row.get("status") == "success")
        return (
            "successful scanner outputs were parsed, but they contained zero vulnerability records; "
            f"successful scanner counts were {dict(successful)}"
        )
    return "normalization parsed raw finding records, but deduplication or schema validation produced zero normalized rows"


def _external_sbom_count(context: RunContext) -> int:
    rows = _read_csv(context.config.artifacts_dir / "sbom" / "sbom_generation_metadata.csv")
    count = 0
    for row in rows:
        for field in ("syft_tool_status", "cyclonedx_tool_status", "spdx_tool_status"):
            if row.get(field) == "generated":
                count += 1
    return count


def _reports_generated(context: RunContext) -> bool:
    return (
        (context.config.artifacts_dir / "reports" / "report.md").exists()
        and (context.config.artifacts_dir / "reports" / "report.html").exists()
        and (context.config.project_root / "docs" / "manuscript_support.md").exists()
    )


def _git_status(context: RunContext) -> dict[str, Any]:
    if not (context.config.project_root / ".git").exists():
        return {"status": "not_a_git_repository", "clean": False, "details": "no .git directory present"}
    result = _command_check(["git", "status", "--short"], context.config.project_root, timeout_seconds=60)
    clean = result["status"] == "pass" and not result["stdout"].strip()
    return {"status": "clean" if clean else "dirty_or_unavailable", "clean": clean, "details": result["stdout"] or result["stderr"]}


def _docker_status() -> dict[str, Any]:
    docker = capture_tool_version("docker", ("--version",))
    if not docker.get("available"):
        return {"status": "unavailable", "verified": False, "details": docker.get("error") or "docker not found"}
    compose = _command_check(["docker", "compose", "version"], Path.cwd(), timeout_seconds=60)
    return {
        "status": "available" if compose["status"] == "pass" else "docker_without_compose",
        "verified": compose["status"] == "pass",
        "details": docker.get("version") or compose.get("stderr"),
    }


def run_evidence_check(context: RunContext, *, run_tests: bool = True) -> dict[str, Any]:
    """Write evidence-readiness artifacts and return a summary payload."""

    audit_dir = context.config.artifacts_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    test_result = _command_check([sys.executable, "-m", "pytest", "-q"], context.config.project_root, timeout_seconds=600) if run_tests else {
        "status": "not_run",
        "stdout": "",
        "stderr": "tests were not run by this evidence-check invocation",
        "duration_seconds": 0.0,
    }
    metadata = _scanner_metadata(context)
    scanner_status_counts = Counter(row.get("status") or "unknown" for row in metadata)
    scanner_output_files = _scanner_output_files(context)
    findings_count = _count_rows(context.config.artifacts_dir / "normalized" / "findings_normalized.csv")
    package_version_missing = _package_version_missing_count(context)
    risk_score_count = _count_rows(context.config.artifacts_dir / "evaluation" / "risk_scores.csv")
    vex_summary_count = _count_rows(context.config.artifacts_dir / "vex" / "vex_summary.csv")
    real_metrics = _real_metric_rows(context)
    external_sboms = _external_sbom_count(context)
    tool_rows = _tool_rows(context)
    scanner_tools = {"npm", "pip-audit", "osv-scanner", "trivy", "grype"}
    installed_scanners = [row for row in tool_rows if row["tool"] in scanner_tools and row["available"] is True]
    docker_status = _docker_status()
    git_status = _git_status(context)
    reports_generated = _reports_generated(context)
    remote_rows = _remote_scanner_command_rows(metadata)
    unreferenced_outputs = _unreferenced_scanner_outputs(context, metadata)

    blocking: list[str] = []
    warnings: list[str] = []
    if test_result["status"] != "pass":
        blocking.append("pytest did not pass during evidence-readiness check")
    if findings_count == 0:
        blocking.append("no scanner-confirmed findings were normalized")
    if risk_score_count == 0:
        blocking.append("no risk score rows exist because no findings were available")
    if vex_summary_count == 0:
        blocking.append("no vulnerability-level VEX-style records exist")
    if not real_metrics:
        blocking.append("evaluation metrics do not contain real comparison values")
    if remote_rows:
        blocking.append("scanner metadata contains remote-looking command arguments")
    if unreferenced_outputs:
        blocking.append("scanner output JSON files exist without successful metadata references")
    if not reports_generated:
        blocking.append("Markdown, HTML, or manuscript-support report artifacts are missing")
    if len(installed_scanners) < 2:
        warnings.append("fewer than two external scanner tools are installed or detectable")
    if external_sboms == 0:
        warnings.append("no external Syft/CycloneDX/SPDX SBOMs were generated")
    if not docker_status["verified"]:
        warnings.append(f"Docker is not verified in this environment: {docker_status['status']}")
    if not git_status["clean"]:
        warnings.append(f"GitHub cleanliness is not verified: {git_status['status']}")

    score = 0.0
    score += 1.0 if test_result["status"] == "pass" else 0.0
    score += 1.0 if len(installed_scanners) >= 2 else 0.5 if installed_scanners else 0.0
    score += 1.0 if scanner_status_counts.get("success", 0) > 0 else 0.0
    score += 1.0 if len(scanner_output_files) > 0 else 0.0
    score += 1.5 if findings_count > 0 else 0.0
    score += 1.0 if risk_score_count > 0 else 0.0
    score += 1.0 if vex_summary_count > 0 else 0.0
    score += 1.0 if real_metrics else 0.0
    score += 0.75 if reports_generated else 0.0
    score += 0.75 if not remote_rows and not unreferenced_outputs else 0.0
    score += 0.5 if external_sboms > 0 else 0.0
    score += 0.5 if docker_status["verified"] else 0.0
    score += 0.5 if git_status["clean"] else 0.0
    score = min(score, 10.0)
    if findings_count == 0:
        score = min(score, 5.0)
    if remote_rows or unreferenced_outputs:
        score = min(score, 4.0)

    ready = (
        test_result["status"] == "pass"
        and findings_count > 0
        and risk_score_count > 0
        and vex_summary_count > 0
        and bool(real_metrics)
        and reports_generated
        and not remote_rows
        and not unreferenced_outputs
        and git_status["clean"]
    )
    if len(installed_scanners) < 2 and not (len(installed_scanners) >= 1 and external_sboms > 0):
        ready = False

    supported_claims = [
        "local testbed generation is reproducible",
        "missing scanner tools are reported in generated metadata",
        "reports distinguish unavailable evidence from generated evidence",
    ]
    unsupported_claims = []
    if findings_count == 0:
        unsupported_claims.append("prioritization improvement over scanner findings")
        unsupported_claims.append("scanner-confirmed vulnerability status for generated cases")
    if not docker_status["verified"]:
        unsupported_claims.append("Docker execution success in this host environment")
    if not real_metrics:
        unsupported_claims.append("comparative evaluation improvement")

    payload = {
        "run_id": context.run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ready_for_paper_results": "yes" if ready else "no",
        "readiness_score_out_of_10": round(score, 2),
        "blocking_issues": blocking,
        "warnings": warnings,
        "required_next_actions": blocking + warnings,
        "supported_claims": supported_claims,
        "unsupported_claims": unsupported_claims,
        "scanner_status": {
            "installed_scanner_count": len(installed_scanners),
            "scanner_success_count": scanner_status_counts.get("success", 0),
            "scanner_output_file_count": len(scanner_output_files),
            "status_counts": dict(scanner_status_counts),
        },
        "metric_status": {
            "normalized_finding_count": findings_count,
            "package_version_missing_count": package_version_missing,
            "risk_score_count": risk_score_count,
            "vex_summary_count": vex_summary_count,
            "real_metric_count": len(real_metrics),
        },
        "artifact_status": {
            "reports_generated": reports_generated,
            "external_sbom_count": external_sboms,
            "unreferenced_scanner_output_count": len(unreferenced_outputs),
            "remote_scanner_command_count": len(remote_rows),
            "docker_status": docker_status,
            "git_status": git_status,
            "pytest_status": test_result["status"],
        },
        "tool_rows": tool_rows,
    }

    summary_rows = [
        {"check": "ready_for_paper_results", "value": payload["ready_for_paper_results"], "status": "pass" if ready else "fail", "notes": "requires real scanner-backed findings and metrics"},
        {"check": "readiness_score_out_of_10", "value": payload["readiness_score_out_of_10"], "status": "info", "notes": "score is capped at 5 when normalized findings are zero"},
        {"check": "installed_scanner_count", "value": len(installed_scanners), "status": "pass" if len(installed_scanners) >= 2 else "warning", "notes": "npm, pip-audit, OSV, Trivy, and Grype are counted"},
        {"check": "scanner_success_count", "value": scanner_status_counts.get("success", 0), "status": "pass" if scanner_status_counts.get("success", 0) else "warning", "notes": "successful local scanner executions"},
        {"check": "scanner_output_file_count", "value": len(scanner_output_files), "status": "pass" if scanner_output_files else "warning", "notes": "raw JSON files under scanner adapter directories"},
        {"check": "normalized_finding_count", "value": findings_count, "status": "pass" if findings_count else "fail", "notes": "must be positive for paper-result claims"},
        {"check": "package_version_missing_count", "value": package_version_missing, "status": "pass" if package_version_missing == 0 else "warning", "notes": "missing versions are reported, not invented"},
        {"check": "risk_score_count", "value": risk_score_count, "status": "pass" if risk_score_count else "fail", "notes": "must be positive for scoring claims"},
        {"check": "vex_summary_count", "value": vex_summary_count, "status": "pass" if vex_summary_count else "fail", "notes": "must be positive for vulnerability-level VEX-style claims"},
        {"check": "real_metric_count", "value": len(real_metrics), "status": "pass" if real_metrics else "fail", "notes": "metrics must be generated from real findings"},
        {"check": "external_sbom_count", "value": external_sboms, "status": "pass" if external_sboms else "warning", "notes": "internal fallback SBOMs do not count as external standard SBOM output"},
        {"check": "reports_generated", "value": reports_generated, "status": "pass" if reports_generated else "fail", "notes": "Markdown, HTML, and manuscript support"},
        {"check": "git_cleanliness", "value": git_status["status"], "status": "pass" if git_status["clean"] else "warning", "notes": git_status["details"]},
        {"check": "docker_status", "value": docker_status["status"], "status": "pass" if docker_status["verified"] else "warning", "notes": docker_status["details"]},
        {"check": "no_remote_scanner_targets", "value": len(remote_rows), "status": "pass" if not remote_rows else "fail", "notes": "scanner metadata command fields checked"},
        {"check": "no_unreferenced_scanner_outputs", "value": len(unreferenced_outputs), "status": "pass" if not unreferenced_outputs else "fail", "notes": "raw case JSON files must be referenced by success metadata"},
    ]

    summary_csv = audit_dir / "evidence_readiness_summary.csv"
    summary_json = audit_dir / "evidence_readiness_summary.json"
    report_md = audit_dir / "evidence_readiness_report.md"
    _write_csv(summary_csv, summary_rows, SUMMARY_FIELDS)
    write_json(summary_json, payload)
    report_md.write_text(_evidence_report_markdown(payload, summary_rows), encoding="utf-8")
    return {
        **payload,
        "summary_csv": to_project_relative_path(summary_csv, context.config),
        "summary_json": to_project_relative_path(summary_json, context.config),
        "report_md": to_project_relative_path(report_md, context.config),
    }


def run_debug_evidence(context: RunContext) -> dict[str, Any]:
    """Write a focused diagnosis for empty or incomplete evidence artifacts."""

    audit_dir = context.config.artifacts_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    metadata = _scanner_metadata(context)
    scanner_status_counts = Counter(row.get("status") or "unknown" for row in metadata)
    scanner_output_files = _scanner_output_files(context)
    raw_by_scanner = Counter(path.parent.name for path in scanner_output_files)
    coverage_rows = _parser_coverage(context)
    parsed_by_scanner = {
        row.get("scanner_name") or "unknown": int(row.get("raw_finding_records") or 0)
        for row in coverage_rows
    }
    normalized_count = _count_rows(context.config.artifacts_dir / "normalized" / "findings_normalized.csv")
    package_version_missing = _package_version_missing_count(context)
    risk_score_count = _count_rows(context.config.artifacts_dir / "evaluation" / "risk_scores.csv")
    vex_record_count = _count_rows(context.config.artifacts_dir / "vex" / "vex_summary.csv")
    real_metric_count = len(_real_metric_rows(context))
    external_sbom_count = _external_sbom_count(context)
    absolute_path_count = _absolute_path_count(context)
    tool_rows = _tool_rows(context)
    scanner_tools = {"npm", "pip-audit", "osv-scanner", "trivy", "grype"}
    installed_count = sum(1 for row in tool_rows if row["tool"] in scanner_tools and row["available"] is True)
    zero_reason = _zero_finding_reason(
        metadata=metadata,
        scanner_output_files=scanner_output_files,
        coverage_rows=coverage_rows,
        findings_count=normalized_count,
    )

    rows: list[dict[str, Any]] = [
        {
            "metric": "scanner_installed_count",
            "value": installed_count,
            "status": "ok" if installed_count else "warning",
            "notes": "npm, pip-audit, OSV-Scanner, Trivy, and Grype are counted",
        },
        {
            "metric": "scanner_success_count",
            "value": scanner_status_counts.get("success", 0),
            "status": "ok" if scanner_status_counts.get("success", 0) else "warning",
            "notes": f"status_counts={dict(scanner_status_counts)}",
        },
        {
            "metric": "raw_scanner_output_count",
            "value": len(scanner_output_files),
            "status": "ok" if scanner_output_files else "warning",
            "notes": "case_*.json files under artifacts/scanner_raw scanner directories",
        },
        {
            "metric": "normalized_findings_count",
            "value": normalized_count,
            "status": "ok" if normalized_count else "fail",
            "notes": zero_reason if normalized_count == 0 else "normalized scanner-confirmed findings exist",
        },
        {
            "metric": "package_version_missing_count",
            "value": package_version_missing,
            "status": "ok" if package_version_missing == 0 else "warning",
            "notes": "missing package versions remain null/unknown and are not invented",
        },
        {
            "metric": "risk_score_count",
            "value": risk_score_count,
            "status": "ok" if risk_score_count else "warning",
            "notes": "risk score rows are only produced for normalized findings",
        },
        {
            "metric": "vex_record_count",
            "value": vex_record_count,
            "status": "ok" if vex_record_count else "warning",
            "notes": "VEX-style vulnerability rows are only produced for real findings",
        },
        {
            "metric": "real_metric_count",
            "value": real_metric_count,
            "status": "ok" if real_metric_count else "warning",
            "notes": "result metrics with concrete generated values",
        },
        {
            "metric": "external_sbom_count",
            "value": external_sbom_count,
            "status": "ok" if external_sbom_count else "warning",
            "notes": "Syft/CycloneDX/SPDX outputs generated by real external tools",
        },
        {
            "metric": "absolute_path_count",
            "value": absolute_path_count,
            "status": "ok" if absolute_path_count == 0 else "warning",
            "notes": "absolute paths found in controlled generated artifacts",
        },
        {
            "metric": "zero_finding_reason",
            "value": zero_reason,
            "status": "info",
            "notes": "root-cause diagnosis for the current artifact state",
        },
    ]
    for scanner_name in sorted(set(raw_by_scanner) | set(parsed_by_scanner)):
        rows.append(
            {
                "metric": f"raw_output_count_{scanner_name}",
                "value": raw_by_scanner.get(scanner_name, 0),
                "status": "ok" if raw_by_scanner.get(scanner_name, 0) else "info",
                "notes": "raw scanner JSON files found",
            }
        )
        rows.append(
            {
                "metric": f"parsed_finding_count_{scanner_name}",
                "value": parsed_by_scanner.get(scanner_name, 0),
                "status": "ok" if parsed_by_scanner.get(scanner_name, 0) else "info",
                "notes": "finding records emitted by the normalization parser before deduplication",
            }
        )

    summary_csv = audit_dir / "debug_evidence_summary.csv"
    report_md = audit_dir / "debug_evidence_report.md"
    _write_csv(summary_csv, rows, DEBUG_FIELDS)
    report_md.write_text(_debug_evidence_markdown(context.run_id, rows), encoding="utf-8")

    payload = {
        "run_id": context.run_id,
        "scanner_installed_count": installed_count,
        "scanner_success_count": scanner_status_counts.get("success", 0),
        "raw_scanner_output_count": len(scanner_output_files),
        "per_scanner_raw_output_count": dict(sorted(raw_by_scanner.items())),
        "per_scanner_parsed_finding_count": dict(sorted(parsed_by_scanner.items())),
        "normalized_findings_count": normalized_count,
        "package_version_missing_count": package_version_missing,
        "risk_score_count": risk_score_count,
        "vex_record_count": vex_record_count,
        "real_metric_count": real_metric_count,
        "external_sbom_count": external_sbom_count,
        "absolute_path_count": absolute_path_count,
        "zero_finding_reason": zero_reason,
        "summary_csv": to_project_relative_path(summary_csv, context.config),
        "report_md": to_project_relative_path(report_md, context.config),
    }
    return payload


def _debug_evidence_markdown(run_id: str, rows: list[dict[str, Any]]) -> str:
    table = "\n".join(f"| {row['metric']} | {row['value']} | {row['status']} | {row['notes']} |" for row in rows)
    return f"""# Debug Evidence Report

Run ID: `{run_id}`

This diagnostic report describes generated local evidence only. It does not create scanner findings, risk scores, VEX records, or metrics.

| Metric | Value | Status | Notes |
| --- | --- | --- | --- |
{table}
"""


def _evidence_report_markdown(payload: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    blocking = "\n".join(f"- {item}" for item in payload["blocking_issues"]) or "- None"
    warnings = "\n".join(f"- {item}" for item in payload["warnings"]) or "- None"
    supported = "\n".join(f"- {item}" for item in payload["supported_claims"]) or "- None"
    unsupported = "\n".join(f"- {item}" for item in payload["unsupported_claims"]) or "- None"
    scanner = payload["scanner_status"]
    metrics = payload["metric_status"]
    artifact = payload["artifact_status"]
    table = "\n".join(f"| {row['check']} | {row['value']} | {row['status']} | {row['notes']} |" for row in rows)
    return f"""# Evidence Readiness Report

Run ID: `{payload['run_id']}`

Generated at: {payload['generated_at']}

- ready_for_paper_results: {payload['ready_for_paper_results']}
- readiness_score_out_of_10: {payload['readiness_score_out_of_10']}

## Blocking Issues

{blocking}

## Warnings

{warnings}

## Scanner Status

- Installed scanner tools: {scanner['installed_scanner_count']}
- Successful scanner executions: {scanner['scanner_success_count']}
- Raw scanner output files: {scanner['scanner_output_file_count']}
- Status counts: `{json.dumps(scanner['status_counts'], sort_keys=True)}`

## Metric Status

- Normalized findings: {metrics['normalized_finding_count']}
- Package version missing rows: {metrics.get('package_version_missing_count', 'not_available')}
- Risk scores: {metrics['risk_score_count']}
- VEX summary rows: {metrics['vex_summary_count']}
- Real comparison metric rows: {metrics['real_metric_count']}

## Artifact Status

- Reports generated: {artifact['reports_generated']}
- External SBOM count: {artifact['external_sbom_count']}
- Docker status: {artifact['docker_status']['status']}
- Git status: {artifact['git_status']['status']}
- Pytest status: {artifact['pytest_status']}

## Supported Claims

{supported}

## Unsupported Claims

{unsupported}

## Check Details

| Check | Value | Status | Notes |
| --- | --- | --- | --- |
{table}

If normalized findings are zero, this report intentionally caps readiness at 5/10 and marks paper-result claims unsupported.
"""


def _artifact_inventory(context: RunContext) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = context.config.project_root
    for base in (context.config.artifacts_dir, context.config.project_root / "docs"):
        if not base.exists():
            continue
        for path in sorted(item for item in base.rglob("*") if item.is_file()):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.as_posix()
            rows.append(
                {
                    "path": rel,
                    "size_bytes": path.stat().st_size,
                    "category": rel.split("/", 1)[0],
                    "sha256_available": "not_computed",
                    "notes": "inventory only; content hashes can be added by release packaging",
                }
            )
    return rows


def _unsupported_claim_hits(context: RunContext) -> list[str]:
    hits: list[str] = []
    report_files = [
        context.config.artifacts_dir / "reports" / "report.md",
        context.config.artifacts_dir / "reports" / "report.html",
    ]
    for base in (context.config.project_root / "README.md", context.config.project_root / "docs", *report_files):
        paths = [base] if base.is_file() else sorted(base.rglob("*")) if base.exists() else []
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in {".md", ".html", ".txt"}:
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                lowered = line.lower()
                if "10/10 ready" in lowered:
                    hits.append(f"{path}:{line_number}: 10/10 ready")
                if "proves exploitability" in lowered:
                    hits.append(f"{path}:{line_number}: proves exploitability")
                if (
                    "official vendor vex" in lowered
                    and "not official vendor vex" not in lowered
                    and "not an official vendor vex" not in lowered
                    and "not represented as official vendor vex" not in lowered
                ):
                    hits.append(f"{path}:{line_number}: official vendor VEX")
                if "expert validation" in lowered and "do not claim" not in lowered and "unless" not in lowered and "without" not in lowered:
                    hits.append(f"{path}:{line_number}: expert validation")
    return hits


def run_publication_audit(context: RunContext, *, run_tests: bool = True) -> dict[str, Any]:
    """Write the final publication-readiness audit artifacts."""

    audit_dir = context.config.artifacts_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    evidence = run_evidence_check(context, run_tests=run_tests)
    tool_rows = evidence["tool_rows"]
    metadata = _scanner_metadata(context)
    remote_rows = _remote_scanner_command_rows(metadata)
    unreferenced = _unreferenced_scanner_outputs(context, metadata)
    claim_hits = _unsupported_claim_hits(context)
    inventory_rows = _artifact_inventory(context)
    docs_required = [
        "methodology.md",
        "validation_protocol.md",
        "ethics.md",
        "limitations.md",
        "reproducibility.md",
        "manuscript_support.md",
        "scanner_installation.md",
        "github_release_checklist.md",
    ]
    docs_missing = [name for name in docs_required if not (context.config.project_root / "docs" / name).exists()]

    score = float(evidence["readiness_score_out_of_10"])
    if evidence["ready_for_paper_results"] != "yes":
        score = min(score, 5.0)
    if claim_hits or remote_rows or unreferenced:
        score = min(score, 4.0)
    recommendation = (
        "ready_for_paper_results"
        if evidence["ready_for_paper_results"] == "yes" and not claim_hits and not docs_missing
        else "not_ready_for_paper_results"
    )

    checklist_rows = [
        {"check_id": "A01", "check": "pytest", "status": evidence["artifact_status"]["pytest_status"], "evidence": "python -m pytest -q", "notes": "executed by audit unless disabled"},
        {"check_id": "A02", "check": "required artifact folders", "status": "pass" if context.config.artifacts_dir.exists() else "fail", "evidence": to_project_relative_path(context.config.artifacts_dir, context.config), "notes": ""},
        {"check_id": "A03", "check": "scanner metadata", "status": "pass" if metadata else "fail", "evidence": f"rows={len(metadata)}", "notes": ""},
        {"check_id": "A04", "check": "no third-party scanner targets", "status": "pass" if not remote_rows else "fail", "evidence": f"remote rows={len(remote_rows)}", "notes": "scanner command metadata searched for URL/SSH/git markers"},
        {"check_id": "A05", "check": "no fake scanner outputs", "status": "pass" if not unreferenced else "fail", "evidence": f"unreferenced scanner JSON={len(unreferenced)}", "notes": "only adapter case JSON files are checked"},
        {"check_id": "A06", "check": "documentation complete", "status": "pass" if not docs_missing else "fail", "evidence": ";".join(docs_missing) or "all required docs exist", "notes": ""},
        {"check_id": "A07", "check": "unsupported claim scan", "status": "pass" if not claim_hits else "fail", "evidence": f"hits={len(claim_hits)}", "notes": "; ".join(claim_hits[:3])},
        {"check_id": "A08", "check": "evidence readiness", "status": "pass" if evidence["ready_for_paper_results"] == "yes" else "fail", "evidence": evidence["ready_for_paper_results"], "notes": f"score={evidence['readiness_score_out_of_10']}"},
    ]

    _write_csv(audit_dir / "reproducibility_checklist.csv", checklist_rows, CHECKLIST_FIELDS)
    _write_csv(audit_dir / "tool_availability_summary.csv", tool_rows, TOOL_FIELDS)
    _write_csv(audit_dir / "artifact_inventory.csv", inventory_rows, INVENTORY_FIELDS)
    _write_csv(
        audit_dir / "publication_readiness_score.csv",
        [
            {"metric": "publication_readiness_score_out_of_10", "value": round(score, 2), "status": recommendation, "notes": "cannot exceed evidence-readiness score"},
            {"metric": "ready_for_paper_results", "value": evidence["ready_for_paper_results"], "status": recommendation, "notes": "requires real normalized findings and metrics"},
            {"metric": "blocking_issue_count", "value": len(evidence["blocking_issues"]), "status": "info", "notes": ""},
            {"metric": "warning_count", "value": len(evidence["warnings"]), "status": "info", "notes": ""},
        ],
        PUBLICATION_SCORE_FIELDS,
    )

    limitations = "\n".join(f"- {item}" for item in [*evidence["blocking_issues"], *evidence["warnings"]]) or "- No limitations recorded by the audit."
    (audit_dir / "known_limitations.md").write_text(f"# Known Limitations\n\n{limitations}\n", encoding="utf-8")
    final_report = _final_audit_markdown(
        context=context,
        evidence=evidence,
        publication_score=round(score, 2),
        recommendation=recommendation,
        checklist_rows=checklist_rows,
        docs_missing=docs_missing,
        claim_hits=claim_hits,
    )
    (audit_dir / "final_audit_report.md").write_text(final_report, encoding="utf-8")

    return {
        "run_id": context.run_id,
        "publication_readiness_score_out_of_10": round(score, 2),
        "recommendation": recommendation,
        "evidence": evidence,
        "final_audit_report": to_project_relative_path(audit_dir / "final_audit_report.md", context.config),
        "publication_readiness_score_csv": to_project_relative_path(audit_dir / "publication_readiness_score.csv", context.config),
        "tool_availability_summary_csv": to_project_relative_path(audit_dir / "tool_availability_summary.csv", context.config),
        "artifact_inventory_csv": to_project_relative_path(audit_dir / "artifact_inventory.csv", context.config),
    }


def _final_audit_markdown(
    *,
    context: RunContext,
    evidence: dict[str, Any],
    publication_score: float,
    recommendation: str,
    checklist_rows: list[dict[str, Any]],
    docs_missing: list[str],
    claim_hits: list[str],
) -> str:
    checklist = "\n".join(f"| {row['check_id']} | {row['check']} | {row['status']} | {row['evidence']} | {row['notes']} |" for row in checklist_rows)
    blocking = "\n".join(f"- {item}" for item in evidence["blocking_issues"]) or "- None"
    warnings = "\n".join(f"- {item}" for item in evidence["warnings"]) or "- None"
    tools = "\n".join(f"| {row['tool']} | {row['available']} | {row.get('version') or ''} | {row.get('notes') or ''} |" for row in evidence["tool_rows"])
    docs = "; ".join(docs_missing) if docs_missing else "all required documentation files are present"
    claims = "\n".join(f"- {item}" for item in claim_hits) or "- No unsupported-claim pattern hits."
    return f"""# Final Publication-Readiness Audit

Run ID: `{context.run_id}`

Generated at: {datetime.now(timezone.utc).isoformat()}

- publication_readiness_score_out_of_10: {publication_score}
- final_recommendation: {recommendation}
- evidence_readiness_score_out_of_10: {evidence['readiness_score_out_of_10']}
- ready_for_paper_results: {evidence['ready_for_paper_results']}

## Exact Commands Checked By Audit

- `python -m pytest -q`
- `git status --short` when a `.git` directory is present
- local tool version commands for Python, Node.js, npm, pip-audit, OSV-Scanner, Trivy, Grype, Syft, CycloneDX, pytest, and Docker

The full pipeline commands are expected to be run before audit; this command verifies the artifacts they produce.

## Pass/Fail Checks

| ID | Check | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
{checklist}

## Evidence Summary

- Normalized findings: {evidence['metric_status']['normalized_finding_count']}
- Risk scores: {evidence['metric_status']['risk_score_count']}
- VEX summary rows: {evidence['metric_status']['vex_summary_count']}
- Real comparison metric rows: {evidence['metric_status']['real_metric_count']}
- Scanner success count: {evidence['scanner_status']['scanner_success_count']}
- External SBOM count: {evidence['artifact_status']['external_sbom_count']}

## Blocking Issues

{blocking}

## Non-Blocking Warnings

{warnings}

## Tool Availability

| Tool | Available | Version | Notes |
| --- | --- | --- | --- |
{tools}

## Documentation Status

{docs}

## Unsupported Claim Scan

{claims}

## Final Recommendation

{recommendation}. Do not make paper-result claims unless `ready_for_paper_results` is `yes` and the generated metrics support the specific claim.
"""
