from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.run_context import create_run_context
from supplytrace.scoring.risk_score import score_findings


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def _write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _write_scoring_inputs(config: ProjectConfig, findings: list[dict[str, object]], context_rows: list[dict[str, object]]) -> None:
    normalized = config.artifacts_dir / "normalized" / "findings_normalized.json"
    normalized.parent.mkdir(parents=True, exist_ok=True)
    normalized.write_text(json.dumps({"findings": findings}), encoding="utf-8")

    reachability_fields = [
        "case_id",
        "package_name",
        "reachability_status",
        "dependency_scope",
        "direct_or_transitive",
    ]
    context_fields = [
        "case_id",
        "package_name",
        "runtime_dependency",
        "dev_dependency",
        "direct_dependency",
        "transitive_dependency",
        "package_reachable",
        "containerized",
        "exposed_service",
        "fixed_version_available",
        "evidence_reason",
    ]
    reachability_rows = [
        {
            "case_id": row["case_id"],
            "package_name": row["package_name"],
            "reachability_status": row.get("reachability_status", ""),
            "dependency_scope": row.get("dependency_scope", ""),
            "direct_or_transitive": row.get("direct_or_transitive", ""),
        }
        for row in context_rows
    ]
    _write_csv(config.artifacts_dir / "reachability" / "reachability_matrix.csv", reachability_rows, reachability_fields)
    _write_csv(config.artifacts_dir / "reachability" / "context_enrichment.csv", context_rows, context_fields)


def _finding(finding_id: str, case_id: str, package: str, *, severity: str | None = "HIGH", cvss_score=None, scanners: str = "trivy") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "case_id": case_id,
        "scanner_name": scanners,
        "package_name": package,
        "package_version": "1.0.0",
        "ecosystem": "npm",
        "package_manager": "npm",
        "vulnerability_id": "CVE-2099-0001",
        "severity": severity,
        "cvss_score": cvss_score,
        "fixed_version": "1.0.1",
        "scanner_confidence": "high",
    }


def test_reachable_runtime_direct_dependency_gets_higher_score(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = [
        _finding("reachable", "case_001", "lodash"),
        _finding("unused", "case_002", "minimist"),
    ]
    context_rows = [
        {
            "case_id": "case_001",
            "package_name": "lodash",
            "runtime_dependency": True,
            "dev_dependency": False,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": True,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": True,
            "reachability_status": "reachable",
            "dependency_scope": "runtime",
            "direct_or_transitive": "direct",
            "evidence_reason": "static import and call",
        },
        {
            "case_id": "case_002",
            "package_name": "minimist",
            "runtime_dependency": True,
            "dev_dependency": False,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": False,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": True,
            "reachability_status": "declared_not_used",
            "dependency_scope": "runtime",
            "direct_or_transitive": "direct",
            "evidence_reason": "declared only",
        },
    ]
    _write_scoring_inputs(config, findings, context_rows)

    result = score_findings(create_run_context(config, run_id="score-test"))
    by_id = {item["finding_id"]: item for item in result["scored_findings"]}

    assert by_id["reachable"]["proposed_score"] > by_id["unused"]["proposed_score"]


def test_dev_only_unreachable_dependency_gets_lower_score(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = [_finding("dev", "case_001", "minimist")]
    context_rows = [
        {
            "case_id": "case_001",
            "package_name": "minimist",
            "runtime_dependency": False,
            "dev_dependency": True,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": False,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": False,
            "reachability_status": "dev_only",
            "dependency_scope": "development",
            "direct_or_transitive": "direct",
            "evidence_reason": "development dependency",
        }
    ]
    _write_scoring_inputs(config, findings, context_rows)

    score = score_findings(create_run_context(config, run_id="score-test"))["scored_findings"][0]["proposed_score"]

    assert score < 50


def test_missing_cvss_is_handled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = [_finding("missing-cvss", "case_001", "lodash", cvss_score=None)]
    context_rows = [
        {
            "case_id": "case_001",
            "package_name": "lodash",
            "runtime_dependency": True,
            "dev_dependency": False,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": True,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": True,
            "reachability_status": "reachable",
            "dependency_scope": "runtime",
            "direct_or_transitive": "direct",
            "evidence_reason": "static import",
        }
    ]
    _write_scoring_inputs(config, findings, context_rows)

    scored = score_findings(create_run_context(config, run_id="score-test"))["scored_findings"][0]

    assert scored["proposed_score"] > 0
    assert scored["proposed_priority"] in {"critical", "high", "medium", "low", "informational"}


def test_scanner_agreement_increases_score(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = [
        _finding("single", "case_001", "lodash", severity="MEDIUM", scanners="trivy"),
        _finding("multi", "case_001", "lodash", severity="MEDIUM", scanners="grype;trivy"),
    ]
    context_rows = [
        {
            "case_id": "case_001",
            "package_name": "lodash",
            "runtime_dependency": True,
            "dev_dependency": False,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": True,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": True,
            "reachability_status": "reachable",
            "dependency_scope": "runtime",
            "direct_or_transitive": "direct",
            "evidence_reason": "static import",
        }
    ]
    _write_scoring_inputs(config, findings, context_rows)

    result = score_findings(create_run_context(config, run_id="score-test"))
    by_id = {item["finding_id"]: item for item in result["scored_findings"]}

    assert by_id["multi"]["proposed_score"] > by_id["single"]["proposed_score"]


def test_baseline_rankings_generated(tmp_path: Path) -> None:
    config = _config(tmp_path)
    findings = [_finding("baseline", "case_001", "lodash")]
    context_rows = [
        {
            "case_id": "case_001",
            "package_name": "lodash",
            "runtime_dependency": True,
            "dev_dependency": False,
            "direct_dependency": True,
            "transitive_dependency": False,
            "package_reachable": True,
            "containerized": False,
            "exposed_service": False,
            "fixed_version_available": True,
            "reachability_status": "reachable",
            "dependency_scope": "runtime",
            "direct_or_transitive": "direct",
            "evidence_reason": "static import",
        }
    ]
    _write_scoring_inputs(config, findings, context_rows)

    score_findings(create_run_context(config, run_id="score-test"))

    baseline_path = config.artifacts_dir / "evaluation" / "baseline_rankings.csv"
    warnings_path = config.artifacts_dir / "evaluation" / "scoring_warnings.csv"
    assert baseline_path.exists()
    assert warnings_path.exists()
    with baseline_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["baseline_name"] for row in rows} == {
        "severity_only",
        "cvss_only",
        "scanner_native_priority",
        "direct_dependency_first",
        "runtime_dependency_first",
        "reachability_only",
    }
