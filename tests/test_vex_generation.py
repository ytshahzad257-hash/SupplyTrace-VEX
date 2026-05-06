from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.run_context import create_run_context
from supplytrace.vex.vex_generator import generate_vex


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


def _finding(finding_id: str = "finding-1", case_id: str = "case_001", package: str = "lodash", version: str = "4.17.20") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "case_id": case_id,
        "scanner_name": "trivy;grype",
        "package_name": package,
        "package_version": version,
        "ecosystem": "npm",
        "package_manager": "npm",
        "vulnerability_id": "CVE-2099-0001",
        "cve_id": "CVE-2099-0001",
        "ghsa_id": None,
        "osv_id": None,
        "severity": "HIGH",
        "cvss_score": 8.1,
        "fixed_version": "4.17.21",
        "advisory_url": None,
        "dependency_scope": "runtime",
        "direct_or_transitive": "direct",
        "source_file": "package-lock.json",
        "raw_reference": "artifacts/scanner_raw/trivy/case_001.json;artifacts/scanner_raw/grype/case_001.json",
        "scanner_confidence": "high",
        "normalization_notes": "parsed from local scanner output",
    }


def _context_row(
    *,
    case_id: str = "case_001",
    package: str = "lodash",
    reachability_status: str = "reachable",
    runtime: bool = True,
    dev: bool = False,
    direct: bool = True,
    transitive: bool = False,
    package_reachable: bool = True,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "package_name": package,
        "runtime_dependency": runtime,
        "dev_dependency": dev,
        "direct_dependency": direct,
        "transitive_dependency": transitive,
        "package_reachable": package_reachable,
        "containerized": False,
        "exposed_service": False,
        "fixed_version_available": True,
        "reachability_status": reachability_status,
        "dependency_scope": "development" if dev else "runtime",
        "direct_or_transitive": "transitive" if transitive else "direct",
        "evidence_reason": "test evidence",
    }


def _write_inputs(config: ProjectConfig, finding: dict[str, object], context_row: dict[str, object], score: float = 80.0) -> None:
    normalized_path = config.artifacts_dir / "normalized" / "findings_normalized.json"
    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_path.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")

    score_path = config.artifacts_dir / "evaluation" / "risk_scores.json"
    score_path.parent.mkdir(parents=True, exist_ok=True)
    score_path.write_text(
        json.dumps(
            {
                "risk_scores": [
                    {
                        "finding_id": finding["finding_id"],
                        "case_id": finding["case_id"],
                        "package_name": finding["package_name"],
                        "vulnerability_id": finding["vulnerability_id"],
                        "proposed_score": score,
                        "proposed_priority": "high" if score >= 70 else "medium",
                        "score_explanation": "test score",
                        "evidence_fields_used": "reachability_status;runtime_dependency",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    reachability_fields = [
        "case_id",
        "package_name",
        "package_version",
        "ecosystem",
        "package_manager",
        "dependency_scope",
        "direct_or_transitive",
        "declared",
        "imported",
        "called",
        "reachability_status",
        "source_files",
        "evidence_reason",
    ]
    reachability_row = {
        **context_row,
        "package_version": finding["package_version"],
        "ecosystem": finding["ecosystem"],
        "package_manager": finding["package_manager"],
        "declared": True,
        "imported": context_row["package_reachable"],
        "called": context_row["package_reachable"],
        "source_files": "src/index.js",
    }
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
    _write_csv(config.artifacts_dir / "reachability" / "reachability_matrix.csv", [reachability_row], reachability_fields)
    _write_csv(config.artifacts_dir / "reachability" / "context_enrichment.csv", [context_row], context_fields)


def _first_record(result: dict[str, object]) -> dict[str, object]:
    records = result["records"]
    assert isinstance(records, list)
    assert records
    return records[0]


def test_vex_affected_assignment(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding()
    _write_inputs(config, finding, _context_row())

    result = generate_vex(create_run_context(config, run_id="vex-test"))

    assert _first_record(result)["status"] == "affected"


def test_vex_not_affected_assignment(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding(package="minimist")
    context_row = _context_row(package="minimist", reachability_status="dev_only", runtime=False, dev=True, package_reachable=False)
    _write_inputs(config, finding, context_row, score=30.0)

    result = generate_vex(create_run_context(config, run_id="vex-test"))

    assert _first_record(result)["status"] == "not_affected"


def test_vex_fixed_assignment_from_local_metadata(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding(version="4.17.21")
    case_dir = config.cases_dir / "case_001"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "metadata.json").write_text(
        json.dumps(
            {
                "case_id": "case_001",
                "expected_actionability_label": "fixed",
                "vulnerable_package_expected": "lodash",
                "vulnerable_version_expected": "4.17.21",
            }
        ),
        encoding="utf-8",
    )
    _write_inputs(config, finding, _context_row(), score=70.0)

    result = generate_vex(create_run_context(config, run_id="vex-test"))

    assert _first_record(result)["status"] == "fixed"


def test_vex_under_investigation_assignment_for_unknown_reachability(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding(package="openssl")
    context_row = _context_row(package="openssl", reachability_status="unknown", package_reachable=False)
    _write_inputs(config, finding, context_row, score=60.0)

    result = generate_vex(create_run_context(config, run_id="vex-test"))

    assert _first_record(result)["status"] == "under_investigation"


def test_vex_evidence_fields_present(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding()
    _write_inputs(config, finding, _context_row())

    record = _first_record(generate_vex(create_run_context(config, run_id="vex-test")))
    evidence = record["evidence"]

    assert set(evidence) == {
        "scanner_names",
        "scanner_output_paths",
        "reachability_status",
        "dependency_scope",
        "context_fields",
        "risk_score",
        "confidence_level",
    }
    assert evidence["scanner_names"] == ["trivy", "grype"]
    assert evidence["risk_score"]["proposed_score"] == 80.0


def test_vex_summary_csv_generated(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding()
    _write_inputs(config, finding, _context_row())

    generate_vex(create_run_context(config, run_id="vex-test"))

    summary_path = config.artifacts_dir / "vex" / "vex_summary.csv"
    distribution_path = config.artifacts_dir / "vex" / "vex_status_distribution.csv"
    warnings_path = config.artifacts_dir / "vex" / "vex_generation_warnings.csv"
    case_path = config.artifacts_dir / "vex" / "case_001.vex.json"
    assert summary_path.exists()
    assert distribution_path.exists()
    assert warnings_path.exists()
    assert case_path.exists()
    with summary_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["status"] == "affected"
