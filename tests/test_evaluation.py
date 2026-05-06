from __future__ import annotations

import csv
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.evaluation.ablation import ABLATION_VARIANTS
from supplytrace.evaluation.comparison import scanner_disagreement_rows
from supplytrace.evaluation.experiments import evaluate_run
from supplytrace.evaluation.metrics import mean_average_precision, ndcg_at_k, precision_recall_f1, top_k_actionability
from supplytrace.run_context import create_run_context


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


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_evaluation_fixture(config: ProjectConfig) -> None:
    _write_csv(
        config.ground_truth_dir / "ground_truth.csv",
        [
            {
                "case_id": "case_001",
                "ecosystem": "nodejs",
                "category": "vulnerable_reachable_direct",
                "package_manager": "npm",
                "vulnerable_package_expected": "lodash",
                "vulnerable_version_expected": "4.17.20",
                "expected_dependency_scope": "runtime",
                "expected_reachability": "direct_import_observed",
                "expected_actionability_label": "actionable",
                "explanation": "local labeled fixture",
                "safety_note": "local only",
            },
            {
                "case_id": "case_002",
                "ecosystem": "nodejs",
                "category": "vulnerable_unreachable_direct",
                "package_manager": "npm",
                "vulnerable_package_expected": "minimist",
                "vulnerable_version_expected": "0.0.8",
                "expected_dependency_scope": "runtime",
                "expected_reachability": "declared_but_not_imported",
                "expected_actionability_label": "non_actionable",
                "explanation": "local labeled fixture",
                "safety_note": "local only",
            },
        ],
        [
            "case_id",
            "ecosystem",
            "category",
            "package_manager",
            "vulnerable_package_expected",
            "vulnerable_version_expected",
            "expected_dependency_scope",
            "expected_reachability",
            "expected_actionability_label",
            "explanation",
            "safety_note",
        ],
    )
    _write_csv(
        config.artifacts_dir / "normalized" / "findings_normalized.csv",
        [
            {
                "finding_id": "finding-1",
                "case_id": "case_001",
                "scanner_name": "trivy;grype",
                "package_name": "lodash",
                "package_version": "4.17.20",
                "ecosystem": "npm",
                "package_manager": "npm",
                "vulnerability_id": "CVE-2099-0001",
                "severity": "HIGH",
                "cvss_score": "8.1",
                "fixed_version": "4.17.21",
                "raw_reference": "artifacts/scanner_raw/trivy/case_001.json",
                "scanner_confidence": "high",
                "normalization_notes": "deduplicated",
            },
            {
                "finding_id": "finding-2",
                "case_id": "case_002",
                "scanner_name": "trivy",
                "package_name": "minimist",
                "package_version": "0.0.8",
                "ecosystem": "npm",
                "package_manager": "npm",
                "vulnerability_id": "CVE-2099-0002",
                "severity": "HIGH",
                "cvss_score": "7.0",
                "fixed_version": "1.2.8",
                "raw_reference": "artifacts/scanner_raw/trivy/case_002.json",
                "scanner_confidence": "high",
                "normalization_notes": "parsed",
            },
        ],
        [
            "finding_id",
            "case_id",
            "scanner_name",
            "package_name",
            "package_version",
            "ecosystem",
            "package_manager",
            "vulnerability_id",
            "severity",
            "cvss_score",
            "fixed_version",
            "raw_reference",
            "scanner_confidence",
            "normalization_notes",
        ],
    )
    _write_csv(
        config.artifacts_dir / "reachability" / "reachability_matrix.csv",
        [
            {
                "case_id": "case_001",
                "package_name": "lodash",
                "reachability_status": "reachable",
                "runtime_dependency": "True",
                "dev_dependency": "False",
                "package_reachable": "True",
            },
            {
                "case_id": "case_002",
                "package_name": "minimist",
                "reachability_status": "declared_not_used",
                "runtime_dependency": "True",
                "dev_dependency": "False",
                "package_reachable": "False",
            },
        ],
        ["case_id", "package_name", "reachability_status", "runtime_dependency", "dev_dependency", "package_reachable"],
    )
    _write_csv(
        config.artifacts_dir / "evaluation" / "risk_scores.csv",
        [
            {
                "finding_id": "finding-1",
                "case_id": "case_001",
                "package_name": "lodash",
                "vulnerability_id": "CVE-2099-0001",
                "proposed_score": "90",
                "proposed_priority": "critical",
                "score_explanation": "test",
                "evidence_fields_used": "reachability_status",
            },
            {
                "finding_id": "finding-2",
                "case_id": "case_002",
                "package_name": "minimist",
                "vulnerability_id": "CVE-2099-0002",
                "proposed_score": "15",
                "proposed_priority": "informational",
                "score_explanation": "test",
                "evidence_fields_used": "reachability_status",
            },
        ],
        [
            "finding_id",
            "case_id",
            "package_name",
            "vulnerability_id",
            "proposed_score",
            "proposed_priority",
            "score_explanation",
            "evidence_fields_used",
        ],
    )
    _write_csv(
        config.artifacts_dir / "evaluation" / "baseline_rankings.csv",
        [
            {
                "baseline_name": "severity_only",
                "rank": "1",
                "finding_id": "finding-2",
                "case_id": "case_002",
                "package_name": "minimist",
                "vulnerability_id": "CVE-2099-0002",
                "baseline_score": "90",
            },
            {
                "baseline_name": "severity_only",
                "rank": "2",
                "finding_id": "finding-1",
                "case_id": "case_001",
                "package_name": "lodash",
                "vulnerability_id": "CVE-2099-0001",
                "baseline_score": "50",
            },
        ],
        ["baseline_name", "rank", "finding_id", "case_id", "package_name", "vulnerability_id", "baseline_score"],
    )
    _write_csv(
        config.artifacts_dir / "vex" / "vex_summary.csv",
        [
            {
                "case_id": "case_001",
                "finding_id": "finding-1",
                "vulnerability_id": "CVE-2099-0001",
                "package_name": "lodash",
                "package_version": "4.17.20",
                "status": "affected",
                "confidence_level": "high",
                "risk_score": "90",
                "scanner_names": "trivy;grype",
                "reachability_status": "reachable",
                "dependency_scope": "runtime",
                "justification": "local evidence",
            },
            {
                "case_id": "case_002",
                "finding_id": "finding-2",
                "vulnerability_id": "CVE-2099-0002",
                "package_name": "minimist",
                "package_version": "0.0.8",
                "status": "not_affected",
                "confidence_level": "high",
                "risk_score": "15",
                "scanner_names": "trivy",
                "reachability_status": "declared_not_used",
                "dependency_scope": "runtime",
                "justification": "local evidence",
            },
        ],
        [
            "case_id",
            "finding_id",
            "vulnerability_id",
            "package_name",
            "package_version",
            "status",
            "confidence_level",
            "risk_score",
            "scanner_names",
            "reachability_status",
            "dependency_scope",
            "justification",
        ],
    )
    _write_csv(
        config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.csv",
        [
            {
                "case_id": "case_001",
                "scanner_name": "trivy",
                "tool_available": "True",
                "duration_seconds": "1.25",
                "status": "success",
            },
            {
                "case_id": "case_002",
                "scanner_name": "grype",
                "tool_available": "False",
                "duration_seconds": "0",
                "status": "unavailable",
            },
        ],
        ["case_id", "scanner_name", "tool_available", "duration_seconds", "status"],
    )


def test_precision_recall_f1() -> None:
    assert precision_recall_f1(true_positive=2, false_positive=1, false_negative=1) == {
        "precision": 0.666667,
        "recall": 0.666667,
        "f1": 0.666667,
    }


def test_top_k_actionability() -> None:
    result = top_k_actionability([True, False, True], 2)

    assert result["evaluated_count"] == 2
    assert result["actionable_count"] == 1
    assert result["topk_actionability"] == 0.5


def test_ndcg_and_map() -> None:
    labels = [True, False, True]

    assert ndcg_at_k(labels) == 0.919721
    assert mean_average_precision(labels) == 0.833333


def test_scanner_disagreement_detection() -> None:
    rows = scanner_disagreement_rows(
        [
            {
                "finding": {"normalization_notes": "scanner disagreement on severity", "scanner_confidence": "high"},
                "finding_id": "finding-1",
                "case_id": "case_001",
                "package_name": "lodash",
                "vulnerability_id": "CVE-2099-0001",
                "scanner_names": ["trivy", "grype"],
            }
        ]
    )

    assert rows[0]["disagreement_flag"] is True
    assert rows[0]["scanner_count"] == 2


def test_evaluate_run_handles_missing_data(tmp_path: Path) -> None:
    config = _config(tmp_path)

    result = evaluate_run(create_run_context(config, run_id="eval-missing"))

    assert result["status"] == "completed_with_missing_or_insufficient_data"
    assert (config.artifacts_dir / "evaluation" / "metrics_summary.csv").exists()
    notes = (config.artifacts_dir / "evaluation" / "evaluation_notes.md").read_text(encoding="utf-8")
    assert "Missing input" in notes
    assert "not fabricate" in notes


def test_evaluate_run_writes_ablation_and_all_outputs(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_evaluation_fixture(config)

    result = evaluate_run(create_run_context(config, run_id="eval-test"))

    assert result["finding_count"] == 2
    assert result["labeled_finding_count"] == 2
    expected_outputs = [
        "metrics_summary.csv",
        "baseline_comparison.csv",
        "scanner_disagreement.csv",
        "ablation_results.csv",
        "runtime_summary.csv",
        "evidence_completeness.csv",
        "topk_comparison.csv",
        "evaluation_notes.md",
    ]
    for filename in expected_outputs:
        assert (config.artifacts_dir / "evaluation" / filename).exists()

    ablation_rows = _read_csv(config.artifacts_dir / "evaluation" / "ablation_results.csv")
    assert {row["variant"] for row in ablation_rows} == set(ABLATION_VARIANTS)

    metrics_rows = _read_csv(config.artifacts_dir / "evaluation" / "metrics_summary.csv")
    fp_reduction = next(row for row in metrics_rows if row["metric"] == "false_positive_reduction")
    assert fp_reduction["value"] == "1.0"
