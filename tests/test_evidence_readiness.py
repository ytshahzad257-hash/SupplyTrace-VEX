from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.audit import run_debug_evidence, run_evidence_check, run_publication_audit
from supplytrace.config import ProjectConfig
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


def _minimal_zero_finding_artifacts(config: ProjectConfig) -> None:
    _write_csv(
        config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.csv",
        [
            {
                "case_id": "case_001",
                "scanner_name": "osv",
                "ecosystem": "nodejs",
                "tool_available": False,
                "tool_version": "",
                "command": "[]",
                "status": "unavailable",
                "output_path": "",
            }
        ],
        [
            "case_id",
            "scanner_name",
            "ecosystem",
            "tool_available",
            "tool_version",
            "command",
            "status",
            "output_path",
        ],
    )
    _write_csv(config.artifacts_dir / "normalized" / "findings_normalized.csv", [], ["finding_id", "case_id"])
    _write_csv(config.artifacts_dir / "evaluation" / "risk_scores.csv", [], ["finding_id", "case_id"])
    _write_csv(config.artifacts_dir / "vex" / "vex_summary.csv", [], ["finding_id", "case_id"])
    _write_csv(
        config.artifacts_dir / "evaluation" / "metrics_summary.csv",
        [{"metric": "precision", "method": "proposed_full_model", "value": "not_available", "status": "not_available"}],
        ["metric", "method", "value", "status"],
    )
    _write_csv(
        config.artifacts_dir / "sbom" / "sbom_generation_metadata.csv",
        [{"case_id": "case_001", "syft_tool_status": "unavailable", "cyclonedx_tool_status": "unavailable", "spdx_tool_status": "unavailable"}],
        ["case_id", "syft_tool_status", "cyclonedx_tool_status", "spdx_tool_status"],
    )
    (config.artifacts_dir / "reports").mkdir(parents=True, exist_ok=True)
    (config.artifacts_dir / "reports" / "report.md").write_text("missing evidence\n", encoding="utf-8")
    (config.artifacts_dir / "reports" / "report.html").write_text("<p>missing evidence</p>\n", encoding="utf-8")
    (config.project_root / "docs").mkdir(parents=True, exist_ok=True)
    (config.project_root / "docs" / "manuscript_support.md").write_text(
        "Do not claim prioritization improvement because no scanner-confirmed findings were normalized.\n",
        encoding="utf-8",
    )


def test_evidence_check_caps_score_when_findings_are_zero(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _minimal_zero_finding_artifacts(config)

    result = run_evidence_check(create_run_context(config, run_id="evidence-test"), run_tests=False)

    assert result["ready_for_paper_results"] == "no"
    assert result["readiness_score_out_of_10"] <= 5
    assert "no scanner-confirmed findings were normalized" in " ".join(result["blocking_issues"])
    assert (config.artifacts_dir / "audit" / "evidence_readiness_report.md").exists()
    assert (config.artifacts_dir / "audit" / "evidence_readiness_summary.csv").exists()
    assert json.loads((config.artifacts_dir / "audit" / "evidence_readiness_summary.json").read_text(encoding="utf-8"))["ready_for_paper_results"] == "no"


def test_publication_audit_score_cannot_exceed_zero_finding_evidence(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _minimal_zero_finding_artifacts(config)

    result = run_publication_audit(create_run_context(config, run_id="audit-test"), run_tests=False)

    assert result["publication_readiness_score_out_of_10"] <= 5
    assert result["recommendation"] == "not_ready_for_paper_results"
    assert (config.artifacts_dir / "audit" / "publication_readiness_score.csv").exists()
    assert (config.artifacts_dir / "audit" / "final_audit_report.md").exists()


def test_debug_evidence_reports_zero_finding_reason(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _minimal_zero_finding_artifacts(config)

    result = run_debug_evidence(create_run_context(config, run_id="debug-test"))

    assert result["normalized_findings_count"] == 0
    assert result["risk_score_count"] == 0
    assert result["vex_record_count"] == 0
    assert result["zero_finding_reason"]
    assert (config.artifacts_dir / "audit" / "debug_evidence_report.md").exists()
    assert (config.artifacts_dir / "audit" / "debug_evidence_summary.csv").exists()
