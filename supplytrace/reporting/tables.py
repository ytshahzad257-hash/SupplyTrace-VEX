"""Paper-ready tabular report helpers."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from supplytrace.normalize.schema import NORMALIZED_FINDING_FIELDS
from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext


TABLE_OUTPUTS: tuple[tuple[str, str], ...] = (
    ("table_01_testbed_taxonomy.csv", "Testbed Case Taxonomy"),
    ("table_02_scanner_tool_capability_matrix.csv", "Scanner Tool Capability Matrix"),
    ("table_03_ground_truth_label_distribution.csv", "Ground Truth Label Distribution"),
    ("table_04_normalized_finding_schema.csv", "Normalized Finding Schema"),
    ("table_05_risk_scoring_factors.csv", "Risk Scoring Factors"),
    ("table_06_baseline_comparison_results.csv", "Baseline Comparison Results"),
    ("table_07_scanner_disagreement_matrix.csv", "Scanner Disagreement Matrix"),
    ("table_08_ablation_study_results.csv", "Ablation Study Results"),
    ("table_09_runtime_summary.csv", "Runtime Summary"),
    ("table_10_limitations.csv", "Limitations and Validity Threats"),
)

SCANNER_CAPABILITIES: dict[str, dict[str, str]] = {
    "osv": {
        "adapter": "OSV-Scanner",
        "local_target": "case directory manifest files",
        "raw_output": "JSON when tool produces JSON",
        "scope": "local generated testbed paths only",
    },
    "trivy": {
        "adapter": "Trivy",
        "local_target": "case directory or local image reference",
        "raw_output": "JSON when tool produces JSON",
        "scope": "local generated testbed paths or local images only",
    },
    "grype": {
        "adapter": "Grype",
        "local_target": "case directory or local image reference",
        "raw_output": "JSON when tool produces JSON",
        "scope": "local generated testbed paths or local images only",
    },
    "npm_audit": {
        "adapter": "npm audit",
        "local_target": "Node.js case directory with package manifest",
        "raw_output": "JSON from npm audit when applicable",
        "scope": "local generated testbed paths only",
    },
    "pip_audit": {
        "adapter": "pip-audit",
        "local_target": "Python case directory with requirements manifest",
        "raw_output": "JSON from pip-audit when applicable",
        "scope": "local generated testbed paths only",
    },
}

NORMALIZED_FIELD_DESCRIPTIONS: dict[str, str] = {
    "finding_id": "Stable normalized finding identifier.",
    "case_id": "Local testbed case identifier.",
    "scanner_name": "Scanner or scanners that produced the normalized evidence.",
    "package_name": "Dependency package name reported by the scanner.",
    "package_version": "Installed or manifest version when reported.",
    "ecosystem": "Package ecosystem such as npm, pypi, or linux-package.",
    "package_manager": "Package manager or manifest family associated with the finding.",
    "vulnerability_id": "Primary vulnerability identifier from scanner output.",
    "cve_id": "CVE identifier when scanner output includes one.",
    "ghsa_id": "GitHub Security Advisory identifier when scanner output includes one.",
    "osv_id": "OSV identifier when scanner output includes one.",
    "severity": "Scanner-provided severity when available.",
    "cvss_score": "Scanner-provided CVSS score when available.",
    "fixed_version": "Scanner-provided fixed version when available.",
    "advisory_url": "Scanner-provided advisory URL when available.",
    "dependency_scope": "Runtime, development, transitive, container, or unknown scope.",
    "direct_or_transitive": "Direct, transitive, container-layer, or unknown relationship.",
    "source_file": "Raw evidence source file or target path.",
    "raw_reference": "Path to raw scanner output used during normalization.",
    "scanner_confidence": "Scanner or normalizer confidence value when available.",
    "normalization_notes": "Warnings or normalization notes preserved for auditability.",
}


def markdown_table(headers: list[str], rows: list[list[object]]) -> str:
    """Render a compact GitHub-flavored Markdown table."""

    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return "\n".join(lines)


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file or return an empty list when it is missing."""

    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | tuple[str, ...]) -> Path:
    """Write a CSV file with a stable header."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})
    return path


def _status_counts(rows: list[dict[str, str]], field: str = "status") -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = row.get(field) or "unknown"
        counts[status] = counts.get(status, 0) + 1
    return counts


def _table_01(ground_truth: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    grouped: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in ground_truth:
        grouped[
            (
                row.get("category") or "unknown",
                row.get("ecosystem") or "unknown",
                row.get("expected_actionability_label") or "unknown",
            )
        ] += 1
    rows = [
        {
            "category": category,
            "ecosystem": ecosystem,
            "expected_actionability_label": label,
            "case_count": count,
        }
        for (category, ecosystem, label), count in sorted(grouped.items())
    ]
    if not rows:
        rows = [{"category": "missing_input", "ecosystem": "", "expected_actionability_label": "", "case_count": 0}]
    return rows, ["category", "ecosystem", "expected_actionability_label", "case_count"]


def _table_02(scanner_metadata: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    metadata_by_scanner: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in scanner_metadata:
        metadata_by_scanner[(row.get("scanner_name") or "").replace("-", "_")].append(row)

    rows: list[dict[str, Any]] = []
    for scanner_name, capability in sorted(SCANNER_CAPABILITIES.items()):
        scanner_rows = metadata_by_scanner.get(scanner_name, [])
        statuses = _status_counts(scanner_rows)
        available = any(str(row.get("tool_available") or "").lower() == "true" for row in scanner_rows)
        rows.append(
            {
                "scanner_name": scanner_name,
                "adapter": capability["adapter"],
                "local_target": capability["local_target"],
                "raw_output": capability["raw_output"],
                "local_only_scope": capability["scope"],
                "tool_available_in_run": available if scanner_rows else "not_observed",
                "success_count": statuses.get("success", 0),
                "failed_count": statuses.get("failed", 0),
                "unavailable_count": statuses.get("unavailable", 0),
                "skipped_not_applicable_count": statuses.get("skipped_not_applicable", 0),
            }
        )
    return rows, [
        "scanner_name",
        "adapter",
        "local_target",
        "raw_output",
        "local_only_scope",
        "tool_available_in_run",
        "success_count",
        "failed_count",
        "unavailable_count",
        "skipped_not_applicable_count",
    ]


def _table_03(ground_truth: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    counts = Counter(row.get("expected_actionability_label") or "unknown" for row in ground_truth)
    rows = [{"expected_actionability_label": label, "case_count": count} for label, count in sorted(counts.items())]
    if not rows:
        rows = [{"expected_actionability_label": "missing_input", "case_count": 0}]
    return rows, ["expected_actionability_label", "case_count"]


def _table_04() -> tuple[list[dict[str, Any]], list[str]]:
    rows = [
        {
            "field_name": field,
            "description": NORMALIZED_FIELD_DESCRIPTIONS.get(field, "Normalized finding field."),
            "missing_data_policy": "null or unknown with normalization warning when source evidence is absent",
        }
        for field in NORMALIZED_FINDING_FIELDS
    ]
    return rows, ["field_name", "description", "missing_data_policy"]


def _table_05(context: RunContext) -> tuple[list[dict[str, Any]], list[str]]:
    rows = [
        {
            "factor": factor,
            "weight": weight,
            "interpretation": "positive values raise actionability priority; negative values lower it",
            "claim_boundary": "heuristic prioritization only, not exploitability proof",
        }
        for factor, weight in sorted(context.config.scoring_weights.items())
    ]
    return rows, ["factor", "weight", "interpretation", "claim_boundary"]


def _copy_or_missing(rows: list[dict[str, str]], fields: list[str], missing_label: str) -> tuple[list[dict[str, Any]], list[str]]:
    if rows:
        return [dict(row) for row in rows], fields
    return [{field: ("missing_or_empty_input" if index == 0 else "") for index, field in enumerate(fields)}], fields


def _table_07(scanner_rows: list[dict[str, str]], findings: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    pair_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"shared_findings": 0, "disagreement_flags": 0})
    for row in scanner_rows:
        scanners = [item for item in (row.get("scanner_names") or "").split(";") if item]
        if len(scanners) < 2:
            continue
        for left_index, left in enumerate(scanners):
            for right in scanners[left_index + 1 :]:
                key = tuple(sorted((left, right)))
                pair_counts[key]["shared_findings"] += 1
                if str(row.get("disagreement_flag") or "").lower() == "true":
                    pair_counts[key]["disagreement_flags"] += 1

    if not pair_counts and findings:
        for row in findings:
            scanners = [item.strip() for item in (row.get("scanner_name") or "").replace(",", ";").split(";") if item.strip()]
            if len(scanners) < 2:
                continue
            for left_index, left in enumerate(scanners):
                for right in scanners[left_index + 1 :]:
                    key = tuple(sorted((left, right)))
                    pair_counts[key]["shared_findings"] += 1

    rows = [
        {
            "scanner_a": left,
            "scanner_b": right,
            "shared_findings": values["shared_findings"],
            "disagreement_flags": values["disagreement_flags"],
            "notes": "derived from normalized finding scanner sets and disagreement annotations",
        }
        for (left, right), values in sorted(pair_counts.items())
    ]
    if not rows:
        rows = [
            {
                "scanner_a": "not_available",
                "scanner_b": "",
                "shared_findings": 0,
                "disagreement_flags": 0,
                "notes": "no multi-scanner normalized findings were available",
            }
        ]
    return rows, ["scanner_a", "scanner_b", "shared_findings", "disagreement_flags", "notes"]


def _table_10() -> tuple[list[dict[str, Any]], list[str]]:
    rows = [
        {
            "validity_threat": "Static reachability limitations",
            "project_handling": "Dynamic imports, generated code, framework dispatch, and runtime configuration are marked as limitations or unknown evidence.",
            "supporting_artifact": "artifacts/reachability/reachability_matrix.csv",
        },
        {
            "validity_threat": "Scanner availability",
            "project_handling": "Missing tools are reported as unavailable instead of being replaced with synthetic scanner output.",
            "supporting_artifact": "artifacts/scanner_raw/scanner_execution_metadata.csv",
        },
        {
            "validity_threat": "Ground truth scope",
            "project_handling": "Labels describe project-context actionability for local cases, not universal vulnerability truth.",
            "supporting_artifact": "testbed/ground_truth/ground_truth.csv",
        },
        {
            "validity_threat": "Prioritization interpretation",
            "project_handling": "Scores rank defensive actionability evidence and do not prove exploitability.",
            "supporting_artifact": "artifacts/evaluation/risk_scores.csv",
        },
        {
            "validity_threat": "VEX interpretation",
            "project_handling": "Generated statuses are VEX-style project evidence records, not official vendor VEX attestations.",
            "supporting_artifact": "artifacts/vex/vex_summary.csv",
        },
    ]
    return rows, ["validity_threat", "project_handling", "supporting_artifact"]


def generate_paper_tables(context: RunContext) -> dict[str, str]:
    """Generate all paper-ready table CSVs and return their paths."""

    artifacts = context.config.artifacts_dir
    reports_dir = artifacts / "reports"
    tables_dir = reports_dir / "tables"
    ground_truth = read_csv(context.config.ground_truth_dir / "ground_truth.csv")
    scanner_metadata = read_csv(artifacts / "scanner_raw" / "scanner_execution_metadata.csv")
    findings = read_csv(artifacts / "normalized" / "findings_normalized.csv")
    baseline = read_csv(artifacts / "evaluation" / "baseline_comparison.csv")
    scanner_disagreement = read_csv(artifacts / "evaluation" / "scanner_disagreement.csv")
    ablation = read_csv(artifacts / "evaluation" / "ablation_results.csv")
    runtime = read_csv(artifacts / "evaluation" / "runtime_summary.csv")

    table_data: dict[str, tuple[list[dict[str, Any]], list[str]]] = {
        "table_01_testbed_taxonomy.csv": _table_01(ground_truth),
        "table_02_scanner_tool_capability_matrix.csv": _table_02(scanner_metadata),
        "table_03_ground_truth_label_distribution.csv": _table_03(ground_truth),
        "table_04_normalized_finding_schema.csv": _table_04(),
        "table_05_risk_scoring_factors.csv": _table_05(context),
        "table_06_baseline_comparison_results.csv": _copy_or_missing(
            baseline,
            ["method", "finding_count", "labeled_count", "actionable_count", "top5_actionability", "top10_actionability", "ndcg", "map", "status", "notes"],
            "baseline_comparison",
        ),
        "table_07_scanner_disagreement_matrix.csv": _table_07(scanner_disagreement, findings),
        "table_08_ablation_study_results.csv": _copy_or_missing(
            ablation,
            ["variant", "finding_count", "labeled_count", "actionable_count", "top5_actionability", "top10_actionability", "ndcg", "map", "status", "notes"],
            "ablation_results",
        ),
        "table_09_runtime_summary.csv": _copy_or_missing(
            runtime,
            ["case_id", "total_duration_seconds", "scanner_count", "success_count", "failed_count", "unavailable_count", "skipped_not_applicable_count", "other_status_count", "available_tool_count", "notes"],
            "runtime_summary",
        ),
        "table_10_limitations.csv": _table_10(),
    }

    paths: dict[str, str] = {}
    for filename, _title in TABLE_OUTPUTS:
        rows, fields = table_data[filename]
        path = write_csv(tables_dir / filename, rows, fields)
        paths[filename] = to_project_relative_path(path, context.config) or str(path)
    return paths
