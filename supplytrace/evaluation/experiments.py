"""Evaluation orchestration for SupplyTrace-VEX local research artifacts."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext, write_json

from .ablation import run_ablation
from .comparison import (
    baseline_rankings,
    build_evaluation_items,
    compare_binary_methods,
    labeled_items,
    proposed_ranking,
    ranking_quality,
    scanner_disagreement_rows,
    scanner_disagreement_summary,
)
from .metrics import evidence_completeness_score, top_k_actionability


METRICS_SUMMARY_FIELDS: tuple[str, ...] = (
    "experiment",
    "method",
    "metric",
    "value",
    "numerator",
    "denominator",
    "status",
    "notes",
)

BASELINE_COMPARISON_FIELDS: tuple[str, ...] = (
    "method",
    "finding_count",
    "labeled_count",
    "actionable_count",
    "top5_actionability",
    "top10_actionability",
    "ndcg",
    "map",
    "status",
    "notes",
)

SCANNER_DISAGREEMENT_FIELDS: tuple[str, ...] = (
    "finding_id",
    "case_id",
    "package_name",
    "vulnerability_id",
    "scanner_names",
    "scanner_count",
    "scanner_overlap",
    "disagreement_flag",
    "disagreement_reason",
)

ABLATION_FIELDS: tuple[str, ...] = (
    "variant",
    "finding_count",
    "labeled_count",
    "actionable_count",
    "top5_actionability",
    "top10_actionability",
    "ndcg",
    "map",
    "status",
    "notes",
)

RUNTIME_FIELDS: tuple[str, ...] = (
    "case_id",
    "total_duration_seconds",
    "scanner_count",
    "success_count",
    "failed_count",
    "unavailable_count",
    "skipped_not_applicable_count",
    "other_status_count",
    "available_tool_count",
    "notes",
)

EVIDENCE_COMPLETENESS_FIELDS: tuple[str, ...] = (
    "finding_id",
    "case_id",
    "package_name",
    "vulnerability_id",
    "evidence_fields_present",
    "evidence_fields_expected",
    "evidence_completeness_score",
    "missing_fields",
    "notes",
)

TOPK_FIELDS: tuple[str, ...] = (
    "method",
    "k",
    "evaluated_count",
    "actionable_count",
    "topk_actionability",
    "status",
    "notes",
)

EXPECTED_BASELINE_METHODS: tuple[str, ...] = (
    "severity_only",
    "cvss_only",
    "scanner_native_priority",
    "direct_dependency_first",
    "runtime_dependency_first",
    "reachability_only",
)

EXPECTED_EVIDENCE_FIELDS: tuple[str, ...] = (
    "scanner_name",
    "vulnerability_id",
    "package_version",
    "severity_or_cvss",
    "scanner_confidence",
    "raw_reference",
    "reachability_status",
    "risk_score",
    "vex_status",
)


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


def _metric_row(
    experiment: str,
    method: str,
    metric: str,
    value: Any,
    *,
    numerator: Any = "",
    denominator: Any = "",
    status: str = "ok",
    notes: str = "",
) -> dict[str, Any]:
    return {
        "experiment": experiment,
        "method": method,
        "metric": metric,
        "value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "notes": notes,
    }


def _input_paths(context: RunContext) -> dict[str, Path]:
    artifacts = context.config.artifacts_dir
    return {
        "ground_truth": context.config.ground_truth_dir / "ground_truth.csv",
        "normalized_findings": artifacts / "normalized" / "findings_normalized.csv",
        "reachability_matrix": artifacts / "reachability" / "reachability_matrix.csv",
        "risk_scores": artifacts / "evaluation" / "risk_scores.csv",
        "baseline_rankings": artifacts / "evaluation" / "baseline_rankings.csv",
        "vex_summary": artifacts / "vex" / "vex_summary.csv",
        "scanner_execution_metadata": artifacts / "scanner_raw" / "scanner_execution_metadata.csv",
    }


def _missing_input_notes(paths: dict[str, Path]) -> list[str]:
    return [f"Missing input: {name} at {path}" for name, path in paths.items() if not path.exists()]


def _runtime_summary_rows(scanner_metadata: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in scanner_metadata:
        case_id = row.get("case_id") or "unknown"
        grouped.setdefault(case_id, []).append(row)

    rows: list[dict[str, Any]] = []
    for case_id in sorted(grouped):
        case_rows = grouped[case_id]
        total_duration = 0.0
        for row in case_rows:
            try:
                total_duration += float(row.get("duration_seconds") or 0.0)
            except ValueError:
                pass
        status_counts: dict[str, int] = {}
        available_tools = 0
        for row in case_rows:
            status = row.get("status") or "unknown"
            status_counts[status] = status_counts.get(status, 0) + 1
            if str(row.get("tool_available") or "").lower() == "true":
                available_tools += 1
        known_total = (
            status_counts.get("success", 0)
            + status_counts.get("failed", 0)
            + status_counts.get("unavailable", 0)
            + status_counts.get("skipped_not_applicable", 0)
        )
        rows.append(
            {
                "case_id": case_id,
                "total_duration_seconds": round(total_duration, 6),
                "scanner_count": len(case_rows),
                "success_count": status_counts.get("success", 0),
                "failed_count": status_counts.get("failed", 0),
                "unavailable_count": status_counts.get("unavailable", 0),
                "skipped_not_applicable_count": status_counts.get("skipped_not_applicable", 0),
                "other_status_count": max(0, len(case_rows) - known_total),
                "available_tool_count": available_tools,
                "notes": "summarized from scanner execution metadata",
            }
        )
    return rows


def _evidence_completeness_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in items:
        finding = item["finding"]
        risk_score = item.get("risk_score") if isinstance(item.get("risk_score"), dict) else {}
        vex = item.get("vex") if isinstance(item.get("vex"), dict) else {}
        missing: list[str] = []
        if not finding.get("scanner_name"):
            missing.append("scanner_name")
        if not finding.get("vulnerability_id") or finding.get("vulnerability_id") == "unknown":
            missing.append("vulnerability_id")
        if not finding.get("package_version"):
            missing.append("package_version")
        if not finding.get("severity") and not finding.get("cvss_score"):
            missing.append("severity_or_cvss")
        if not finding.get("scanner_confidence") or finding.get("scanner_confidence") == "unknown":
            missing.append("scanner_confidence")
        if not finding.get("raw_reference"):
            missing.append("raw_reference")
        if not item.get("reachability_status") or item.get("reachability_status") == "unknown":
            missing.append("reachability_status")
        if not risk_score.get("proposed_score"):
            missing.append("risk_score")
        if not vex.get("status"):
            missing.append("vex_status")
        present = len(EXPECTED_EVIDENCE_FIELDS) - len(missing)
        rows.append(
            {
                "finding_id": item.get("finding_id"),
                "case_id": item.get("case_id"),
                "package_name": item.get("package_name"),
                "vulnerability_id": item.get("vulnerability_id"),
                "evidence_fields_present": present,
                "evidence_fields_expected": len(EXPECTED_EVIDENCE_FIELDS),
                "evidence_completeness_score": evidence_completeness_score(present, len(EXPECTED_EVIDENCE_FIELDS)),
                "missing_fields": ";".join(missing),
                "notes": "score is a completeness fraction, not evidence quality proof",
            }
        )
    return rows


def _topk_rows(rankings: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for method, ranked in sorted(rankings.items()):
        labels = [bool(item["label"]) for item in ranked if isinstance(item.get("label"), bool)]
        for k in (5, 10):
            metric = top_k_actionability(labels, k) if labels else {
                "k": k,
                "evaluated_count": 0,
                "actionable_count": 0,
                "topk_actionability": 0.0,
            }
            rows.append(
                {
                    "method": method,
                    "k": metric["k"],
                    "evaluated_count": metric["evaluated_count"],
                    "actionable_count": metric["actionable_count"],
                    "topk_actionability": metric["topk_actionability"],
                    "status": "ok" if labels else "not_available",
                    "notes": "computed over labeled scanner-backed findings" if labels else "no labeled scanner-backed findings available",
                }
            )
    return rows


def _metrics_from_binary(binary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for experiment, key in (("E1", "raw"), ("E2", "context_filter"), ("E2", "proposed")):
        method = binary[key]
        for metric in ("precision", "recall", "f1"):
            rows.append(
                _metric_row(
                    experiment,
                    method["method"],
                    metric,
                    method[metric],
                    status=method["status"],
                    notes=method["notes"],
                )
            )
    rows.extend(
        [
            _metric_row(
                "E2",
                "proposed_full_model",
                "false_positive_reduction",
                binary["false_positive_reduction"],
                numerator=int(binary["raw"]["false_positive"]) - int(binary["proposed"]["false_positive"]),
                denominator=binary["raw"]["false_positive"],
                status=binary["proposed"]["status"],
                notes="computed against raw-scanner-as-retain-all baseline",
            ),
            _metric_row(
                "E2",
                "proposed_full_model",
                "actionable_findings_retained",
                binary["actionable_findings_retained"],
                numerator=binary["actionable_findings_retained"],
                denominator=sum(1 for item in labeled_items(binary.get("items", [])) if item.get("label") is True),
                status=binary["proposed"]["status"],
                notes="true positives retained by proposed actionability decision",
            ),
        ]
    )
    return rows


def _notes_markdown(
    *,
    run_id: str,
    input_notes: list[str],
    finding_count: int,
    labeled_count: int,
    scanner_metadata: list[dict[str, str]],
    binary: dict[str, Any],
    baseline_rows: list[dict[str, Any]],
    completeness_rows: list[dict[str, Any]],
) -> str:
    scanner_status_counts: dict[str, int] = {}
    for row in scanner_metadata:
        status = row.get("status") or "unknown"
        scanner_status_counts[status] = scanner_status_counts.get(status, 0) + 1
    unavailable = scanner_status_counts.get("unavailable", 0)
    failed = scanner_status_counts.get("failed", 0)
    skipped = scanner_status_counts.get("skipped_not_applicable", 0)
    mean_completeness = (
        round(sum(float(row["evidence_completeness_score"]) for row in completeness_rows) / len(completeness_rows), 6)
        if completeness_rows
        else 0.0
    )

    best_line = "Ranking comparison was not available because there were no labeled scanner-backed findings."
    zero_finding_warning = (
        "\nNo normalized scanner-confirmed findings were available. Do not claim prioritization improvement "
        "from this run.\n"
        if finding_count == 0
        else ""
    )
    proposed = next((row for row in baseline_rows if row.get("method") == "proposed_full_model"), None)
    baselines = [row for row in baseline_rows if row.get("method") != "proposed_full_model" and row.get("status") == "ok"]
    if proposed and proposed.get("status") == "ok" and baselines:
        best_baseline = max(baselines, key=lambda row: float(row.get("map") or 0.0))
        proposed_map = float(proposed.get("map") or 0.0)
        baseline_map = float(best_baseline.get("map") or 0.0)
        if proposed_map > baseline_map:
            best_line = (
                f"The proposed ranking MAP ({proposed_map}) exceeded the best available baseline "
                f"({best_baseline['method']}: {baseline_map}) on labeled scanner-backed findings."
            )
        elif proposed_map == baseline_map:
            best_line = (
                f"The proposed ranking MAP ({proposed_map}) tied the best available baseline "
                f"({best_baseline['method']}: {baseline_map}) on labeled scanner-backed findings."
            )
        else:
            best_line = (
                f"The proposed ranking MAP ({proposed_map}) did not exceed the best available baseline "
                f"({best_baseline['method']}: {baseline_map}) on labeled scanner-backed findings."
            )

    missing_block = "\n".join(f"- {note}" for note in input_notes) if input_notes else "- No required input files were missing."
    return f"""# Evaluation Notes

Run ID: `{run_id}`

## Scope

This evaluation summarizes local SupplyTrace-VEX artifacts. It evaluates prioritization over normalized scanner-backed findings that can be mapped to local testbed actionability labels. It does not fabricate scanner results, vulnerability labels, performance gains, or exploitability claims.

## Input Status

{missing_block}

- Normalized finding rows: {finding_count}
- Labeled scanner-backed findings used for metric denominators: {labeled_count}
- Scanner metadata rows: {len(scanner_metadata)}
- Scanner unavailable rows: {unavailable}
- Scanner failed rows: {failed}
- Scanner skipped-not-applicable rows: {skipped}

## Result Interpretation

{best_line}
{zero_finding_warning}

False-positive reduction is computed only against labeled scanner-backed findings by comparing the proposed retain/drop decision with a raw-scanner retain-all baseline. If no labeled findings exist, classification and ranking metrics are marked `not_available`.

## Evidence Completeness

Mean evidence completeness score: {mean_completeness}

The completeness score records whether expected evidence fields are present. It is not a measure of vulnerability truth or exploitability.

## Limitations

- Ground truth describes intended project-context actionability for controlled local cases; it is not universal CVE truth.
- Scanner coverage depends on installed local tools and their databases.
- Missing scanner outputs remain part of the evaluation evidence and are not replaced with synthetic findings.
- Static reachability can miss dynamic imports, reflection, generated code, framework dispatch, and runtime-only behavior.
- VEX-style statuses are project-evidence records, not official vendor VEX attestations.
- Reported comparisons are descriptive. A method is not described as improved unless the generated metrics support that claim.
"""


def evaluate_run(context: RunContext) -> dict[str, Any]:
    """Run all evaluation experiments and write reproducible CSV/Markdown outputs."""

    paths = _input_paths(context)
    input_notes = _missing_input_notes(paths)
    ground_truth_rows = _read_csv(paths["ground_truth"])
    findings = _read_csv(paths["normalized_findings"])
    reachability_rows = _read_csv(paths["reachability_matrix"])
    risk_score_rows = _read_csv(paths["risk_scores"])
    baseline_input_rows = _read_csv(paths["baseline_rankings"])
    vex_rows = _read_csv(paths["vex_summary"])
    scanner_metadata = _read_csv(paths["scanner_execution_metadata"])

    items = build_evaluation_items(
        findings,
        ground_truth_rows,
        reachability_rows,
        risk_score_rows,
        vex_rows,
    )
    scoped_labeled_items = labeled_items(items)
    binary = compare_binary_methods(items)
    binary["items"] = items

    proposed_ranked = proposed_ranking(items)
    rankings = {"proposed_full_model": proposed_ranked}
    rankings.update(baseline_rankings(items, baseline_input_rows))
    for method in EXPECTED_BASELINE_METHODS:
        rankings.setdefault(method, [])
    baseline_rows = [ranking_quality(method, ranked) for method, ranked in sorted(rankings.items())]
    topk_rows = _topk_rows(rankings)
    scanner_rows = scanner_disagreement_rows(items)
    scanner_summary = scanner_disagreement_summary(items)
    ablation_rows = run_ablation(items, context.config.scoring_weights)
    runtime_rows = _runtime_summary_rows(scanner_metadata)
    completeness_rows = _evidence_completeness_rows(items)

    metrics_rows = _metrics_from_binary(binary)
    metrics_rows.extend(
        [
            _metric_row("E1", "raw_scanner", "raw_finding_count", len(findings), status="ok"),
            _metric_row("E3", "proposed_full_model", "top5_actionability", next((row["top5_actionability"] for row in baseline_rows if row["method"] == "proposed_full_model"), 0.0), status=next((row["status"] for row in baseline_rows if row["method"] == "proposed_full_model"), "not_available")),
            _metric_row("E3", "proposed_full_model", "top10_actionability", next((row["top10_actionability"] for row in baseline_rows if row["method"] == "proposed_full_model"), 0.0), status=next((row["status"] for row in baseline_rows if row["method"] == "proposed_full_model"), "not_available")),
            _metric_row("E3", "proposed_full_model", "ndcg", next((row["ndcg"] for row in baseline_rows if row["method"] == "proposed_full_model"), 0.0), status=next((row["status"] for row in baseline_rows if row["method"] == "proposed_full_model"), "not_available")),
            _metric_row("E3", "proposed_full_model", "map", next((row["map"] for row in baseline_rows if row["method"] == "proposed_full_model"), 0.0), status=next((row["status"] for row in baseline_rows if row["method"] == "proposed_full_model"), "not_available")),
            _metric_row("E4", "scanner_evidence", "scanner_overlap", scanner_summary["scanner_overlap"], numerator=scanner_summary["multi_scanner_findings"], denominator=scanner_summary["finding_count"], status="ok" if items else "not_available"),
            _metric_row("E4", "scanner_evidence", "scanner_disagreement_rate", scanner_summary["scanner_disagreement_rate"], numerator=scanner_summary["scanner_disagreement_count"], denominator=len(items), status="ok" if items else "not_available"),
            _metric_row("E6", "scanner_runtime", "runtime_per_case_mean", round(sum(float(row["total_duration_seconds"]) for row in runtime_rows) / len(runtime_rows), 6) if runtime_rows else 0.0, denominator=len(runtime_rows), status="ok" if runtime_rows else "not_available"),
            _metric_row("E7", "evidence", "evidence_completeness_score_mean", round(sum(float(row["evidence_completeness_score"]) for row in completeness_rows) / len(completeness_rows), 6) if completeness_rows else 0.0, denominator=len(completeness_rows), status="ok" if completeness_rows else "not_available"),
        ]
    )

    output_dir = context.config.artifacts_dir / "evaluation"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_paths = {
        "metrics_summary": output_dir / "metrics_summary.csv",
        "baseline_comparison": output_dir / "baseline_comparison.csv",
        "scanner_disagreement": output_dir / "scanner_disagreement.csv",
        "ablation_results": output_dir / "ablation_results.csv",
        "runtime_summary": output_dir / "runtime_summary.csv",
        "evidence_completeness": output_dir / "evidence_completeness.csv",
        "topk_comparison": output_dir / "topk_comparison.csv",
        "evaluation_notes": output_dir / "evaluation_notes.md",
    }
    _write_csv(output_paths["metrics_summary"], metrics_rows, METRICS_SUMMARY_FIELDS)
    _write_csv(output_paths["baseline_comparison"], baseline_rows, BASELINE_COMPARISON_FIELDS)
    _write_csv(output_paths["scanner_disagreement"], scanner_rows, SCANNER_DISAGREEMENT_FIELDS)
    _write_csv(output_paths["ablation_results"], ablation_rows, ABLATION_FIELDS)
    _write_csv(output_paths["runtime_summary"], runtime_rows, RUNTIME_FIELDS)
    _write_csv(output_paths["evidence_completeness"], completeness_rows, EVIDENCE_COMPLETENESS_FIELDS)
    _write_csv(output_paths["topk_comparison"], topk_rows, TOPK_FIELDS)

    notes = _notes_markdown(
        run_id=context.run_id,
        input_notes=input_notes,
        finding_count=len(findings),
        labeled_count=len(scoped_labeled_items),
        scanner_metadata=scanner_metadata,
        binary=binary,
        baseline_rows=baseline_rows,
        completeness_rows=completeness_rows,
    )
    output_paths["evaluation_notes"].write_text(notes, encoding="utf-8")

    status = "completed"
    if input_notes or not findings or not scoped_labeled_items:
        status = "completed_with_missing_or_insufficient_data"
    rel = lambda path: to_project_relative_path(path, context.config) or str(path)
    payload = {
        "run_id": context.run_id,
        "status": status,
        "finding_count": len(findings),
        "labeled_finding_count": len(scoped_labeled_items),
        "scanner_metadata_count": len(scanner_metadata),
        "input_warnings": input_notes,
        "outputs": {name: rel(path) for name, path in output_paths.items()},
        "metrics": {
            "binary": {key: value for key, value in binary.items() if key != "items"},
            "scanner_disagreement": scanner_summary,
        },
        "claim_scope": (
            "Evaluation metrics are computed only from generated local artifacts. "
            "Missing findings, missing scanner outputs, and unlabeled rows are reported rather than inferred."
        ),
    }
    write_json(output_dir / "evaluation_summary.json", payload)
    run_output_dir = context.run_dir("evaluation")
    write_json(run_output_dir / "metrics.json", payload)
    return payload
