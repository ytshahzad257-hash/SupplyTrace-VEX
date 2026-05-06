"""Markdown report and manuscript-support generation."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext

from .figures import FIGURE_OUTPUTS, generate_figure_data
from .tables import TABLE_OUTPUTS, generate_paper_tables, markdown_table, read_csv


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else default


def _artifact_inputs(context: RunContext) -> dict[str, Path]:
    artifacts = context.config.artifacts_dir
    return {
        "ground_truth": context.config.ground_truth_dir / "ground_truth.csv",
        "sbom_metadata": artifacts / "sbom" / "sbom_generation_metadata.csv",
        "scanner_metadata": artifacts / "scanner_raw" / "scanner_execution_metadata.csv",
        "normalized_findings": artifacts / "normalized" / "findings_normalized.csv",
        "normalization_summary": artifacts / "normalized" / "normalization_summary.json",
        "reachability_matrix": artifacts / "reachability" / "reachability_matrix.csv",
        "reachability_summary": artifacts / "reachability" / "reachability_summary.json",
        "risk_scores": artifacts / "evaluation" / "risk_scores.csv",
        "vex_summary": artifacts / "vex" / "vex_summary.csv",
        "vex_distribution": artifacts / "vex" / "vex_status_distribution.csv",
        "metrics_summary": artifacts / "evaluation" / "metrics_summary.csv",
        "baseline_comparison": artifacts / "evaluation" / "baseline_comparison.csv",
        "ablation_results": artifacts / "evaluation" / "ablation_results.csv",
        "evaluation_notes": artifacts / "evaluation" / "evaluation_notes.md",
    }


def _missing_inputs(inputs: dict[str, Path]) -> list[str]:
    return [name for name, path in inputs.items() if not path.exists()]


def _count_by(rows: list[dict[str, str]], field: str) -> dict[str, int]:
    return dict(Counter(row.get(field) or "unknown" for row in rows))


def _metric_lookup(metrics: list[dict[str, str]], metric: str, method: str | None = None) -> str:
    for row in metrics:
        if row.get("metric") == metric and (method is None or row.get("method") == method):
            status = row.get("status") or "unknown"
            value = row.get("value") or "0"
            return f"{value} ({status})"
    return "not_available"


def _scanner_status_summary(scanner_metadata: list[dict[str, str]]) -> str:
    if not scanner_metadata:
        return "Scanner execution metadata is missing or empty."
    counts = _count_by(scanner_metadata, "status")
    rows = [[status, count] for status, count in sorted(counts.items())]
    return markdown_table(["Scanner execution status", "Rows"], rows)


def _scanner_success_by_tool(scanner_metadata: list[dict[str, str]]) -> str:
    if not scanner_metadata:
        return "Scanner execution metadata is missing or empty."
    counts: Counter[str] = Counter()
    for row in scanner_metadata:
        if row.get("status") == "success":
            counts[row.get("scanner_name") or "unknown"] += 1
    rows = [[scanner, count] for scanner, count in sorted(counts.items())]
    return markdown_table(["Scanner", "Successful local runs"], rows or [["none", 0]])


def _model_vs_baseline_note(baseline_rows: list[dict[str, str]]) -> str:
    def value_for(method: str) -> float | None:
        for row in baseline_rows:
            if row.get("method") == method:
                try:
                    return float(row.get("map") or "")
                except ValueError:
                    return None
        return None

    proposed = value_for("proposed_full_model")
    reachability = value_for("reachability_only")
    if proposed is None or reachability is None:
        return "Proposed-vs-baseline comparison is not available for this run."
    if proposed < reachability:
        return "The proposed contextual model did not outperform the reachability-only baseline in this run; claims must be limited to evidence-backed observations."
    return "The proposed contextual model matched or outperformed the reachability-only baseline on MAP in this run; cite generated metrics for exact values."


def _sbom_summary(sbom_metadata: list[dict[str, str]]) -> str:
    if not sbom_metadata:
        return "SBOM generation metadata is missing or empty."
    internal_count = sum(1 for row in sbom_metadata if row.get("internal_tool_status") == "generated")
    cyclonedx_count = sum(1 for row in sbom_metadata if row.get("cyclonedx_tool_status") == "generated")
    spdx_count = sum(1 for row in sbom_metadata if row.get("spdx_tool_status") == "generated")
    return markdown_table(
        ["SBOM output", "Generated files"],
        [
            ["internal_fallback", internal_count],
            ["cyclonedx_real_tool_output", cyclonedx_count],
            ["spdx_real_tool_output", spdx_count],
        ],
    )


def _reachability_summary(reachability_rows: list[dict[str, str]]) -> str:
    if not reachability_rows:
        return "Reachability matrix is missing or empty."
    rows = [[status, count] for status, count in sorted(_count_by(reachability_rows, "reachability_status").items())]
    return markdown_table(["Reachability status", "Dependencies"], rows)


def _baseline_summary(baseline_rows: list[dict[str, str]]) -> str:
    if not baseline_rows:
        return "Baseline comparison metrics are missing or empty."
    rows = [
        [
            row.get("method"),
            row.get("labeled_count"),
            row.get("top5_actionability"),
            row.get("top10_actionability"),
            row.get("ndcg"),
            row.get("map"),
            row.get("status"),
        ]
        for row in baseline_rows[:12]
    ]
    return markdown_table(["Method", "Labeled", "Top-5", "Top-10", "NDCG", "MAP", "Status"], rows)


def _ablation_summary(ablation_rows: list[dict[str, str]]) -> str:
    if not ablation_rows:
        return "Ablation metrics are missing or empty."
    rows = [
        [
            row.get("variant"),
            row.get("top5_actionability"),
            row.get("top10_actionability"),
            row.get("ndcg"),
            row.get("map"),
            row.get("status"),
        ]
        for row in ablation_rows
    ]
    return markdown_table(["Variant", "Top-5", "Top-10", "NDCG", "MAP", "Status"], rows)


def _table_list(table_paths: dict[str, str]) -> str:
    rows = []
    for filename, title in TABLE_OUTPUTS:
        rows.append([filename, title, table_paths.get(filename, "not_generated")])
    return markdown_table(["File", "Table", "Path"], rows)


def _figure_list(figure_paths: dict[str, str]) -> str:
    rows = [[filename, figure_paths.get(filename, "not_generated")] for filename in FIGURE_OUTPUTS]
    return markdown_table(["File", "Path"], rows)


def _summary_payload(context: RunContext, table_paths: dict[str, str], figure_paths: dict[str, str]) -> dict[str, Any]:
    inputs = _artifact_inputs(context)
    ground_truth = read_csv(inputs["ground_truth"])
    sbom_metadata = read_csv(inputs["sbom_metadata"])
    scanner_metadata = read_csv(inputs["scanner_metadata"])
    findings = read_csv(inputs["normalized_findings"])
    reachability = read_csv(inputs["reachability_matrix"])
    risk_scores = read_csv(inputs["risk_scores"])
    vex = read_csv(inputs["vex_summary"])
    vex_distribution = read_csv(inputs["vex_distribution"])
    metrics = read_csv(inputs["metrics_summary"])
    baseline = read_csv(inputs["baseline_comparison"])
    ablation = read_csv(inputs["ablation_results"])
    normalization_summary = _load_json(inputs["normalization_summary"], {})
    reachability_summary = _load_json(inputs["reachability_summary"], {})
    return {
        "inputs": inputs,
        "missing_inputs": _missing_inputs(inputs),
        "ground_truth": ground_truth,
        "sbom_metadata": sbom_metadata,
        "scanner_metadata": scanner_metadata,
        "findings": findings,
        "reachability": reachability,
        "risk_scores": risk_scores,
        "vex": vex,
        "vex_distribution": vex_distribution,
        "metrics": metrics,
        "baseline": baseline,
        "ablation": ablation,
        "normalization_summary": normalization_summary,
        "reachability_summary": reachability_summary,
        "table_paths": table_paths,
        "figure_paths": figure_paths,
    }


def _report_content(context: RunContext, summary: dict[str, Any]) -> str:
    missing = summary["missing_inputs"]
    missing_text = "No required reporting inputs were missing." if not missing else "\n".join(f"- {name}" for name in missing)
    scanner_metadata = summary["scanner_metadata"]
    findings = summary["findings"]
    risk_scores = summary["risk_scores"]
    vex = summary["vex"]
    metrics = summary["metrics"]
    ground_truth = summary["ground_truth"]
    reachability = summary["reachability"]
    sbom_metadata = summary["sbom_metadata"]
    normalization_summary = summary["normalization_summary"]
    reachability_summary = summary["reachability_summary"]
    zero_evidence_warning = (
        "\n> Evidence insufficiency warning: no scanner-confirmed findings were normalized. "
        "Do not claim prioritization improvement because no scanner-confirmed findings were normalized.\n"
        if not findings
        else ""
    )
    package_version_missing = sum(1 for row in findings if row.get("package_version") in (None, "", "unknown"))
    external_sbom_count = sum(int(row.get("external_sbom_count") or 0) for row in sbom_metadata)
    model_note = _model_vs_baseline_note(summary["baseline"])

    return f"""# SupplyTrace-VEX Research Artifact Report

Run ID: `{context.run_id}`

## Project Overview

SupplyTrace-VEX is a defensive software supply-chain research artifact for local, reproducible vulnerability prioritization. It combines generated local testbed cases, SBOM evidence, local scanner outputs, normalized findings, static dependency reachability, contextual scoring, VEX-style status generation, and evaluation artifacts.

This report does not assert scanner findings, performance improvements, or exploitability unless the referenced local artifacts support those statements.
{zero_evidence_warning}

## Research Questions

1. How much vulnerability-evidence data is available from local scanners for the generated testbed cases?
2. How does static dependency reachability change the interpretation of scanner-backed findings?
3. How does the proposed SupplyTrace-VEX ranking compare with baseline rankings when labeled scanner-backed findings exist?
4. Where do scanner availability, scanner overlap, and evidence completeness limit prioritization claims?

## Methodology Summary

The pipeline builds local testbed cases, generates SBOM files, runs configured scanners against local targets, normalizes scanner JSON, analyzes source reachability without executing project code, scores findings with configurable evidence weights, generates VEX-style project evidence records, evaluates against local labels when possible, and emits reproducible report artifacts.

## Input Status

{missing_text}

## Scanner Status

{_scanner_status_summary(scanner_metadata)}

{_scanner_success_by_tool(scanner_metadata)}

## SBOM Summary

{_sbom_summary(sbom_metadata)}

- External SBOM count: {external_sbom_count}

## Normalized Findings Summary

- Normalized finding rows: {len(findings)}
- Package version missing rows: {package_version_missing}
- Normalization summary status: {normalization_summary.get("claim_scope", "not_available")}
- Zero-finding warning: {normalization_summary.get("zero_finding_warning", len(findings) == 0)}

## Reachability Summary

- Reachability dependency rows: {len(reachability)}
- Reachability summary: {reachability_summary.get("claim_scope", "not_available")}

{_reachability_summary(reachability)}

## Risk Scoring Summary

- Risk score rows: {len(risk_scores)}
- Precision: {_metric_lookup(metrics, "precision", "proposed_full_model")}
- Recall: {_metric_lookup(metrics, "recall", "proposed_full_model")}
- F1: {_metric_lookup(metrics, "f1", "proposed_full_model")}
- False-positive reduction: {_metric_lookup(metrics, "false_positive_reduction", "proposed_full_model")}

Scores rank defensive actionability evidence. They do not prove exploitability.

## VEX Summary

- VEX-style record rows: {len(vex)}
- VEX status distribution rows: {len(summary["vex_distribution"])}

These are project-evidence-based VEX-style statuses, not official vendor VEX statements.

## Evaluation Metrics

- Ground-truth case rows: {len(ground_truth)}
- Normalized findings available for evaluation: {len(findings)}
- Paper-result claims supported: {"no" if not findings else "review generated metrics before claiming"}
- Proposed MAP: {_metric_lookup(metrics, "map", "proposed_full_model")}
- Proposed NDCG: {_metric_lookup(metrics, "ndcg", "proposed_full_model")}
- Evidence completeness mean: {_metric_lookup(metrics, "evidence_completeness_score_mean", "evidence")}

## Baseline Comparison

{model_note}

{_baseline_summary(summary["baseline"])}

## Ablation Study

{_ablation_summary(summary["ablation"])}

## Paper-Ready Tables

{_table_list(summary["table_paths"])}

## Figure-Ready Data

{_figure_list(summary["figure_paths"])}

## Limitations

- Static reachability can miss dynamic imports, reflection, generated code, framework dispatch, and runtime-only behavior.
- Scanner outputs depend on tools installed locally and their available databases.
- Missing scanner output is reported as missing or unavailable, not replaced with synthetic findings.
- Ground truth labels describe intended project-context actionability for controlled local cases.
- Metrics marked `not_available` must not be interpreted as zero effectiveness or as evidence of improvement.

## Ethics and Safety Statement

SupplyTrace-VEX is scoped to defensive local research. The project must not be used to scan third-party systems, probe public services, exploit vulnerabilities, or represent generated local cases as measurements from real organizations.

## Reproducibility Instructions

Run the full local pipeline with:

```bash
python -m supplytrace run-all --run-id paper-repro-001
python -m supplytrace report --run-id paper-repro-001
```

Then review `artifacts/reports`, `artifacts/figures_data`, `artifacts/evaluation`, and `docs/manuscript_support.md`.
"""


def _manuscript_support_content(context: RunContext, summary: dict[str, Any]) -> str:
    findings = summary["findings"]
    ground_truth = summary["ground_truth"]
    scanner_metadata = summary["scanner_metadata"]
    risk_scores = summary["risk_scores"]
    baseline = summary["baseline"]
    ablation = summary["ablation"]
    metrics = summary["metrics"]
    missing = summary["missing_inputs"]
    abstract_limit = (
        "The current generated artifacts contain no normalized scanner findings, so the abstract does not claim prioritization improvement."
        if not findings
        else "The abstract should report only the generated evaluation metrics shown in artifacts/evaluation."
    )
    exact_zero_warning = (
        "\nDo not claim prioritization improvement because no scanner-confirmed findings were normalized.\n"
        if not findings
        else ""
    )
    missing_text = "No required reporting inputs were missing." if not missing else "; ".join(missing)
    model_note = _model_vs_baseline_note(baseline)
    return f"""# Manuscript Support

## Journal-Style Project Positioning

SupplyTrace-VEX is positioned as a reproducible applied cybersecurity artifact for studying context-aware software supply-chain vulnerability prioritization. The contribution is the artifact and evidence workflow, not a claim that one scoring model universally outperforms another across real-world software.

## Suggested Title

SupplyTrace-VEX: A Reproducible Local Artifact for Context-Aware Software Supply-Chain Vulnerability Prioritization

## Research Questions

1. How can scanner evidence, SBOM data, and local dependency context be represented in a reproducible prioritization pipeline?
2. How does static dependency reachability change the interpretation of scanner-backed findings in controlled local cases?
3. How do contextual rankings compare with severity-based and scope-based baselines when labeled scanner-backed findings are available?
4. Which evidence gaps limit VEX-style status assignment and evaluation?

## Abstract Draft

Software dependency scanners can produce vulnerability evidence without the project context needed for defensive prioritization. SupplyTrace-VEX provides a local, reproducible research artifact that connects generated testbed cases, SBOM evidence, scanner outputs, static dependency reachability, context enrichment, heuristic scoring, VEX-style status records, and evaluation tables. In the current generated artifact set, the repository contains {len(ground_truth)} ground-truth case rows, {len(scanner_metadata)} scanner execution metadata rows, {len(findings)} normalized scanner finding rows, and {len(risk_scores)} risk score rows. {abstract_limit} The artifact emphasizes auditability: missing tools, absent findings, and unavailable metrics are reported directly rather than replaced with fabricated results.
{exact_zero_warning}

## Contribution Bullets

- A local-only defensive pipeline for SBOM, scanner evidence, reachability, contextual scoring, and VEX-style status generation.
- Deterministic testbed metadata for project-context actionability labels.
- Normalized scanner evidence and evaluation outputs designed for reproducible artifact review.
- Paper-ready tables and figure-ready data derived from generated JSON and CSV files.
- Explicit missing-data reporting for scanner availability, finding coverage, and metric availability.

## Methodology Summary

The methodology uses generated local cases, optional local scanner adapters, manifest-derived SBOM files, static source analysis, and configurable scoring weights. Evaluation is limited to normalized scanner-backed findings that can be mapped to local project-context labels. No external targets are scanned by the reporting layer.

## Artifact Checklist

- `testbed/cases/`
- `testbed/ground_truth/ground_truth.csv`
- `artifacts/sbom/sbom_generation_metadata.csv`
- `artifacts/scanner_raw/scanner_execution_metadata.csv`
- `artifacts/normalized/findings_normalized.csv`
- `artifacts/reachability/reachability_matrix.csv`
- `artifacts/evaluation/risk_scores.csv`
- `artifacts/evaluation/metrics_summary.csv`
- `artifacts/vex/vex_summary.csv`
- `artifacts/reports/report.md`
- `artifacts/reports/report.html`
- `artifacts/audit/<run_id>/tool_versions.json`

## Evidence Checklist

- Normalized scanner finding rows: {len(findings)}
- Risk score rows: {len(risk_scores)}
- VEX-style summary rows: {len(summary["vex"])}
- Scanner execution metadata rows: {len(scanner_metadata)}
- Paper-result claims currently supported: {"no" if not findings else "only claims directly supported by generated metrics"}
- Proposed model vs reachability-only: {model_note}

## Supported Claims

- The repository can generate deterministic local testbed cases.
- The pipeline records missing scanner tools and scanner execution states.
- The reporting layer distinguishes internal fallback SBOMs from external tool output.
- These are project-evidence-based VEX-style statuses, not official vendor VEX statements.

## Unsupported Claims

- Do not claim prioritization improvement unless `artifacts/evaluation/baseline_comparison.csv` supports it.
- Do not claim scanner-confirmed vulnerabilities without raw scanner JSON and normalized finding rows.
- Do not claim Docker success unless Docker commands pass in the target environment.
- Do not claim expert validation or real-world deployment evidence unless those artifacts are added.

## Table List

{_table_list(summary["table_paths"])}

## Figure List

{_figure_list(summary["figure_paths"])}

## Limitation Language

Static reachability is conservative and can miss runtime behavior. Scanner evidence depends on locally installed tools and their data. Ground truth labels describe the intended context of controlled local cases and do not assert universal CVE truth. Metrics marked `not_available` indicate insufficient generated evidence, not a hidden performance result.

## Ethics Statement

SupplyTrace-VEX is intended for defensive software supply-chain research on generated local cases or local images. It must not be used to scan third-party systems, probe public infrastructure, or make vulnerability claims about real organizations.

## Reproducibility Statement

All claims in a manuscript should cite generated files under `artifacts/`, `testbed/ground_truth/`, or `docs/`. The current reporting input status is: {missing_text} Regenerate the evidence with `python -m supplytrace run-all --run-id <id>` followed by `python -m supplytrace report --run-id <id>`.

## No Unsupported Claims

- Do not claim effectiveness improvement unless `artifacts/evaluation/baseline_comparison.csv` supports it.
- Do not claim scanner-confirmed vulnerabilities unless raw scanner output and normalized findings exist.
- Do not claim official VEX status; generated records are VEX-style project evidence.
- Do not report expert review, external validation, or real-world deployment results unless those artifacts are added explicitly.

## Current Metric Pointers

- Proposed F1: {_metric_lookup(metrics, "f1", "proposed_full_model")}
- Proposed MAP: {_metric_lookup(metrics, "map", "proposed_full_model")}
- Baseline rows: {len(baseline)}
- Ablation rows: {len(ablation)}
"""


def generate_markdown_report(context: RunContext) -> dict[str, object]:
    """Generate Markdown report, paper tables, figure data, and manuscript support."""

    table_paths = generate_paper_tables(context)
    figure_paths = generate_figure_data(context)
    summary = _summary_payload(context, table_paths, figure_paths)
    report_content = _report_content(context, summary)
    manuscript_content = _manuscript_support_content(context, summary)

    report_dir = context.config.artifacts_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.md"
    report_path.write_text(report_content, encoding="utf-8")

    run_report_dir = context.run_dir("reports")
    run_report_path = run_report_dir / "report.md"
    run_report_path.write_text(report_content, encoding="utf-8")

    manuscript_path = context.config.project_root / "docs" / "manuscript_support.md"
    manuscript_path.parent.mkdir(parents=True, exist_ok=True)
    manuscript_path.write_text(manuscript_content, encoding="utf-8")

    return {
        "run_id": context.run_id,
        "report_path": to_project_relative_path(report_path, context.config),
        "run_report_path": to_project_relative_path(run_report_path, context.config),
        "manuscript_support_path": to_project_relative_path(manuscript_path, context.config),
        "table_paths": table_paths,
        "figure_paths": figure_paths,
        "missing_inputs": summary["missing_inputs"],
    }
