# Manuscript Support

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

Software dependency scanners can produce vulnerability evidence without the project context needed for defensive prioritization. SupplyTrace-VEX provides a local, reproducible research artifact that connects generated testbed cases, SBOM evidence, scanner outputs, static dependency reachability, context enrichment, heuristic scoring, VEX-style status records, and evaluation tables. In the current generated artifact set, the repository contains 50 ground-truth case rows, 250 scanner execution metadata rows, 167 normalized scanner finding rows, and 167 risk score rows. The abstract should report only the generated evaluation metrics shown in artifacts/evaluation. The artifact emphasizes auditability: missing tools, absent findings, and unavailable metrics are reported directly rather than replaced with fabricated results.


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

- Normalized scanner finding rows: 167
- Risk score rows: 167
- VEX-style summary rows: 167
- Scanner execution metadata rows: 250
- Paper-result claims currently supported: only claims directly supported by generated metrics
- Proposed model vs reachability-only: The proposed contextual model did not outperform the reachability-only baseline in this run; claims must be limited to evidence-backed observations.

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

| File | Table | Path |
| --- | --- | --- |
| table_01_testbed_taxonomy.csv | Testbed Case Taxonomy | artifacts/reports/tables/table_01_testbed_taxonomy.csv |
| table_02_scanner_tool_capability_matrix.csv | Scanner Tool Capability Matrix | artifacts/reports/tables/table_02_scanner_tool_capability_matrix.csv |
| table_03_ground_truth_label_distribution.csv | Ground Truth Label Distribution | artifacts/reports/tables/table_03_ground_truth_label_distribution.csv |
| table_04_normalized_finding_schema.csv | Normalized Finding Schema | artifacts/reports/tables/table_04_normalized_finding_schema.csv |
| table_05_risk_scoring_factors.csv | Risk Scoring Factors | artifacts/reports/tables/table_05_risk_scoring_factors.csv |
| table_06_baseline_comparison_results.csv | Baseline Comparison Results | artifacts/reports/tables/table_06_baseline_comparison_results.csv |
| table_07_scanner_disagreement_matrix.csv | Scanner Disagreement Matrix | artifacts/reports/tables/table_07_scanner_disagreement_matrix.csv |
| table_08_ablation_study_results.csv | Ablation Study Results | artifacts/reports/tables/table_08_ablation_study_results.csv |
| table_09_runtime_summary.csv | Runtime Summary | artifacts/reports/tables/table_09_runtime_summary.csv |
| table_10_limitations.csv | Limitations and Validity Threats | artifacts/reports/tables/table_10_limitations.csv |

## Figure List

| File | Path |
| --- | --- |
| architecture_mermaid.md | artifacts/figures_data/architecture_mermaid.md |
| pipeline_mermaid.md | artifacts/figures_data/pipeline_mermaid.md |
| scanner_overlap.csv | artifacts/figures_data/scanner_overlap.csv |
| risk_distribution.csv | artifacts/figures_data/risk_distribution.csv |
| topk_actionability.csv | artifacts/figures_data/topk_actionability.csv |
| alert_reduction.csv | artifacts/figures_data/alert_reduction.csv |
| vex_status_distribution.csv | artifacts/figures_data/vex_status_distribution.csv |
| ablation_chart_data.csv | artifacts/figures_data/ablation_chart_data.csv |
| runtime_chart_data.csv | artifacts/figures_data/runtime_chart_data.csv |

## Limitation Language

Static reachability is conservative and can miss runtime behavior. Scanner evidence depends on locally installed tools and their data. Ground truth labels describe the intended context of controlled local cases and do not assert universal CVE truth. Metrics marked `not_available` indicate insufficient generated evidence, not a hidden performance result.

## Ethics Statement

SupplyTrace-VEX is intended for defensive software supply-chain research on generated local cases or local images. It must not be used to scan third-party systems, probe public infrastructure, or make vulnerability claims about real organizations.

## Reproducibility Statement

All claims in a manuscript should cite generated files under `artifacts/`, `testbed/ground_truth/`, or `docs/`. The current reporting input status is: No required reporting inputs were missing. Regenerate the evidence with `python -m supplytrace run-all --run-id <id>` followed by `python -m supplytrace report --run-id <id>`.

## No Unsupported Claims

- Do not claim effectiveness improvement unless `artifacts/evaluation/baseline_comparison.csv` supports it.
- Do not claim scanner-confirmed vulnerabilities unless raw scanner output and normalized findings exist.
- Do not claim official VEX status; generated records are VEX-style project evidence.
- Do not report expert review, external validation, or real-world deployment results unless those artifacts are added explicitly.

## Current Metric Pointers

- Proposed F1: 0.583333 (ok)
- Proposed MAP: 0.458853 (ok)
- Baseline rows: 7
- Ablation rows: 6
