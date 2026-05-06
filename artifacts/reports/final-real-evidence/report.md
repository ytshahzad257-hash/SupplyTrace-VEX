# SupplyTrace-VEX Research Artifact Report

Run ID: `final-real-evidence`

## Project Overview

SupplyTrace-VEX is a defensive software supply-chain research artifact for local, reproducible vulnerability prioritization. It combines generated local testbed cases, SBOM evidence, local scanner outputs, normalized findings, static dependency reachability, contextual scoring, VEX-style status generation, and evaluation artifacts.

This report does not assert scanner findings, performance improvements, or exploitability unless the referenced local artifacts support those statements.


## Research Questions

1. How much vulnerability-evidence data is available from local scanners for the generated testbed cases?
2. How does static dependency reachability change the interpretation of scanner-backed findings?
3. How does the proposed SupplyTrace-VEX ranking compare with baseline rankings when labeled scanner-backed findings exist?
4. Where do scanner availability, scanner overlap, and evidence completeness limit prioritization claims?

## Methodology Summary

The pipeline builds local testbed cases, generates SBOM files, runs configured scanners against local targets, normalizes scanner JSON, analyzes source reachability without executing project code, scores findings with configurable evidence weights, generates VEX-style project evidence records, evaluates against local labels when possible, and emits reproducible report artifacts.

## Input Status

No required reporting inputs were missing.

## Scanner Status

| Scanner execution status | Rows |
| --- | --- |
| skipped_not_applicable | 27 |
| success | 23 |
| unavailable | 200 |

## SBOM Summary

| SBOM output | Generated files |
| --- | --- |
| internal_fallback | 50 |
| cyclonedx_real_tool_output | 0 |
| spdx_real_tool_output | 0 |

## Normalized Findings Summary

- Normalized finding rows: 67
- Normalization summary status: Normalized findings are derived only from raw local scanner JSON. Missing fields are represented as null or unknown and recorded in normalization_warnings.csv.
- Zero-finding warning: False

## Reachability Summary

- Reachability dependency rows: 58
- Reachability summary: Reachability evidence is limited to local static analysis and does not claim exploitability.

| Reachability status | Dependencies |
| --- | --- |
| declared_not_used | 11 |
| dev_only | 7 |
| reachable | 26 |
| transitive_only | 8 |
| unknown | 6 |

## Risk Scoring Summary

- Risk score rows: 67
- Precision: 0.5 (ok)
- Recall: 0.857143 (ok)
- F1: 0.631579 (ok)
- False-positive reduction: 0.225806 (ok)

Scores rank defensive actionability evidence. They do not prove exploitability.

## VEX Summary

- VEX-style record rows: 67
- VEX status distribution rows: 4

Generated VEX-style statuses are project-evidence records, not official vendor VEX attestations.

## Evaluation Metrics

- Ground-truth case rows: 50
- Normalized findings available for evaluation: 67
- Paper-result claims supported: review generated metrics before claiming
- Proposed MAP: 0.547557 (ok)
- Proposed NDCG: 0.81359 (ok)
- Evidence completeness mean: 0.777778 (ok)

## Baseline Comparison

| Method | Labeled | Top-5 | Top-10 | NDCG | MAP | Status |
| --- | --- | --- | --- | --- | --- | --- |
| cvss_only | 59 | 0.0 | 0.1 | 0.669057 | 0.416345 | ok |
| direct_dependency_first | 59 | 0.2 | 0.2 | 0.681992 | 0.39746 | ok |
| proposed_full_model | 59 | 0.4 | 0.4 | 0.81359 | 0.547557 | ok |
| reachability_only | 59 | 0.6 | 0.6 | 0.882123 | 0.645782 | ok |
| runtime_dependency_first | 59 | 0.4 | 0.3 | 0.741908 | 0.467429 | ok |
| scanner_native_priority | 59 | 0.0 | 0.1 | 0.669057 | 0.416345 | ok |
| severity_only | 59 | 0.0 | 0.2 | 0.683113 | 0.439802 | ok |

## Ablation Study

| Variant | Top-5 | Top-10 | NDCG | MAP | Status |
| --- | --- | --- | --- | --- | --- |
| full_model | 0.4 | 0.4 | 0.81359 | 0.547557 | ok |
| no_reachability | 0.0 | 0.1 | 0.669057 | 0.416345 | ok |
| no_dependency_scope | 0.4 | 0.6 | 0.833784 | 0.567001 | ok |
| no_scanner_agreement | 0.4 | 0.6 | 0.833784 | 0.567001 | ok |
| severity_only | 0.0 | 0.1 | 0.669057 | 0.416345 | ok |
| context_only | 0.6 | 0.6 | 0.890673 | 0.679501 | ok |

## Paper-Ready Tables

| File | Table | Path |
| --- | --- | --- |
| table_01_testbed_taxonomy.csv | Testbed Case Taxonomy | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_01_testbed_taxonomy.csv |
| table_02_scanner_tool_capability_matrix.csv | Scanner Tool Capability Matrix | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_02_scanner_tool_capability_matrix.csv |
| table_03_ground_truth_label_distribution.csv | Ground Truth Label Distribution | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_03_ground_truth_label_distribution.csv |
| table_04_normalized_finding_schema.csv | Normalized Finding Schema | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_04_normalized_finding_schema.csv |
| table_05_risk_scoring_factors.csv | Risk Scoring Factors | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_05_risk_scoring_factors.csv |
| table_06_baseline_comparison_results.csv | Baseline Comparison Results | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_06_baseline_comparison_results.csv |
| table_07_scanner_disagreement_matrix.csv | Scanner Disagreement Matrix | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_07_scanner_disagreement_matrix.csv |
| table_08_ablation_study_results.csv | Ablation Study Results | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_08_ablation_study_results.csv |
| table_09_runtime_summary.csv | Runtime Summary | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_09_runtime_summary.csv |
| table_10_limitations.csv | Limitations and Validity Threats | E:\Publication\Projects\03\supplytrace-vex\artifacts\reports\tables\table_10_limitations.csv |

## Figure-Ready Data

| File | Path |
| --- | --- |
| architecture_mermaid.md | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\architecture_mermaid.md |
| pipeline_mermaid.md | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\pipeline_mermaid.md |
| scanner_overlap.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\scanner_overlap.csv |
| risk_distribution.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\risk_distribution.csv |
| topk_actionability.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\topk_actionability.csv |
| alert_reduction.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\alert_reduction.csv |
| vex_status_distribution.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\vex_status_distribution.csv |
| ablation_chart_data.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\ablation_chart_data.csv |
| runtime_chart_data.csv | E:\Publication\Projects\03\supplytrace-vex\artifacts\figures_data\runtime_chart_data.csv |

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
