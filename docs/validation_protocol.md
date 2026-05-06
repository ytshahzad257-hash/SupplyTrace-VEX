# Validation Protocol

This protocol describes how to validate a SupplyTrace-VEX run without fabricating results or overstating evidence.

## Ground Truth Definition

Ground truth is stored in `testbed/ground_truth/ground_truth.csv` and `testbed/ground_truth/ground_truth.json`. It defines intended project-context labels for generated local cases:

- `actionable`
- `non_actionable`
- `fixed`
- `clean`
- `unknown_until_scanned`

These labels describe the designed local context of the testbed. They do not assert scanner-confirmed vulnerability presence and do not define universal CVE truth.

## Expected Versus Scanner-Confirmed Vulnerabilities

Case metadata uses expected fields such as `vulnerable_package_expected` and `vulnerable_version_expected`. These fields describe the package under study for a local fixture before scanner execution.

A vulnerability is scanner-confirmed only when a real scanner produces raw output and the normalizer creates a corresponding finding under `artifacts/normalized/`. Documentation and reports must distinguish expected fixture design from scanner-confirmed evidence.

## Required Validation Checks

Run:

```bash
python -m pytest
python -m supplytrace --help
python -m supplytrace run-all --run-id validation-local
python -m supplytrace report --run-id validation-local
python -m supplytrace evidence-check --run-id validation-local
python -m supplytrace audit --run-id validation-local
```

Then verify:

- `testbed/cases/` contains 50 generated cases.
- Every case contains `metadata.json`.
- `testbed/ground_truth/ground_truth.csv` and `.json` exist.
- `artifacts/sbom/internal/` contains one internal fallback SBOM per case.
- External SBOM files exist only when real external tool output was validated.
- `artifacts/scanner_raw/scanner_execution_metadata.csv` includes success, failure, unavailable, or skipped rows for each scanner/case decision.
- `artifacts/normalized/normalization_warnings.csv` records missing fields instead of hiding them.
- `artifacts/reachability/reachability_matrix.csv` documents static-analysis status and evidence reasons.
- `artifacts/evaluation/evaluation_notes.md` explains missing metrics or insufficient data.
- `artifacts/audit/evidence_readiness_report.md` states whether paper-result claims are supported.
- `artifacts/reports/report.md`, `report.html`, table CSVs, and figure data exist after `report`.

## Missing Tool Behavior

Missing tools are valid reproducibility evidence. If a scanner or SBOM tool is not installed, the pipeline must record an unavailable status and continue without creating fake output. Missing tool records should be cited as part of the run environment.

## Reproducibility Checks

Use a stable run ID for publication artifacts. Record:

- CLI commands used.
- Python version.
- External scanner availability and versions.
- Docker image build context if Docker was used.
- Generated artifact paths.
- Any unavailable metrics and the reason they are unavailable.
- Evidence-readiness score and blocking issues.
- Publication-readiness score and final recommendation.

No result should be reported in a manuscript unless the corresponding JSON, CSV, Markdown, HTML, log, or test output exists.

If normalized findings are zero, validation must confirm that `evidence-check`, `report.md`, and `docs/manuscript_support.md` warn against prioritization-improvement claims.
