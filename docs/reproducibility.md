# Reproducibility

SupplyTrace-VEX is designed so that every research claim can be tied to generated artifacts.

## Clean Clone Instructions

From a clean checkout:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
```

## Docker Instructions

```bash
docker compose build
RUN_ID=docker-repro-001 docker compose run --rm run-all
RUN_ID=docker-repro-001 docker compose run --rm report
RUN_ID=docker-repro-001 docker compose run --rm evidence-check
```

Generated artifacts are mounted into the host `artifacts/` and `testbed/` directories.

## Recommended Local Run

```bash
python -m supplytrace run-all --run-id repro-001
python -m supplytrace report --run-id repro-001
python -m supplytrace evidence-check --run-id repro-001
python -m supplytrace audit --run-id repro-001
```

Use a stable run ID for publication artifacts. The run ID appears in run-scoped compatibility directories such as `artifacts/audit/<run_id>/` and `artifacts/reports/<run_id>/`.

## Expected Outputs

After a full run, review:

- `testbed/ground_truth/ground_truth.csv`
- `artifacts/sbom/sbom_generation_metadata.csv`
- `artifacts/scanner_raw/scanner_execution_metadata.csv`
- `artifacts/normalized/findings_normalized.csv`
- `artifacts/normalized/normalization_warnings.csv`
- `artifacts/reachability/reachability_matrix.csv`
- `artifacts/reachability/context_enrichment.csv`
- `artifacts/evaluation/risk_scores.csv`
- `artifacts/evaluation/baseline_comparison.csv`
- `artifacts/evaluation/evaluation_notes.md`
- `artifacts/vex/vex_summary.csv`
- `artifacts/reports/report.md`
- `artifacts/reports/report.html`
- `artifacts/reports/tables/`
- `artifacts/figures_data/`
- `docs/manuscript_support.md`
- `artifacts/audit/<run_id>/tool_versions.json`
- `artifacts/audit/evidence_readiness_report.md`
- `artifacts/audit/publication_readiness_score.csv`

If a file exists but contains only headers, that is still evidence. It usually means the current run did not produce scanner-backed rows for that stage.

## Tool Version Capture

Use:

```bash
python -m supplytrace audit --run-id repro-001
```

The audit command captures Python and scanner tool availability/version information. Missing tools are recorded honestly as unavailable.

## How To Verify Results

1. Run `python -m pytest`.
2. Run `python -m supplytrace --help`.
3. Confirm generated testbed case count is 50.
4. Confirm scanner metadata includes every scanner/case decision.
5. Confirm external SBOM files are present only when real external tool output exists.
6. Confirm normalized findings reference raw scanner output paths.
7. Confirm evaluation notes explain missing or unavailable metrics.
8. Confirm report and manuscript support do not claim improvement unless metrics support it.
9. Confirm `python -m supplytrace evidence-check --run-id <id>` reports whether paper-result claims are supported.
10. If normalized findings are zero, confirm the readiness score is capped and the manuscript warning remains visible.

## Reproducibility Boundaries

Scanner databases and installed tool versions can change results. SupplyTrace-VEX records tool metadata and does not hide missing scanners. VEX-style status files are generated only from local normalized findings, reachability evidence, context enrichment, and risk scores. They are project-evidence records, not official vendor VEX claims.
