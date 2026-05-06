# Agent Instructions for SupplyTrace-VEX

These instructions apply to future Codex and coding-agent sessions in this repository.

## Research Integrity

- Never fabricate scanner output, vulnerability findings, datasets, labels, expert review, metrics, tables, figures, or claims.
- Never convert an expected testbed package into a scanner-confirmed vulnerability unless raw scanner output and normalized findings support it.
- Never claim exploitability, prioritization improvement, scanner coverage, or external validation without generated evidence.
- Do not add claims about AI detection, plagiarism scores, or unsupported publication quality.

## Safety Scope

- Never scan external targets or third-party systems.
- Scanner adapters must run only against generated local testbed paths or local Docker images.
- Do not introduce exploit payloads, malware, credential theft, persistence, evasion, or offensive automation.
- Preserve remote-target blocking in subprocess execution.

## Artifact Contracts

Preserve these stable output paths unless the user explicitly requests a breaking change:

- `testbed/cases/`
- `testbed/ground_truth/ground_truth.csv`
- `artifacts/sbom/`
- `artifacts/scanner_raw/`
- `artifacts/normalized/`
- `artifacts/reachability/`
- `artifacts/evaluation/`
- `artifacts/vex/`
- `artifacts/reports/`
- `artifacts/figures_data/`
- `artifacts/audit/`

Reports and manuscript text must state missing data clearly instead of filling gaps with synthetic values.

## CLI Stability

Keep these commands available:

- `build-testbed`
- `generate-sbom`
- `run-scans`
- `normalize`
- `analyze-reachability`
- `score`
- `generate-vex`
- `evaluate`
- `report`
- `evidence-check`
- `audit`
- `run-all`

If command behavior changes, update README, docs, scripts, Docker usage, tests, and CI together.

## Development Expectations

- Keep modules small, typed where practical, and testable.
- Prefer structured JSON, CSV, Markdown, and HTML artifacts over console-only output.
- Use existing helpers for config, run contexts, safe subprocess execution, artifact paths, and JSON writing.
- Preserve deterministic generation where tests rely on stable output.
- Avoid unresolved work markers in production paths.

## Verification Before Finishing

Before reporting completion, run:

```bash
python -m compileall supplytrace
python -m pytest
python -m supplytrace --help
python -m supplytrace evidence-check --run-id <run-id>
```

When relevant, also run the CLI command affected by the change. If a tool is missing, report the missing tool honestly and cite the metadata file that records it.

## Documentation Tone

Use original, professional, evidence-bounded wording. Do not overclaim. Static reachability is contextual evidence, VEX-style output is project evidence, and evaluation metrics are meaningful only when generated artifacts support them.
