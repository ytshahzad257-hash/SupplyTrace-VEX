# Final Publication-Readiness Audit

Run ID: `vscode-check`

Generated at: 2026-05-06T18:54:40.431834+00:00

- publication_readiness_score_out_of_10: 5.0
- final_recommendation: not_ready_for_paper_results
- evidence_readiness_score_out_of_10: 10.0
- ready_for_paper_results: no

## Exact Commands Checked By Audit

- `python -m pytest -q`
- `git status --short` when a `.git` directory is present
- local tool version commands for Python, Node.js, npm, pip-audit, OSV-Scanner, Trivy, Grype, Syft, CycloneDX, pytest, and Docker

The full pipeline commands are expected to be run before audit; this command verifies the artifacts they produce.

## Pass/Fail Checks

| ID | Check | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| A01 | pytest | pass | python -m pytest -q | executed by audit unless disabled |
| A02 | required artifact folders | pass | artifacts |  |
| A03 | scanner metadata | pass | rows=250 |  |
| A04 | no third-party scanner targets | pass | remote rows=0 | scanner command metadata searched for URL/SSH/git markers |
| A05 | no fake scanner outputs | pass | unreferenced scanner JSON=0 | only adapter case JSON files are checked |
| A06 | documentation complete | pass | all required docs exist |  |
| A07 | unsupported claim scan | pass | hits=0 |  |
| A08 | evidence readiness | fail | no | score=10.0 |

## Evidence Summary

- Normalized findings: 167
- Risk scores: 167
- VEX summary rows: 167
- Real comparison metric rows: 15
- Scanner success count: 44
- External SBOM count: 21

## Blocking Issues

- None

## Non-Blocking Warnings

- Docker is not verified in this environment: unavailable
- GitHub cleanliness is not verified: dirty_or_unavailable

## Tool Availability

| Tool | Available | Version | Notes |
| --- | --- | --- | --- |
| python | True | Python 3.13.12 |  |
| node | True | v22.22.0 |  |
| npm | True | 10.9.4 |  |
| pip-audit | True | pip-audit 2.10.0 |  |
| osv-scanner | False |  | not found on PATH |
| trivy | False |  | not found on PATH |
| grype | False |  | not found on PATH |
| syft | False |  | not found on PATH |
| cyclonedx-py | False |  | Command '('E:\\Publication\\Projects\\03_01\\supplytrace-vex 01\\.venv\\Scripts\\python.exe', '-m', 'cyclonedx_py', '--version')' returned non-zero exit status 1. |
| pytest | True | pytest 9.0.3 |  |
| docker | False |  | not found on PATH |

## Documentation Status

all required documentation files are present

## Unsupported Claim Scan

- No unsupported-claim pattern hits.

## Final Recommendation

not_ready_for_paper_results. Do not make paper-result claims unless `ready_for_paper_results` is `yes` and the generated metrics support the specific claim.
