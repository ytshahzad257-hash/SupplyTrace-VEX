# Evidence Readiness Report

Run ID: `vscode-check`

Generated at: 2026-05-06T18:54:40.310436+00:00

- ready_for_paper_results: no
- readiness_score_out_of_10: 10.0

## Blocking Issues

- None

## Warnings

- Docker is not verified in this environment: unavailable
- GitHub cleanliness is not verified: dirty_or_unavailable

## Scanner Status

- Installed scanner tools: 2
- Successful scanner executions: 44
- Raw scanner output files: 44
- Status counts: `{"skipped_not_applicable": 56, "success": 44, "unavailable": 150}`

## Metric Status

- Normalized findings: 167
- Package version missing rows: 0
- Risk scores: 167
- VEX summary rows: 167
- Real comparison metric rows: 15

## Artifact Status

- Reports generated: True
- External SBOM count: 21
- Docker status: unavailable
- Git status: dirty_or_unavailable
- Pytest status: pass

## Supported Claims

- local testbed generation is reproducible
- missing scanner tools are reported in generated metadata
- reports distinguish unavailable evidence from generated evidence

## Unsupported Claims

- Docker execution success in this host environment

## Check Details

| Check | Value | Status | Notes |
| --- | --- | --- | --- |
| ready_for_paper_results | no | fail | requires real scanner-backed findings and metrics |
| readiness_score_out_of_10 | 10.0 | info | score is capped at 5 when normalized findings are zero |
| installed_scanner_count | 2 | pass | npm, pip-audit, OSV, Trivy, and Grype are counted |
| scanner_success_count | 44 | pass | successful local scanner executions |
| scanner_output_file_count | 44 | pass | raw JSON files under scanner adapter directories |
| normalized_finding_count | 167 | pass | must be positive for paper-result claims |
| package_version_missing_count | 0 | pass | missing versions are reported, not invented |
| risk_score_count | 167 | pass | must be positive for scoring claims |
| vex_summary_count | 167 | pass | must be positive for vulnerability-level VEX-style claims |
| real_metric_count | 15 | pass | metrics must be generated from real findings |
| external_sbom_count | 21 | pass | internal fallback SBOMs do not count as external standard SBOM output |
| reports_generated | True | pass | Markdown, HTML, and manuscript support |
| git_cleanliness | dirty_or_unavailable | warning | Command '('C:\\Program Files\\Git\\cmd\\git.EXE', 'status', '--short')' returned non-zero exit status 128. |
| docker_status | unavailable | warning | not found on PATH |
| no_remote_scanner_targets | 0 | pass | scanner metadata command fields checked |
| no_unreferenced_scanner_outputs | 0 | pass | raw case JSON files must be referenced by success metadata |

If normalized findings are zero, this report intentionally caps readiness at 5/10 and marks paper-result claims unsupported.
