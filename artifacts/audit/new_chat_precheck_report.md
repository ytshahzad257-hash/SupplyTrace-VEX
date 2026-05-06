# New Chat Precheck Report

Run ID: `new-chat-precheck`

This report records the initial continuation-state inspection for the new-chat handoff. It was recreated from command logs after workspace recovery; the final audit artifacts for `final-new-chat-complete` supersede this precheck for publication decisions.

## Command Status

| Check | Status | Notes |
| --- | --- | --- |
| `python -m pytest -q` | pass after dependency setup | The first sandboxed attempt lacked test/runtime dependencies. After installing the project dependencies in the active Python environment, the test suite passed. |
| `python -m supplytrace --help` | pass | CLI entry point was present and usable. |
| `python -m supplytrace debug-evidence --run-id new-chat-precheck` | pass | Diagnostic command existed and generated an audit report. |
| `python -m supplytrace evidence-check --run-id new-chat-precheck` | pass | Evidence-readiness command existed and generated summary artifacts. |
| `python -m supplytrace audit --run-id new-chat-precheck` | pass | Publication audit command existed and generated summary artifacts. |

## Evidence Snapshot

| Metric | Precheck Value | Notes |
| --- | ---: | --- |
| Scanner availability by tool | npm available; pip-audit initially unavailable; OSV-Scanner unavailable; Trivy unavailable; Grype unavailable; Syft unavailable | Availability was environment-specific and reported rather than inferred. |
| Scanner success count by tool | npm audit: 23; pip-audit: 0; OSV: 0; Trivy: 0; Grype: 0 | Only npm audit had successful scanner runs at precheck. |
| Raw scanner file count | 23 | Raw npm audit JSON files existed. |
| Normalized findings count | 67 | Normalized rows came from scanner-backed npm audit output. |
| `package_version` missing count | 67 | Precheck normalization still lacked package-version recovery for npm audit findings. |
| Risk score count | 67 | Risk scoring rows matched the normalized findings then present. |
| VEX row count | 67 | VEX-style rows were generated only from normalized findings. |
| Real metric count | 15 | Metrics existed where generated evidence supported them. |
| External SBOM count | 0 | External SBOM tooling was not yet producing standard SBOMs. |
| Proposed model vs baselines | proposed contextual model underperformed reachability-only on MAP | Precheck values showed proposed MAP about `0.547557` versus reachability-only MAP about `0.645782`; claims needed limitation. |
| Evidence readiness score | 4/10 | Blocked by weak evidence completeness, one-scanner evidence, missing package versions, and external SBOM absence. |
| Publication readiness score | 4/10 | Not publication-ready at precheck. |

## Blockers Observed

- Only npm audit was producing successful scanner evidence.
- pip-audit, OSV-Scanner, Trivy, Grype, and Syft were unavailable or not yet integrated successfully.
- External SBOM generation was not producing standard external SBOM artifacts.
- `package_version` was missing for normalized findings.
- Some artifact references contained absolute Windows paths.
- Docker execution was not verified.
- The proposed contextual model did not outperform the reachability-only baseline in that precheck state.
- The release package still needed cleanup hardening and clearer publication-readiness wording.

## Continuation Decision

The project was safe to continue without rebuilding the foundation. The existing folder structure, CLI, tests, scanner pipeline, normalization, scoring, VEX generation, evaluation, reporting, and audit commands were present; the correct next step was targeted remediation rather than a restart.
