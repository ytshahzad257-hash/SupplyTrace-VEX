# Methodology

SupplyTrace-VEX treats vulnerability prioritization as an evidence composition problem. Each pipeline stage writes machine-readable artifacts so that a research claim can be traced to generated files.

## Testbed Design

The testbed generator creates 50 local cases under `testbed/cases/`. Cases cover Node.js, Python, and container-oriented fixtures. The categories are:

- `vulnerable_reachable_direct`
- `vulnerable_unreachable_direct`
- `vulnerable_reachable_transitive`
- `vulnerable_dev_only`
- `patched_dependency`
- `container_vulnerable_layer`
- `clean_control`

Each case includes `metadata.json`, source files, a dependency manifest, and a README. The metadata records intended project-context actionability labels. These labels are not scanner-confirmed vulnerability findings and do not assert universal CVE truth.

## SBOM Generation

SBOM generation starts from local manifests such as `package.json`, `package-lock.json`, `requirements.txt`, and container fixture metadata. SupplyTrace-VEX always writes an internal fallback SBOM marked as `internal_fallback`.

CycloneDX-style and SPDX-style files are generated only when an external tool produces real valid output. If the tool is unavailable or fails, the pipeline records that status in `artifacts/sbom/sbom_generation_metadata.csv` and does not create fake external SBOM files.

## Scanner Adapters

Scanner adapters wrap OSV-Scanner, Trivy, Grype, npm audit, and pip-audit. Each adapter checks tool availability, captures version information when possible, runs only against local generated case paths or local images, and writes execution metadata for success, failure, unavailable, or skipped-not-applicable outcomes.

The scanner layer does not install tools during a scan and does not target remote URLs. Missing tools are part of the experimental evidence.

## Normalization

Raw scanner JSON is normalized into a shared finding schema. The normalizer preserves scanner names, package/version fields, vulnerability identifiers, severity/CVSS values when supplied, fixed versions when supplied, raw scanner output paths, and normalization notes.

If a field is absent, the normalizer uses `null` or `unknown` and writes a warning. It does not infer severity, CVSS, fixed versions, or advisory data that the scanner did not provide.

## Reachability Analysis

Reachability analysis is static. Python files are parsed with AST import extraction, and JavaScript files are parsed for `import` and `require()` patterns. The analyzer maps observed imports to manifest-declared packages when possible and classifies dependencies as reachable, imported but not called, declared but unused, development-only, transitive-only, or unknown.

The analysis does not execute project code. Dynamic imports, reflection, generated code, framework wiring, and runtime configuration are treated conservatively and can lead to `unknown`.

## Risk Scoring

Risk scoring combines scanner-native severity or CVSS with local context fields such as reachability, runtime/development scope, direct/transitive relationship, container context, exposed service evidence, fixed-version evidence, scanner agreement, and evidence completeness.

Scores are configurable heuristics for defensive prioritization. They do not prove exploitability. Baseline rankings are generated for comparison, including severity-only, CVSS-only, scanner-native priority, direct-dependency-first, runtime-dependency-first, and reachability-only variants.

## VEX-Style Status Generation

SupplyTrace-VEX generates project-evidence-based VEX-style status records for normalized findings. Supported statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`.

These statuses are local research outputs. They are not vendor-certified VEX attestations. If reachability or scanner evidence is incomplete, the generator uses `under_investigation` rather than overclaiming.

## Evaluation Design

Evaluation joins ground-truth case labels, normalized scanner findings, reachability evidence, risk scores, baseline rankings, VEX summaries, and scanner execution metadata. Metrics are computed only when scanner-backed findings can be mapped to local labels.

The evaluation layer produces precision, recall, F1, false-positive reduction, actionable findings retained, top-k actionability, NDCG, MAP, scanner overlap, disagreement rate, runtime per case, evidence completeness, and ablation outputs when the data supports them.

If findings, labels, or scanner outputs are missing, evaluation files still exist and state that metrics are unavailable. Missing data is not converted into synthetic results.

## Evidence Readiness Gate

The `evidence-check` command measures whether a run can support paper-result claims. It checks scanner availability, scanner successes, raw scanner outputs, normalized findings, risk scores, VEX-style records, real metric availability, external SBOM generation, report generation, Docker status when detectable, and Git cleanliness when repository metadata is present. If normalized findings are zero, readiness is capped and the report explicitly states that prioritization-improvement claims are unsupported.
