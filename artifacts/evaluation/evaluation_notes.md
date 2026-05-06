# Evaluation Notes

Run ID: `final-new-chat-complete`

## Scope

This evaluation summarizes local SupplyTrace-VEX artifacts. It evaluates prioritization over normalized scanner-backed findings that can be mapped to local testbed actionability labels. It does not fabricate scanner results, vulnerability labels, performance gains, or exploitability claims.

## Input Status

- No required input files were missing.

- Normalized finding rows: 167
- Labeled scanner-backed findings used for metric denominators: 143
- Scanner metadata rows: 250
- Scanner unavailable rows: 150
- Scanner failed rows: 0
- Scanner skipped-not-applicable rows: 56

## Result Interpretation

The proposed ranking MAP (0.458853) did not exceed the best available baseline (reachability_only: 0.498147) on labeled scanner-backed findings.


False-positive reduction is computed only against labeled scanner-backed findings by comparing the proposed retain/drop decision with a raw-scanner retain-all baseline. If no labeled findings exist, classification and ranking metrics are marked `not_available`.

## Evidence Completeness

Mean evidence completeness score: 0.822355

The completeness score records whether expected evidence fields are present. It is not a measure of vulnerability truth or exploitability.

## Limitations

- Ground truth describes intended project-context actionability for controlled local cases; it is not universal CVE truth.
- Scanner coverage depends on installed local tools and their databases.
- Missing scanner outputs remain part of the evaluation evidence and are not replaced with synthetic findings.
- Static reachability can miss dynamic imports, reflection, generated code, framework dispatch, and runtime-only behavior.
- VEX-style statuses are project-evidence records, not official vendor VEX attestations.
- Reported comparisons are descriptive. A method is not described as improved unless the generated metrics support that claim.
