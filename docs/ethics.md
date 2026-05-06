# Ethics and Responsible Use

SupplyTrace-VEX is a defensive software supply-chain research artifact. It is intended for local reproducible experiments, artifact evaluation, education, and applied cybersecurity research.

## Defensive-Only Scope

The project supports local analysis of generated testbed cases and local Docker images. It must not be used as an offensive scanning, exploitation, credential discovery, or target-profiling tool.

## Local Scanning Only

Scanner adapters must run only against:

- generated local testbed directories under `testbed/cases/`
- local Docker images intentionally prepared for the experiment
- local manifest files created as part of the testbed

Remote URLs, public applications, external package services as targets, and third-party infrastructure are outside the project scope.

## No External Targets

Do not add examples, tests, scanner commands, documentation, or configuration that targets third-party systems. The pipeline blocks remote-looking scanner arguments, and future changes should preserve that boundary.

## No Exploitation

The generated cases must not include exploit payloads, live exploit proof-of-concept code, privilege escalation logic, destructive operations, or instructions for exploiting a vulnerability.

## No Malware

The repository must not contain malware, droppers, persistence mechanisms, evasion logic, weaponized payloads, or code intended to harm systems.

## No Credential Theft

The project must not collect, guess, exfiltrate, test, or store credentials. Testbed code should avoid authentication workflows unless they are inert local fixtures with no secrets.

## Responsible Use

Researchers should report only what the generated artifacts support. VEX-style records are project-evidence outputs and should not be represented as vendor attestations. Synthetic testbed results should not be presented as measurements from real organizations.

If the project is extended, new cases and adapters should keep the same local-only, evidence-preserving, non-exploitative design.
