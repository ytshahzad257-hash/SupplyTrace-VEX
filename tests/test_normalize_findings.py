from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.normalize.normalize_findings import normalize_findings
from supplytrace.run_context import create_run_context


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def _write_case_manifest(config: ProjectConfig, case_id: str = "case_001") -> None:
    case_dir = config.cases_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "local-case",
                "version": "0.1.0",
                "dependencies": {"lodash": "4.17.20"},
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")


def _write_raw(config: ProjectConfig, scanner: str, case_id: str, payload: dict[str, object]) -> Path:
    path = config.artifacts_dir / "scanner_raw" / scanner / f"{case_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _findings(config: ProjectConfig) -> list[dict[str, object]]:
    payload = json.loads((config.artifacts_dir / "normalized" / "findings_normalized.json").read_text(encoding="utf-8"))
    return payload["findings"]


def _warnings(config: ProjectConfig) -> list[dict[str, str]]:
    with (config.artifacts_dir / "normalized" / "normalization_warnings.csv").open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_parse_sample_osv_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "osv",
        "case_001",
        {
            "results": [
                {
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-35jh-r3h4-6jhm",
                            "aliases": ["CVE-2020-8203"],
                            "database_specific": {"severity": "HIGH"},
                            "references": [{"url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"}],
                            "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                        }
                    ],
                }
            ]
        },
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    findings = _findings(config)
    assert len(findings) == 1
    assert findings[0]["scanner_name"] == "osv"
    assert findings[0]["package_name"] == "lodash"
    assert findings[0]["ghsa_id"] == "GHSA-35JH-R3H4-6JHM"
    assert findings[0]["cve_id"] == "CVE-2020-8203"
    assert findings[0]["fixed_version"] == "4.17.21"


def test_parse_sample_trivy_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "trivy",
        "case_001",
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-8203",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "FixedVersion": "4.17.21",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 7.4}},
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8203",
                        }
                    ],
                }
            ]
        },
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    finding = _findings(config)[0]
    assert finding["scanner_name"] == "trivy"
    assert finding["cvss_score"] == 7.4
    assert finding["severity"] == "HIGH"


def test_parse_sample_grype_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "grype",
        "case_001",
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2020-8203",
                        "severity": "High",
                        "cvss": [{"metrics": {"baseScore": 7.4}}],
                        "fix": {"versions": ["4.17.21"]},
                        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"],
                    },
                    "artifact": {
                        "name": "lodash",
                        "version": "4.17.20",
                        "type": "npm",
                        "locations": [{"path": "package-lock.json"}],
                    },
                    "matchDetails": [{"confidence": "high"}],
                }
            ]
        },
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    finding = _findings(config)[0]
    assert finding["scanner_name"] == "grype"
    assert finding["scanner_confidence"] == "high"
    assert finding["fixed_version"] == "4.17.21"


def test_parse_sample_npm_audit_vulnerable_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "npm_audit",
        "case_001",
        {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 1106913,
                            "name": "lodash",
                            "dependency": "lodash",
                            "title": "Command Injection in lodash",
                            "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                            "severity": "high",
                            "cvss": {"score": 7.2},
                            "range": "<4.17.21",
                        }
                    ],
                    "effects": [],
                    "range": "<4.17.21",
                    "nodes": ["node_modules/lodash"],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": False},
                }
            },
            "metadata": {"vulnerabilities": {"total": 1}},
        },
    )

    summary = normalize_findings(create_run_context(config, run_id="normalize-test"))

    findings = _findings(config)
    assert summary["normalized_finding_count"] == 1
    assert len(findings) == 1
    assert findings[0]["scanner_name"] == "npm_audit"
    assert findings[0]["package_name"] == "lodash"
    assert findings[0]["severity"] == "high"
    assert findings[0]["cvss_score"] == 7.2
    assert findings[0]["ghsa_id"] == "GHSA-35JH-R3H4-6JHM"
    assert findings[0]["fixed_version"] == "4.17.21"


def test_parse_sample_pip_audit_vulnerable_output(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "pip_audit",
        "case_001",
        {
            "dependencies": [
                {
                    "name": "PyYAML",
                    "version": "5.3.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2021-142",
                            "aliases": ["CVE-2020-14343"],
                            "fix_versions": ["5.4"],
                            "references": [{"url": "https://osv.dev/vulnerability/PYSEC-2021-142"}],
                        }
                    ],
                }
            ]
        },
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    finding = _findings(config)[0]
    assert finding["scanner_name"] == "pip_audit"
    assert finding["package_name"] == "PyYAML"
    assert finding["cve_id"] == "CVE-2020-14343"
    assert finding["fixed_version"] == "5.4"


def test_handle_missing_fields_with_warnings(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "osv",
        "case_001",
        {"results": [{"package": {"name": "lodash"}, "vulnerabilities": [{}]}]},
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    finding = _findings(config)[0]
    warning_fields = {row["field"] for row in _warnings(config)}
    assert finding["vulnerability_id"] == "unknown"
    assert finding["package_version"] == "4.17.20"
    assert "vulnerability_id" in warning_fields
    assert "package_version" not in warning_fields


def test_deduplicate_same_vulnerability_package_from_multiple_scanners(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(
        config,
        "trivy",
        "case_001",
        {
            "Results": [
                {
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-8203",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        },
    )
    _write_raw(
        config,
        "grype",
        "case_001",
        {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2020-8203", "severity": "High"},
                    "artifact": {"name": "lodash", "version": "4.17.20", "type": "npm"},
                }
            ]
        },
    )

    normalize_findings(create_run_context(config, run_id="normalize-test"))

    findings = _findings(config)
    assert len(findings) == 1
    assert findings[0]["scanner_name"] == "grype;trivy"
    assert "deduplicated_from_2_scanner_records" in findings[0]["normalization_notes"]


def test_create_warnings_file(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(config, "pip_audit", "case_001", {"dependencies": [{"name": "PyYAML", "vulns": [{}]}]})

    summary = normalize_findings(create_run_context(config, run_id="normalize-test"))

    assert (config.artifacts_dir / "normalized" / "normalization_warnings.csv").exists()
    assert summary["warning_count"] > 0
    assert _warnings(config)


def test_parser_coverage_and_zero_finding_warning(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_case_manifest(config)
    _write_raw(config, "npm_audit", "case_001", {"auditReportVersion": 2, "vulnerabilities": {}})

    summary = normalize_findings(create_run_context(config, run_id="normalize-test"))

    coverage_path = config.artifacts_dir / "normalized" / "parser_coverage_summary.csv"
    assert coverage_path.exists()
    with coverage_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    npm_row = next(row for row in rows if row["scanner_name"] == "npm_audit")
    assert npm_row["raw_files_considered"] == "1"
    assert npm_row["raw_files_parsed"] == "1"
    assert summary["zero_finding_warning"] is True
    assert any(row["field"] == "normalized_finding_count" for row in _warnings(config))
