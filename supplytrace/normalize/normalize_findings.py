"""Normalize scanner outputs into one evaluation and scoring schema."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from supplytrace.config import ProjectConfig, project_path_from_artifact_reference, to_project_relative_path
from supplytrace.run_context import RunContext, write_json
from supplytrace.sbom.parsers import components_from_manifests

from .schema import NORMALIZED_FINDING_FIELDS, WARNING_FIELDS, NormalizedFinding, NormalizationWarning


SCANNER_DIRS: tuple[str, ...] = ("osv", "trivy", "grype", "npm_audit", "npm-audit", "pip_audit", "pip-audit")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)

PARSER_COVERAGE_FIELDS: tuple[str, ...] = (
    "scanner_name",
    "raw_files_considered",
    "raw_files_parsed",
    "raw_finding_records",
    "normalized_findings_after_dedupe",
    "warning_count",
    "notes",
)


class WarningCollector:
    """Collect normalization warnings with consistent context."""

    def __init__(self) -> None:
        self.items: list[NormalizationWarning] = []

    def add(self, *, case_id: str, scanner_name: str, raw_reference: str, field: str, warning: str) -> None:
        self.items.append(
            NormalizationWarning(
                case_id=case_id,
                scanner_name=scanner_name,
                raw_reference=raw_reference,
                field=field,
                warning=warning,
            )
        )


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _safe_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _first_url(values: Iterable[Any]) -> str | None:
    for value in values:
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict) and value.get("url"):
            return str(value["url"])
    return None


def _first_fixed_version(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list):
        for item in value:
            if item:
                return str(item)
    if isinstance(value, dict):
        if value.get("version"):
            return str(value["version"])
        versions = value.get("versions")
        if isinstance(versions, list) and versions:
            return str(versions[0])
    return None


def _first_cvss_score(value: Any) -> float | None:
    """Return a numeric CVSS score only when the scanner supplies one."""

    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        for key in ("score", "baseScore", "V3Score", "V2Score"):
            if isinstance(value.get(key), (int, float)):
                return float(value[key])
        for nested in value.values():
            score = _first_cvss_score(nested)
            if score is not None:
                return score
    if isinstance(value, list):
        for item in value:
            score = _first_cvss_score(item)
            if score is not None:
                return score
    return None


def _extract_ids(vulnerability_id: str | None, aliases: Iterable[Any]) -> tuple[str | None, str | None, str | None]:
    values = [str(item) for item in [vulnerability_id, *aliases] if item]
    cve_id = None
    ghsa_id = None
    osv_id = None
    for value in values:
        if cve_id is None:
            cve_match = CVE_RE.search(value)
            if cve_match:
                cve_id = cve_match.group(0).upper()
        if ghsa_id is None:
            ghsa_match = GHSA_RE.search(value)
            if ghsa_match:
                ghsa_id = ghsa_match.group(0).upper()
    if vulnerability_id and not CVE_RE.fullmatch(vulnerability_id) and not GHSA_RE.fullmatch(vulnerability_id):
        osv_id = vulnerability_id
    return cve_id, ghsa_id, osv_id


def _case_id_from_path(path: Path) -> str:
    return path.stem


def _scanner_name_from_path(path: Path) -> str:
    for part in reversed(path.parts):
        lowered = part.lower()
        if lowered in SCANNER_DIRS:
            return lowered.replace("-", "_")
    return "unknown"


def _finding_id(
    *,
    case_id: str,
    package_name: str,
    package_version: str | None,
    vulnerability_id: str,
) -> str:
    raw = "|".join(
        [
            case_id,
            package_name.lower(),
            package_version or "unknown",
            vulnerability_id.upper(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _component_context(config: ProjectConfig) -> dict[tuple[str, str], dict[str, str]]:
    context: dict[tuple[str, str], dict[str, str]] = {}
    if not config.cases_dir.exists():
        return context
    for case_dir in sorted(config.cases_dir.glob("case_*")):
        if not case_dir.is_dir():
            continue
        for component in components_from_manifests(case_dir):
            context[(case_dir.name, component.name.lower())] = {
                "package_version": component.version,
                "ecosystem": component.ecosystem,
                "package_manager": component.package_manager,
                "dependency_scope": component.dependency_scope,
                "direct_or_transitive": component.direct_or_transitive,
                "source_manifest": component.source_manifest,
            }
    return context


def _warn_missing(
    warnings: WarningCollector,
    *,
    case_id: str,
    scanner_name: str,
    raw_reference: str,
    field: str,
    value: Any,
) -> None:
    if value in (None, "", "unknown"):
        warnings.add(
            case_id=case_id,
            scanner_name=scanner_name,
            raw_reference=raw_reference,
            field=field,
            warning=f"{field} missing in scanner output or local dependency context",
        )


def _make_finding(
    *,
    case_id: str,
    scanner_name: str,
    raw_reference: str,
    package_name: str | None,
    package_version: str | None,
    ecosystem: str | None,
    package_manager: str | None,
    vulnerability_id: str | None,
    aliases: Iterable[Any] = (),
    severity: str | None = None,
    cvss_score: float | None = None,
    fixed_version: str | None = None,
    advisory_url: str | None = None,
    dependency_scope: str | None = None,
    direct_or_transitive: str | None = None,
    source_file: str | None = None,
    scanner_confidence: str | None = None,
    notes: Iterable[str] = (),
    component_context: dict[tuple[str, str], dict[str, str]] | None = None,
    warnings: WarningCollector,
) -> NormalizedFinding:
    pkg = package_name or "unknown"
    context = (component_context or {}).get((case_id, pkg.lower()), {})
    version = _safe_str(package_version) or context.get("package_version")
    vuln = vulnerability_id or "unknown"
    cve_id, ghsa_id, osv_id = _extract_ids(vuln, aliases)

    resolved_ecosystem = ecosystem or context.get("ecosystem") or "unknown"
    resolved_manager = package_manager or context.get("package_manager") or "unknown"
    resolved_scope = dependency_scope or context.get("dependency_scope") or "unknown"
    resolved_direct = direct_or_transitive or context.get("direct_or_transitive") or "unknown"
    resolved_source = source_file or context.get("source_manifest") or "unknown"
    confidence = scanner_confidence or "unknown"

    for field, value in (
        ("package_name", pkg),
        ("package_version", version),
        ("ecosystem", resolved_ecosystem),
        ("package_manager", resolved_manager),
        ("vulnerability_id", vuln),
        ("severity", severity),
        ("cvss_score", cvss_score),
        ("fixed_version", fixed_version),
        ("advisory_url", advisory_url),
        ("dependency_scope", resolved_scope),
        ("direct_or_transitive", resolved_direct),
        ("source_file", resolved_source),
        ("scanner_confidence", confidence),
    ):
        _warn_missing(
            warnings,
            case_id=case_id,
            scanner_name=scanner_name,
            raw_reference=raw_reference,
            field=field,
            value=value,
        )

    normalized_notes = "; ".join(str(item) for item in notes if item) or "normalized from scanner JSON"
    return NormalizedFinding(
        finding_id=_finding_id(
            case_id=case_id,
            package_name=pkg,
            package_version=version,
            vulnerability_id=vuln,
        ),
        case_id=case_id,
        scanner_name=scanner_name,
        package_name=pkg,
        package_version=version,
        ecosystem=resolved_ecosystem,
        package_manager=resolved_manager,
        vulnerability_id=vuln,
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        osv_id=osv_id,
        severity=severity,
        cvss_score=cvss_score,
        fixed_version=fixed_version,
        advisory_url=advisory_url,
        dependency_scope=resolved_scope,
        direct_or_transitive=resolved_direct,
        source_file=resolved_source,
        raw_reference=raw_reference,
        scanner_confidence=confidence,
        normalization_notes=normalized_notes,
    )


def parse_osv_output(
    path: Path,
    payload: dict[str, Any],
    component_context: dict[tuple[str, str], dict[str, str]],
    warnings: WarningCollector,
) -> list[NormalizedFinding]:
    case_id = _case_id_from_path(path)
    scanner_name = "osv"
    findings: list[NormalizedFinding] = []
    for result in _as_list(payload.get("results")):
        result_dict = _as_dict(result)
        packages = _as_list(result_dict.get("packages"))
        if not packages:
            packages = [result_dict]
        for package_result in packages:
            package_result_dict = _as_dict(package_result)
            package = _as_dict(package_result_dict.get("package") or result_dict.get("package"))
            source = _as_dict(package_result_dict.get("source") or result_dict.get("source"))
            package_name = _safe_str(package.get("name"))
            package_version = _safe_str(package.get("version"))
            ecosystem = _safe_str(package.get("ecosystem"))
            source_file = _safe_str(source.get("path"))
            vulnerabilities = _as_list(package_result_dict.get("vulnerabilities"))
            for vuln in vulnerabilities:
                vuln_dict = _as_dict(vuln)
                vuln_id = _safe_str(vuln_dict.get("id"))
                aliases = _as_list(vuln_dict.get("aliases"))
                severity_items = _as_list(vuln_dict.get("severity"))
                severity = _safe_str(_as_dict(vuln_dict.get("database_specific")).get("severity"))
                cvss_score = _first_cvss_score(severity_items)
                fixed_version = None
                for affected in _as_list(vuln_dict.get("affected")):
                    for range_item in _as_list(_as_dict(affected).get("ranges")):
                        for event in _as_list(_as_dict(range_item).get("events")):
                            fixed_version = fixed_version or _safe_str(_as_dict(event).get("fixed"))
                advisory_url = _first_url(_as_list(vuln_dict.get("references")))
                findings.append(
                    _make_finding(
                        case_id=case_id,
                        scanner_name=scanner_name,
                        raw_reference=str(path),
                        package_name=package_name,
                        package_version=package_version,
                        ecosystem=ecosystem.lower() if ecosystem else None,
                        package_manager=None,
                        vulnerability_id=vuln_id,
                        aliases=aliases,
                        severity=severity,
                        cvss_score=cvss_score,
                        fixed_version=fixed_version,
                        advisory_url=advisory_url,
                        source_file=source_file,
                        scanner_confidence=None,
                        notes=["OSV scanner result"],
                        component_context=component_context,
                        warnings=warnings,
                    )
                )
    for vuln in _as_list(payload.get("vulnerabilities")):
        vuln_dict = _as_dict(vuln)
        package = _as_dict(vuln_dict.get("package"))
        if not package and vuln_dict.get("package_name"):
            package = {"name": vuln_dict.get("package_name"), "version": vuln_dict.get("package_version")}
        if package:
            vuln_dict = _as_dict(vuln)
            vuln_id = _safe_str(vuln_dict.get("id"))
            aliases = _as_list(vuln_dict.get("aliases"))
            severity_items = _as_list(vuln_dict.get("severity") or vuln_dict.get("severity_scores"))
            severity = _safe_str(_as_dict(vuln_dict.get("database_specific")).get("severity"))
            cvss_score = _first_cvss_score(severity_items)
            advisory_url = _first_url(_as_list(vuln_dict.get("references")))
            findings.append(
                _make_finding(
                    case_id=case_id,
                    scanner_name=scanner_name,
                    raw_reference=str(path),
                    package_name=_safe_str(package.get("name")),
                    package_version=_safe_str(package.get("version")),
                    ecosystem=_safe_str(package.get("ecosystem")),
                    package_manager=None,
                    vulnerability_id=vuln_id,
                    aliases=aliases,
                    severity=severity,
                    cvss_score=cvss_score,
                    fixed_version=_first_fixed_version(vuln_dict.get("fixed_versions")),
                    advisory_url=advisory_url,
                    source_file=None,
                    scanner_confidence=None,
                    notes=["OSV scanner result"],
                    component_context=component_context,
                    warnings=warnings,
                )
            )
    return findings


def parse_trivy_output(
    path: Path,
    payload: dict[str, Any],
    component_context: dict[tuple[str, str], dict[str, str]],
    warnings: WarningCollector,
) -> list[NormalizedFinding]:
    case_id = _case_id_from_path(path)
    scanner_name = "trivy"
    findings: list[NormalizedFinding] = []
    for result in _as_list(payload.get("Results")):
        result_dict = _as_dict(result)
        result_type = _safe_str(result_dict.get("Type"))
        target = _safe_str(result_dict.get("Target"))
        for vuln in _as_list(result_dict.get("Vulnerabilities")):
            vuln_dict = _as_dict(vuln)
            vuln_id = _safe_str(vuln_dict.get("VulnerabilityID"))
            aliases = _as_list(vuln_dict.get("Aliases"))
            findings.append(
                _make_finding(
                    case_id=case_id,
                    scanner_name=scanner_name,
                    raw_reference=str(path),
                    package_name=_safe_str(vuln_dict.get("PkgName")),
                    package_version=_safe_str(vuln_dict.get("InstalledVersion")),
                    ecosystem=result_type,
                    package_manager=None,
                    vulnerability_id=vuln_id,
                    aliases=aliases,
                    severity=_safe_str(vuln_dict.get("Severity")),
                    cvss_score=_first_cvss_score(vuln_dict.get("CVSS")),
                    fixed_version=_first_fixed_version(vuln_dict.get("FixedVersion")),
                    advisory_url=_safe_str(vuln_dict.get("PrimaryURL")) or _first_url(_as_list(vuln_dict.get("References"))),
                    source_file=_safe_str(vuln_dict.get("PkgPath")) or target,
                    scanner_confidence=_safe_str(vuln_dict.get("Status")),
                    notes=["Trivy scanner result"],
                    component_context=component_context,
                    warnings=warnings,
                )
            )
    return findings


def parse_grype_output(
    path: Path,
    payload: dict[str, Any],
    component_context: dict[tuple[str, str], dict[str, str]],
    warnings: WarningCollector,
) -> list[NormalizedFinding]:
    case_id = _case_id_from_path(path)
    scanner_name = "grype"
    findings: list[NormalizedFinding] = []
    for match in _as_list(payload.get("matches")):
        match_dict = _as_dict(match)
        vuln = _as_dict(match_dict.get("vulnerability"))
        artifact = _as_dict(match_dict.get("artifact"))
        vuln_id = _safe_str(vuln.get("id"))
        aliases = _as_list(vuln.get("aliases"))
        fix = _as_dict(vuln.get("fix"))
        locations = _as_list(artifact.get("locations"))
        source_file = None
        if locations:
            source_file = _safe_str(_as_dict(locations[0]).get("path"))
        match_details = _as_list(match_dict.get("matchDetails"))
        confidence = None
        if match_details:
            confidence = _safe_str(_as_dict(match_details[0]).get("confidence"))
        urls = vuln.get("urls")
        if isinstance(urls, list):
            advisory_url = _first_url(urls)
        else:
            advisory_url = _safe_str(urls)
        findings.append(
            _make_finding(
                case_id=case_id,
                scanner_name=scanner_name,
                raw_reference=str(path),
                package_name=_safe_str(artifact.get("name")),
                package_version=_safe_str(artifact.get("version")),
                ecosystem=_safe_str(artifact.get("type")),
                package_manager=None,
                vulnerability_id=vuln_id,
                aliases=aliases,
                severity=_safe_str(vuln.get("severity")),
                cvss_score=_first_cvss_score(vuln.get("cvss")),
                fixed_version=_first_fixed_version(fix.get("versions")),
                advisory_url=advisory_url,
                source_file=source_file,
                scanner_confidence=confidence,
                notes=["Grype scanner result"],
                component_context=component_context,
                warnings=warnings,
            )
        )
    return findings


def parse_npm_audit_output(
    path: Path,
    payload: dict[str, Any],
    component_context: dict[tuple[str, str], dict[str, str]],
    warnings: WarningCollector,
) -> list[NormalizedFinding]:
    case_id = _case_id_from_path(path)
    scanner_name = "npm_audit"
    findings: list[NormalizedFinding] = []
    vulnerabilities = payload.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        warnings.add(case_id=case_id, scanner_name=scanner_name, raw_reference=str(path), field="vulnerabilities", warning="npm audit vulnerabilities field is missing or not an object")
        vulnerabilities = {}

    for package_name, vuln in sorted(vulnerabilities.items()):
        vuln_dict = _as_dict(vuln)
        via_items = _as_list(vuln_dict.get("via"))
        object_via = [item for item in via_items if isinstance(item, dict)]
        if not object_via and vuln_dict:
            object_via = [vuln_dict]
        for via in object_via:
            via_dict = _as_dict(via)
            vuln_id = _safe_str(_first_non_empty(via_dict.get("source"), via_dict.get("url"), via_dict.get("title"), vuln_dict.get("name")))
            fixed_version = _first_fixed_version(vuln_dict.get("fixAvailable"))
            is_direct = vuln_dict.get("isDirect")
            if isinstance(is_direct, bool):
                direct_or_transitive = "direct" if is_direct else "transitive"
            else:
                direct_or_transitive = None
            dependency_scope = "development" if vuln_dict.get("dev") is True else "runtime" if vuln_dict.get("dev") is False else None
            nodes = _as_list(vuln_dict.get("nodes"))
            findings.append(
                _make_finding(
                    case_id=case_id,
                    scanner_name=scanner_name,
                    raw_reference=str(path),
                    package_name=str(package_name),
                    package_version=None,
                    ecosystem="npm",
                    package_manager="npm",
                    vulnerability_id=vuln_id,
                    aliases=[via_dict.get("url"), via_dict.get("title")],
                    severity=_safe_str(_first_non_empty(via_dict.get("severity"), vuln_dict.get("severity"))),
                    cvss_score=_first_cvss_score(via_dict.get("cvss")),
                    fixed_version=fixed_version,
                    advisory_url=_safe_str(via_dict.get("url")),
                    dependency_scope=dependency_scope,
                    direct_or_transitive=direct_or_transitive,
                    source_file=_safe_str(nodes[0]) if nodes else None,
                    scanner_confidence=None,
                    notes=["npm audit scanner result"],
                    component_context=component_context,
                    warnings=warnings,
                )
            )
    advisories = payload.get("advisories", {})
    if isinstance(advisories, dict):
        for advisory_id, advisory in sorted(advisories.items()):
            advisory_dict = _as_dict(advisory)
            package_name = _safe_str(_first_non_empty(advisory_dict.get("module_name"), advisory_dict.get("name")))
            findings_list = _as_list(advisory_dict.get("findings"))
            versions = []
            paths = []
            for item in findings_list:
                item_dict = _as_dict(item)
                if item_dict.get("version"):
                    versions.append(item_dict.get("version"))
                paths.extend(_as_list(item_dict.get("paths")))
            vulnerability_id = _safe_str(
                _first_non_empty(
                    advisory_dict.get("github_advisory_id"),
                    advisory_dict.get("cves", [None])[0] if isinstance(advisory_dict.get("cves"), list) and advisory_dict.get("cves") else None,
                    advisory_dict.get("url"),
                    advisory_id,
                )
            )
            aliases = _as_list(advisory_dict.get("cves"))
            if advisory_dict.get("github_advisory_id"):
                aliases.append(advisory_dict.get("github_advisory_id"))
            findings.append(
                _make_finding(
                    case_id=case_id,
                    scanner_name=scanner_name,
                    raw_reference=str(path),
                    package_name=package_name,
                    package_version=_safe_str(versions[0]) if versions else None,
                    ecosystem="npm",
                    package_manager="npm",
                    vulnerability_id=vulnerability_id,
                    aliases=aliases,
                    severity=_safe_str(advisory_dict.get("severity")),
                    cvss_score=_first_cvss_score(advisory_dict.get("cvss")),
                    fixed_version=_safe_str(advisory_dict.get("patched_versions")),
                    advisory_url=_safe_str(advisory_dict.get("url")),
                    dependency_scope=None,
                    direct_or_transitive=None,
                    source_file=_safe_str(paths[0]) if paths else None,
                    scanner_confidence=None,
                    notes=["npm audit legacy advisory result"],
                    component_context=component_context,
                    warnings=warnings,
                )
            )
    return findings


def parse_pip_audit_output(
    path: Path,
    payload: dict[str, Any],
    component_context: dict[tuple[str, str], dict[str, str]],
    warnings: WarningCollector,
) -> list[NormalizedFinding]:
    case_id = _case_id_from_path(path)
    scanner_name = "pip_audit"
    findings: list[NormalizedFinding] = []
    dependencies = payload.get("dependencies")
    if dependencies is None and isinstance(payload, list):
        dependencies = payload
    for dep in _as_list(dependencies):
        dep_dict = _as_dict(dep)
        package_name = _safe_str(dep_dict.get("name"))
        package_version = _safe_str(dep_dict.get("version"))
        for vuln in _as_list(dep_dict.get("vulns")):
            vuln_dict = _as_dict(vuln)
            vuln_id = _safe_str(vuln_dict.get("id"))
            aliases = _as_list(vuln_dict.get("aliases"))
            references = _as_list(vuln_dict.get("references"))
            findings.append(
                _make_finding(
                    case_id=case_id,
                    scanner_name=scanner_name,
                    raw_reference=str(path),
                    package_name=package_name,
                    package_version=package_version,
                    ecosystem="pypi",
                    package_manager="pip",
                    vulnerability_id=vuln_id,
                    aliases=aliases,
                    severity=None,
                    cvss_score=None,
                    fixed_version=_first_fixed_version(vuln_dict.get("fix_versions")),
                    advisory_url=_first_url(references),
                    source_file=None,
                    scanner_confidence=None,
                    notes=["pip-audit scanner result"],
                    component_context=component_context,
                    warnings=warnings,
                )
            )
    for vuln in _as_list(payload.get("vulnerabilities")):
        vuln_dict = _as_dict(vuln)
        package = _as_dict(vuln_dict.get("dependency") or vuln_dict.get("package"))
        package_name = _safe_str(_first_non_empty(vuln_dict.get("name"), package.get("name")))
        package_version = _safe_str(_first_non_empty(vuln_dict.get("version"), package.get("version")))
        findings.append(
            _make_finding(
                case_id=case_id,
                scanner_name=scanner_name,
                raw_reference=str(path),
                package_name=package_name,
                package_version=package_version,
                ecosystem="pypi",
                package_manager="pip",
                vulnerability_id=_safe_str(_first_non_empty(vuln_dict.get("id"), vuln_dict.get("vulnerability_id"))),
                aliases=_as_list(vuln_dict.get("aliases")),
                severity=_safe_str(vuln_dict.get("severity")),
                cvss_score=_first_cvss_score(vuln_dict.get("cvss")),
                fixed_version=_first_fixed_version(_first_non_empty(vuln_dict.get("fix_versions"), vuln_dict.get("fixed_versions"))),
                advisory_url=_first_url(_as_list(vuln_dict.get("references"))),
                source_file=None,
                scanner_confidence=None,
                notes=["pip-audit flat vulnerability result"],
                component_context=component_context,
                warnings=warnings,
            )
        )
    return findings


Parser = Callable[[Path, dict[str, Any], dict[tuple[str, str], dict[str, str]], WarningCollector], list[NormalizedFinding]]


def _parser_for_path(path: Path) -> Parser | None:
    scanner = _scanner_name_from_path(path)
    return {
        "osv": parse_osv_output,
        "trivy": parse_trivy_output,
        "grype": parse_grype_output,
        "npm_audit": parse_npm_audit_output,
        "pip_audit": parse_pip_audit_output,
    }.get(scanner)


def _dedupe_findings(findings: Iterable[NormalizedFinding]) -> list[NormalizedFinding]:
    grouped: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.finding_id].append(finding)

    merged: list[NormalizedFinding] = []
    for finding_id, items in grouped.items():
        first = items[0]
        scanner_names = sorted({item.scanner_name for item in items})
        raw_refs = sorted({item.raw_reference for item in items})
        notes = sorted({item.normalization_notes for item in items if item.normalization_notes})

        def choose(field: str) -> Any:
            for item in items:
                value = getattr(item, field)
                if value not in (None, "", "unknown"):
                    return value
            return getattr(first, field)

        merged.append(
            NormalizedFinding(
                finding_id=finding_id,
                case_id=first.case_id,
                scanner_name=";".join(scanner_names),
                package_name=first.package_name,
                package_version=choose("package_version"),
                ecosystem=choose("ecosystem"),
                package_manager=choose("package_manager"),
                vulnerability_id=first.vulnerability_id,
                cve_id=choose("cve_id"),
                ghsa_id=choose("ghsa_id"),
                osv_id=choose("osv_id"),
                severity=choose("severity"),
                cvss_score=choose("cvss_score"),
                fixed_version=choose("fixed_version"),
                advisory_url=choose("advisory_url"),
                dependency_scope=choose("dependency_scope"),
                direct_or_transitive=choose("direct_or_transitive"),
                source_file=";".join(sorted({item.source_file for item in items if item.source_file != "unknown"})) or "unknown",
                raw_reference=";".join(raw_refs),
                scanner_confidence=choose("scanner_confidence"),
                normalization_notes="; ".join(notes + ([f"deduplicated_from_{len(items)}_scanner_records"] if len(items) > 1 else [])),
            )
        )
    return sorted(merged, key=lambda item: (item.case_id, item.package_name.lower(), item.vulnerability_id, item.scanner_name))


def _write_csv(path: Path, rows: list[dict[str, object]], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _raw_scanner_files(config: ProjectConfig) -> list[Path]:
    raw_dir = config.artifacts_dir / "scanner_raw"
    metadata_path = raw_dir / "scanner_execution_metadata.csv"
    if metadata_path.exists():
        with metadata_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        referenced: list[Path] = []
        for row in rows:
            if row.get("status") != "success" or not row.get("output_path"):
                continue
            path = project_path_from_artifact_reference(config, row.get("output_path"))
            candidates = [path] if path is not None else []
            scanner_name = (row.get("scanner_name") or "").replace("-", "_")
            case_id = row.get("case_id") or ""
            if scanner_name and case_id:
                candidates.append(raw_dir / scanner_name / f"{case_id}.json")
            path = next((candidate for candidate in candidates if candidate and candidate.exists()), None)
            if path and path.name.startswith("case_") and path.suffix == ".json":
                referenced.append(path)
        return sorted(set(referenced))
    paths: list[Path] = []
    for scanner_dir in SCANNER_DIRS:
        scanner_path = raw_dir / scanner_dir
        if scanner_path.exists():
            paths.extend(sorted(scanner_path.glob("case_*.json")))
    return sorted(set(paths))


def normalize_findings(context: RunContext) -> dict[str, object]:
    """Normalize raw scanner outputs for one run."""

    config = context.config
    output_dir = config.artifacts_dir / "normalized"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_output_dir = context.run_dir("normalized")
    warnings = WarningCollector()
    component_context = _component_context(config)
    findings: list[NormalizedFinding] = []
    parsed_files = 0
    raw_files = _raw_scanner_files(config)
    parser_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"considered": 0, "parsed": 0, "raw_findings": 0})

    for path in raw_files:
        raw_reference_path = Path(to_project_relative_path(path, config) or str(path))
        parser = _parser_for_path(raw_reference_path)
        scanner_name = _scanner_name_from_path(raw_reference_path)
        case_id = _case_id_from_path(raw_reference_path)
        parser_stats[scanner_name]["considered"] += 1
        if parser is None:
            warnings.add(case_id=case_id, scanner_name=scanner_name, raw_reference=str(raw_reference_path), field="parser", warning="no parser registered for scanner output")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            warnings.add(case_id=case_id, scanner_name=scanner_name, raw_reference=str(raw_reference_path), field="json", warning=f"raw scanner output could not be parsed as JSON: {exc}")
            continue
        if not isinstance(payload, dict):
            warnings.add(case_id=case_id, scanner_name=scanner_name, raw_reference=str(raw_reference_path), field="json", warning="raw scanner output was not a JSON object")
            continue
        parsed = parser(raw_reference_path, payload, component_context, warnings)
        findings.extend(parsed)
        parser_stats[scanner_name]["raw_findings"] += len(parsed)
        parser_stats[scanner_name]["parsed"] += 1
        parsed_files += 1

    deduped = _dedupe_findings(findings)
    if not deduped:
        warnings.add(
            case_id="all",
            scanner_name="normalization",
            raw_reference=to_project_relative_path(config.artifacts_dir / "scanner_raw", config) or "artifacts/scanner_raw",
            field="normalized_finding_count",
            warning=(
                "zero scanner-confirmed findings were normalized; downstream scoring, VEX, and "
                "evaluation cannot support prioritization-improvement claims"
            ),
        )
    finding_rows = [finding.to_dict() for finding in deduped]
    warning_rows = [warning.to_dict() for warning in warnings.items]
    coverage_rows: list[dict[str, object]] = []
    deduped_by_scanner: Counter[str] = Counter()
    for finding in deduped:
        for scanner_name in str(finding.scanner_name).replace(",", ";").split(";"):
            if scanner_name.strip():
                deduped_by_scanner[scanner_name.strip()] += 1
    for scanner_name in sorted(set(parser_stats) | set(SCANNER_DIRS)):
        if "-" in scanner_name:
            continue
        stats = parser_stats[scanner_name]
        coverage_rows.append(
            {
                "scanner_name": scanner_name,
                "raw_files_considered": stats["considered"],
                "raw_files_parsed": stats["parsed"],
                "raw_finding_records": stats["raw_findings"],
                "normalized_findings_after_dedupe": deduped_by_scanner.get(scanner_name, 0),
                "warning_count": sum(1 for warning in warnings.items if warning.scanner_name == scanner_name),
                "notes": "parser coverage from local raw JSON outputs",
            }
        )

    normalized_json = output_dir / "findings_normalized.json"
    normalized_csv = output_dir / "findings_normalized.csv"
    warnings_csv = output_dir / "normalization_warnings.csv"
    summary_json = output_dir / "normalization_summary.json"
    parser_coverage_csv = output_dir / "parser_coverage_summary.csv"

    write_json(normalized_json, {"run_id": context.run_id, "findings": finding_rows})
    _write_csv(normalized_csv, finding_rows, NORMALIZED_FINDING_FIELDS)
    _write_csv(warnings_csv, warning_rows, WARNING_FIELDS)
    _write_csv(parser_coverage_csv, coverage_rows, PARSER_COVERAGE_FIELDS)
    summary = {
        "run_id": context.run_id,
        "raw_scanner_files_considered": len(raw_files),
        "raw_scanner_files_parsed": parsed_files,
        "raw_finding_records": len(findings),
        "normalized_finding_count": len(deduped),
        "warning_count": len(warning_rows),
        "zero_finding_warning": len(deduped) == 0,
        "findings_json": to_project_relative_path(normalized_json, config),
        "findings_csv": to_project_relative_path(normalized_csv, config),
        "warnings_csv": to_project_relative_path(warnings_csv, config),
        "parser_coverage_summary_csv": to_project_relative_path(parser_coverage_csv, config),
        "claim_scope": (
            "Normalized findings are derived only from raw local scanner JSON. "
            "Missing fields are represented as null or unknown and recorded in normalization_warnings.csv."
        ),
    }
    write_json(summary_json, summary)

    # Compatibility outputs for downstream pipeline stages that predate the stable artifact names.
    write_json(run_output_dir / "findings.json", {"run_id": context.run_id, "findings": finding_rows})
    write_json(run_output_dir / "normalization_report.json", summary)
    return summary
