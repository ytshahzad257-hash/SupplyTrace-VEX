"""Normalized vulnerability finding schema."""

from __future__ import annotations

from dataclasses import asdict, dataclass


NORMALIZED_FINDING_FIELDS: tuple[str, ...] = (
    "finding_id",
    "case_id",
    "scanner_name",
    "package_name",
    "package_version",
    "ecosystem",
    "package_manager",
    "vulnerability_id",
    "cve_id",
    "ghsa_id",
    "osv_id",
    "severity",
    "cvss_score",
    "fixed_version",
    "advisory_url",
    "dependency_scope",
    "direct_or_transitive",
    "source_file",
    "raw_reference",
    "scanner_confidence",
    "normalization_notes",
)

WARNING_FIELDS: tuple[str, ...] = (
    "case_id",
    "scanner_name",
    "raw_reference",
    "field",
    "warning",
)


@dataclass(frozen=True)
class NormalizedFinding:
    """One normalized vulnerability finding."""

    finding_id: str
    case_id: str
    scanner_name: str
    package_name: str
    package_version: str | None
    ecosystem: str
    package_manager: str
    vulnerability_id: str
    cve_id: str | None
    ghsa_id: str | None
    osv_id: str | None
    severity: str | None
    cvss_score: float | None
    fixed_version: str | None
    advisory_url: str | None
    dependency_scope: str
    direct_or_transitive: str
    source_file: str
    raw_reference: str
    scanner_confidence: str
    normalization_notes: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizationWarning:
    """Warning emitted when a field is missing or a raw record is unusable."""

    case_id: str
    scanner_name: str
    raw_reference: str
    field: str
    warning: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

