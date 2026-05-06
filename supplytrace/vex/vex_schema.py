"""Schema helpers for SupplyTrace-VEX VEX-style status records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


VEX_STATUSES = {"affected", "not_affected", "fixed", "under_investigation"}

VEX_RECORD_FIELDS: tuple[str, ...] = (
    "case_id",
    "finding_id",
    "vulnerability_id",
    "package_name",
    "package_version",
    "status",
    "justification",
    "evidence",
    "generated_at",
    "limitations",
)

VEX_SUMMARY_FIELDS: tuple[str, ...] = (
    "case_id",
    "finding_id",
    "vulnerability_id",
    "package_name",
    "package_version",
    "status",
    "confidence_level",
    "risk_score",
    "scanner_names",
    "reachability_status",
    "dependency_scope",
    "justification",
)

VEX_DISTRIBUTION_FIELDS: tuple[str, ...] = ("status", "count")

STANDARD_LIMITATIONS: tuple[str, ...] = (
    "This is a SupplyTrace-VEX project-evidence-based VEX-style status, not an official vendor VEX attestation.",
    "Static reachability analysis can miss dynamic imports, reflection, framework dispatch, and generated code.",
    "Scanner availability, scanner databases, and raw scanner output quality limit the strength of status assignment.",
    "Status records prioritize defensive triage and do not prove exploitability or non-exploitability.",
)


@dataclass(frozen=True)
class VexEvidence:
    """Evidence attached to one VEX-style record."""

    scanner_names: list[str]
    scanner_output_paths: list[str]
    reachability_status: str
    dependency_scope: str
    context_fields: dict[str, Any]
    risk_score: dict[str, Any] | None
    confidence_level: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VexRecord:
    """One project-evidence-based VEX-style vulnerability status."""

    case_id: str
    finding_id: str
    vulnerability_id: str
    package_name: str
    package_version: str | None
    status: str
    justification: str
    evidence: VexEvidence
    generated_at: str
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        validate_status(self.status)
        return {
            "case_id": self.case_id,
            "finding_id": self.finding_id,
            "vulnerability_id": self.vulnerability_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "status": self.status,
            "justification": self.justification,
            "evidence": self.evidence.to_dict(),
            "generated_at": self.generated_at,
            "limitations": self.limitations,
        }


def validate_status(status: str) -> str:
    if status not in VEX_STATUSES:
        raise ValueError(f"Unsupported VEX status: {status}")
    return status
