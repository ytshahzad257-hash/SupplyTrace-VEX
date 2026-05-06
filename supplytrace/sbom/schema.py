"""SBOM data structures for SupplyTrace-VEX."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SbomComponent:
    """Internal normalized component representation."""

    name: str
    version: str
    ecosystem: str
    package_manager: str
    dependency_scope: str
    direct_or_transitive: str
    source_manifest: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def utc_now() -> str:
    """Return an ISO 8601 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def component_purl(ecosystem: str, name: str, version: str) -> str:
    """Return a package URL for ecosystems used by the local testbed."""

    if ecosystem == "pypi":
        return f"pkg:pypi/{name}@{version}"
    if ecosystem == "npm":
        return f"pkg:npm/{name}@{version}"
    if ecosystem == "linux-package":
        return f"pkg:generic/{name}@{version}"
    return f"pkg:generic/{name}@{version}"


def make_component(
    name: str,
    version: str,
    ecosystem: str,
    scope: str = "runtime",
    *,
    package_manager: str | None = None,
    direct_or_transitive: str = "direct",
    source_manifest: str = "manifest",
) -> dict[str, object]:
    """Return a component dict compatible with existing pipeline callers."""

    manager = package_manager or ("npm" if ecosystem == "npm" else "pip" if ecosystem == "pypi" else "unknown")
    return {
        "type": "library",
        "name": name,
        "version": version,
        "scope": scope,
        "dependency_scope": scope,
        "direct_or_transitive": direct_or_transitive,
        "ecosystem": ecosystem,
        "package_manager": manager,
        "source_manifest": source_manifest,
        "purl": component_purl(ecosystem, name, version),
        "bom-ref": f"{ecosystem}:{name}@{version}",
        "properties": [{"name": "supplytrace:ecosystem", "value": ecosystem}],
    }


def make_internal_sbom(
    *,
    case_id: str,
    generated_at: str,
    tool_name: str,
    tool_version: str,
    tool_status: str,
    components: list[SbomComponent],
    case_hash: str,
    generation_command: list[str],
    notes: list[str],
) -> dict[str, Any]:
    """Create the internal fallback SBOM document."""

    return {
        "case_id": case_id,
        "format": "internal_fallback",
        "sbom_format": "internal_fallback",
        "generated_at": generated_at,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "tool_status": tool_status,
        "components": [component.to_dict() for component in components],
        "metadata": {
            "case_hash": case_hash,
            "generation_command": generation_command,
            "notes": notes,
        },
    }


def make_external_metadata_stub(
    *,
    case_id: str,
    sbom_format: str,
    generated_at: str,
    tool_name: str,
    tool_version: str | None,
    tool_status: str,
    generation_command: list[str],
    notes: list[str],
) -> dict[str, Any]:
    """Return metadata for attempted external SBOM generation."""

    return {
        "case_id": case_id,
        "sbom_format": sbom_format,
        "generated_at": generated_at,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "tool_status": tool_status,
        "components": [],
        "metadata": {
            "case_hash": None,
            "generation_command": generation_command,
            "notes": notes,
        },
    }

