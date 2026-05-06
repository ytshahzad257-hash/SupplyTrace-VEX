"""Dependency scope context helpers."""

from __future__ import annotations

from pathlib import Path

from supplytrace.sbom.parsers import components_from_manifests


def dependency_scopes(case_dir: Path) -> dict[str, dict[str, object]]:
    """Return dependency scope and direct/transitive facts from local manifests."""

    scopes: dict[str, dict[str, object]] = {}
    for component in components_from_manifests(case_dir):
        scopes[component.name] = {
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "package_manager": component.package_manager,
            "dependency_scope": component.dependency_scope,
            "direct_or_transitive": component.direct_or_transitive,
            "source_manifest": component.source_manifest,
            "runtime_dependency": component.dependency_scope in {"runtime", "optional", "peer"},
            "dev_dependency": component.dependency_scope == "development",
            "direct_dependency": component.direct_or_transitive == "direct",
            "transitive_dependency": component.direct_or_transitive in {"transitive", "container_layer"},
        }
    return scopes

