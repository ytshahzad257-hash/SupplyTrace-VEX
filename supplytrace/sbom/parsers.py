"""Manifest and SBOM parser helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from .schema import SbomComponent


REQ_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)")


def load_sbom(path: Path) -> dict[str, object]:
    """Load a JSON SBOM file."""

    return json.loads(path.read_text(encoding="utf-8"))


def iter_components(sbom: dict[str, object]) -> Iterable[dict[str, object]]:
    """Iterate component dictionaries from common SBOM shapes."""

    components = sbom.get("components", [])
    if isinstance(components, list):
        for component in components:
            if isinstance(component, dict):
                yield component
    packages = sbom.get("packages", [])
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict):
                yield package


def component_ecosystem(component: dict[str, object]) -> str:
    """Infer the package ecosystem from a normalized or CycloneDX component."""

    if component.get("ecosystem"):
        return str(component["ecosystem"])
    for prop in component.get("properties", []) if isinstance(component.get("properties"), list) else []:
        if isinstance(prop, dict) and prop.get("name") == "supplytrace:ecosystem":
            return str(prop.get("value", "generic"))
    purl = str(component.get("purl", ""))
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:npm/"):
        return "npm"
    return "generic"


def _clean_version(value: object) -> str:
    version = str(value).strip()
    return version.lstrip("^~=").strip()


def parse_package_json(path: Path) -> list[SbomComponent]:
    """Parse direct npm dependencies from ``package.json``."""

    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    components: list[SbomComponent] = []
    sections = (
        ("dependencies", "runtime"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
        ("devDependencies", "development"),
    )
    for section, scope in sections:
        deps = payload.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version in sorted(deps.items()):
            components.append(
                SbomComponent(
                    name=str(name),
                    version=_clean_version(version),
                    ecosystem="npm",
                    package_manager="npm",
                    dependency_scope=scope,
                    direct_or_transitive="direct",
                    source_manifest=path.name,
                )
            )
    return components


def parse_package_lock(path: Path, direct_components: Iterable[SbomComponent]) -> list[SbomComponent]:
    """Parse transitive npm package entries from ``package-lock.json`` when present."""

    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages", {})
    if not isinstance(packages, dict):
        return []

    direct_by_name = {component.name: component for component in direct_components}
    components: list[SbomComponent] = []
    for package_path, package_payload in sorted(packages.items()):
        if not package_path or not isinstance(package_payload, dict):
            continue
        if not package_path.startswith("node_modules/"):
            continue
        name = package_path.removeprefix("node_modules/")
        version = package_payload.get("version")
        if not version:
            continue
        if name in direct_by_name:
            continue
        components.append(
            SbomComponent(
                name=name,
                version=_clean_version(version),
                ecosystem="npm",
                package_manager="npm",
                dependency_scope="transitive",
                direct_or_transitive="transitive",
                source_manifest=path.name,
            )
        )
    return components


def parse_requirements(path: Path, *, scope: str = "runtime", direct_or_transitive: str = "direct") -> list[SbomComponent]:
    """Parse pinned pip requirements from a requirements-style file."""

    if not path.exists():
        return []
    components: list[SbomComponent] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = REQ_PATTERN.match(stripped)
        if not match:
            continue
        components.append(
            SbomComponent(
                name=match.group(1),
                version=_clean_version(match.group(2)),
                ecosystem="pypi",
                package_manager="pip",
                dependency_scope=scope,
                direct_or_transitive=direct_or_transitive,
                source_manifest=path.name,
            )
        )
    return components


def parse_container_manifest(path: Path) -> list[SbomComponent]:
    """Parse the local container fixture manifest."""

    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages_expected", [])
    if not isinstance(packages, list):
        return []
    components: list[SbomComponent] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        components.append(
            SbomComponent(
                name=str(name),
                version=str(version),
                ecosystem=str(package.get("ecosystem", "linux-package")),
                package_manager="dockerfile",
                dependency_scope=str(package.get("scope", "container_layer")),
                direct_or_transitive="container_layer",
                source_manifest=path.name,
            )
        )
    return components


def components_from_manifests(case_dir: Path) -> list[SbomComponent]:
    """Parse all supported local manifests for a case directory."""

    components: list[SbomComponent] = []

    npm_direct = parse_package_json(case_dir / "package.json")
    components.extend(npm_direct)
    components.extend(parse_package_lock(case_dir / "package-lock.json", npm_direct))

    pip_runtime = parse_requirements(case_dir / "requirements.txt", scope="runtime", direct_or_transitive="direct")
    pip_dev = parse_requirements(case_dir / "requirements-dev.txt", scope="development", direct_or_transitive="direct")
    components.extend(pip_runtime)
    components.extend(pip_dev)

    known_python = {(component.name.lower(), component.version) for component in [*pip_runtime, *pip_dev]}
    for component in parse_requirements(
        case_dir / "requirements.lock",
        scope="transitive",
        direct_or_transitive="transitive",
    ):
        if (component.name.lower(), component.version) not in known_python:
            components.append(component)

    components.extend(parse_container_manifest(case_dir / "container-manifest.json"))
    return sorted(
        components,
        key=lambda item: (
            item.ecosystem,
            item.package_manager,
            item.direct_or_transitive,
            item.name.lower(),
            item.version,
            item.source_manifest,
        ),
    )

