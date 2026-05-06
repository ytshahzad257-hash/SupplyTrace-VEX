"""Static JavaScript dependency reachability analyzer."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<local>[A-Za-z_$][\w$]*)\s*=\s*require\(\s*["'](?P<specifier>[^"']+)["']\s*\)"""
)
BARE_REQUIRE_RE = re.compile(r"""require\(\s*["'](?P<specifier>[^"']+)["']\s*\)""")
IMPORT_FROM_RE = re.compile(
    r"""import\s+(?P<local>[A-Za-z_$][\w$]*|\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]+\})\s+from\s+["'](?P<specifier>[^"']+)["']"""
)
SIDE_EFFECT_IMPORT_RE = re.compile(r"""import\s+["'](?P<specifier>[^"']+)["']""")
DYNAMIC_IMPORT_RE = re.compile(r"""(?:import|require)\(\s*(?!["'])""")


@dataclass(frozen=True)
class JsImportEvidence:
    """One JavaScript import/require observation."""

    package: str
    specifier: str
    local_name: str | None
    source_file: str
    line: int
    import_type: str
    used_in_call: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class JsAnalysis:
    """Static JavaScript analysis result for one source tree."""

    imports: list[JsImportEvidence]
    declared_dependencies: list[dict[str, object]]
    dynamic_imports: list[dict[str, object]]
    parse_errors: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "imports": [item.to_dict() for item in self.imports],
            "declared_dependencies": self.declared_dependencies,
            "dynamic_imports": self.dynamic_imports,
            "parse_errors": self.parse_errors,
        }


def package_name(specifier: str) -> str:
    """Return the npm package portion of an import specifier."""

    if specifier.startswith("."):
        return specifier
    parts = specifier.split("/")
    if specifier.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _local_from_import(local: str) -> str | None:
    local = local.strip()
    if local.startswith("* as "):
        return local.removeprefix("* as ").strip()
    if local.startswith("{"):
        return None
    return local


def _is_called(text: str, local_name: str | None) -> bool:
    if not local_name:
        return False
    return bool(re.search(rf"\b{re.escape(local_name)}\s*(?:\.|\()", text))


def imported_packages(path: Path) -> set[str]:
    """Return statically imported package names for one JavaScript file."""

    return {item.package for item in analyze_js_file(path).imports if not item.package.startswith(".")}


def analyze_js_file(path: Path) -> JsAnalysis:
    """Analyze imports in one JavaScript/TypeScript file without executing code."""

    text = path.read_text(encoding="utf-8", errors="ignore")
    imports: list[JsImportEvidence] = []
    seen_spans: set[tuple[int, int]] = set()

    for match in REQUIRE_RE.finditer(text):
        seen_spans.add(match.span())
        specifier = match.group("specifier")
        local = match.group("local")
        imports.append(
            JsImportEvidence(
                package=package_name(specifier),
                specifier=specifier,
                local_name=local,
                source_file=str(path),
                line=_line_number(text, match.start()),
                import_type="require",
                used_in_call=_is_called(text[match.end() :], local),
            )
        )

    for match in IMPORT_FROM_RE.finditer(text):
        seen_spans.add(match.span())
        specifier = match.group("specifier")
        local = _local_from_import(match.group("local"))
        imports.append(
            JsImportEvidence(
                package=package_name(specifier),
                specifier=specifier,
                local_name=local,
                source_file=str(path),
                line=_line_number(text, match.start()),
                import_type="import",
                used_in_call=_is_called(text[match.end() :], local),
            )
        )

    for match in SIDE_EFFECT_IMPORT_RE.finditer(text):
        if any(start <= match.start() < end for start, end in seen_spans):
            continue
        specifier = match.group("specifier")
        imports.append(
            JsImportEvidence(
                package=package_name(specifier),
                specifier=specifier,
                local_name=None,
                source_file=str(path),
                line=_line_number(text, match.start()),
                import_type="side_effect_import",
                used_in_call=False,
            )
        )

    for match in BARE_REQUIRE_RE.finditer(text):
        if any(start <= match.start() < end for start, end in seen_spans):
            continue
        specifier = match.group("specifier")
        imports.append(
            JsImportEvidence(
                package=package_name(specifier),
                specifier=specifier,
                local_name=None,
                source_file=str(path),
                line=_line_number(text, match.start()),
                import_type="bare_require",
                used_in_call=False,
            )
        )

    dynamic = [
        {
            "source_file": str(path),
            "line": _line_number(text, match.start()),
            "reason": "dynamic import or require requires runtime evaluation",
        }
        for match in DYNAMIC_IMPORT_RE.finditer(text)
    ]
    return JsAnalysis(imports=imports, declared_dependencies=[], dynamic_imports=dynamic, parse_errors=[])


def parse_package_json_dependencies(path: Path) -> list[dict[str, object]]:
    """Parse npm dependency declarations from package.json."""

    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, object]] = []
    for section, scope in (
        ("dependencies", "runtime"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
        ("devDependencies", "development"),
    ):
        deps = payload.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version in sorted(deps.items()):
            dependencies.append(
                {
                    "name": str(name),
                    "version": str(version).lstrip("^~"),
                    "ecosystem": "npm",
                    "package_manager": "npm",
                    "dependency_scope": scope,
                    "direct_or_transitive": "direct",
                    "source_manifest": path.name,
                }
            )
    return dependencies


def parse_package_lock_transitives(path: Path, direct_names: set[str]) -> list[dict[str, object]]:
    """Parse transitive npm package entries from package-lock.json."""

    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages", {})
    if not isinstance(packages, dict):
        return []
    dependencies: list[dict[str, object]] = []
    for package_path, package_payload in sorted(packages.items()):
        if not package_path.startswith("node_modules/") or not isinstance(package_payload, dict):
            continue
        name = package_path.removeprefix("node_modules/")
        if name in direct_names:
            continue
        version = package_payload.get("version")
        if not version:
            continue
        dependencies.append(
            {
                "name": name,
                "version": str(version),
                "ecosystem": "npm",
                "package_manager": "npm",
                "dependency_scope": "transitive",
                "direct_or_transitive": "transitive",
                "source_manifest": path.name,
            }
        )
    return dependencies


def analyze_js_tree(root: Path) -> JsAnalysis:
    """Analyze JavaScript/TypeScript source files and npm manifests under ``root``."""

    imports: list[JsImportEvidence] = []
    dynamic_imports: list[dict[str, object]] = []
    parse_errors: list[dict[str, object]] = []
    for pattern in ("*.js", "*.mjs", "*.cjs", "*.ts"):
        for path in sorted(root.rglob(pattern)):
            if "node_modules" in path.parts:
                continue
            try:
                analysis = analyze_js_file(path)
            except Exception as exc:  # pragma: no cover - defensive parsing path
                parse_errors.append({"source_file": str(path), "error": str(exc)})
                continue
            imports.extend(analysis.imports)
            dynamic_imports.extend(analysis.dynamic_imports)

    declared = parse_package_json_dependencies(root / "package.json")
    direct_names = {item["name"] for item in declared if item["direct_or_transitive"] == "direct"}
    declared.extend(parse_package_lock_transitives(root / "package-lock.json", direct_names))
    return JsAnalysis(
        imports=imports,
        declared_dependencies=declared,
        dynamic_imports=dynamic_imports,
        parse_errors=parse_errors,
    )

