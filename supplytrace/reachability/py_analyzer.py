"""Static Python dependency reachability analyzer."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path

from supplytrace.sbom.parsers import parse_requirements


COMMON_IMPORT_TO_PACKAGE: dict[str, str] = {
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "flask": "Flask",
    "pil": "Pillow",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
}


@dataclass(frozen=True)
class PythonImportEvidence:
    """One Python import observation."""

    module: str
    imported_name: str
    local_name: str
    source_file: str
    line: int
    import_type: str
    used_in_call: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PythonAnalysis:
    """Static Python analysis result for one source tree."""

    imports: list[PythonImportEvidence]
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


def normalize_name(value: str) -> str:
    """Normalize package/import names for approximate matching."""

    return value.lower().replace("_", "-").replace(".", "-")


def imported_modules(path: Path) -> set[str]:
    """Return root modules imported by a Python file."""

    return {item.module for item in analyze_python_file(path).imports}


def _call_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            roots.add(func.id)
        elif isinstance(func, ast.Attribute):
            value = func.value
            while isinstance(value, ast.Attribute):
                value = value.value
            if isinstance(value, ast.Name):
                roots.add(value.id)
    return roots


def _dynamic_imports(tree: ast.AST, path: Path) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        dynamic = False
        name = None
        if isinstance(func, ast.Name) and func.id in {"__import__", "import_module"}:
            dynamic = True
            name = func.id
        elif isinstance(func, ast.Attribute) and func.attr == "import_module":
            dynamic = True
            name = "import_module"
        if dynamic:
            observations.append(
                {
                    "source_file": str(path),
                    "line": getattr(node, "lineno", None),
                    "call": name,
                    "reason": "dynamic import requires runtime evaluation",
                }
            )
    return observations


def analyze_python_file(path: Path) -> PythonAnalysis:
    """Analyze imports in one Python file using AST without executing code."""

    parse_errors: list[dict[str, object]] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return PythonAnalysis(
            imports=[],
            declared_dependencies=[],
            dynamic_imports=[],
            parse_errors=[{"source_file": str(path), "error": str(exc)}],
        )

    call_roots = _call_roots(tree)
    observations: list[PythonImportEvidence] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                local_name = alias.asname or module
                observations.append(
                    PythonImportEvidence(
                        module=module,
                        imported_name=alias.name,
                        local_name=local_name,
                        source_file=str(path),
                        line=getattr(node, "lineno", 0),
                        import_type="import",
                        used_in_call=local_name in call_roots,
                    )
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module.split(".")[0]
            for alias in node.names:
                local_name = alias.asname or alias.name
                observations.append(
                    PythonImportEvidence(
                        module=module,
                        imported_name=f"{node.module}.{alias.name}",
                        local_name=local_name,
                        source_file=str(path),
                        line=getattr(node, "lineno", 0),
                        import_type="from_import",
                        used_in_call=local_name in call_roots,
                    )
                )

    return PythonAnalysis(
        imports=observations,
        declared_dependencies=[],
        dynamic_imports=_dynamic_imports(tree, path),
        parse_errors=parse_errors,
    )


def map_import_to_package(module: str, declared_package_names: set[str]) -> str | None:
    """Map an import root to a declared package name where possible."""

    normalized_declared = {normalize_name(name): name for name in declared_package_names}
    normalized_module = normalize_name(module)
    if normalized_module in normalized_declared:
        return normalized_declared[normalized_module]
    mapped = COMMON_IMPORT_TO_PACKAGE.get(module.lower())
    if mapped and normalize_name(mapped) in normalized_declared:
        return normalized_declared[normalize_name(mapped)]
    return None


def declared_requirements(root: Path) -> list[dict[str, object]]:
    """Return dependencies declared in local requirements files."""

    dependencies: list[dict[str, object]] = []
    for filename, scope in (("requirements.txt", "runtime"), ("requirements-dev.txt", "development")):
        for component in parse_requirements(root / filename, scope=scope):
            dependencies.append(component.to_dict())
    for component in parse_requirements(root / "requirements.lock", scope="transitive", direct_or_transitive="transitive"):
        if not any(
            item["name"].lower() == component.name.lower() and item["version"] == component.version
            for item in dependencies
        ):
            dependencies.append(component.to_dict())
    return dependencies


def analyze_python_tree(root: Path) -> PythonAnalysis:
    """Analyze Python source files and requirements manifests under ``root``."""

    imports: list[PythonImportEvidence] = []
    dynamic_imports: list[dict[str, object]] = []
    parse_errors: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part.startswith(".") for part in relative.parts):
            continue
        analysis = analyze_python_file(path)
        imports.extend(analysis.imports)
        dynamic_imports.extend(analysis.dynamic_imports)
        parse_errors.extend(analysis.parse_errors)
    return PythonAnalysis(
        imports=imports,
        declared_dependencies=declared_requirements(root),
        dynamic_imports=dynamic_imports,
        parse_errors=parse_errors,
    )

