"""Build deterministic local testbed projects for research runs.

The generated corpus encodes expected project-context labels. It does not
claim scanner-confirmed vulnerabilities, exploitability, or real-world impact.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from supplytrace.config import ProjectConfig
from supplytrace.run_context import write_json


CATEGORIES: tuple[str, ...] = (
    "vulnerable_reachable_direct",
    "vulnerable_unreachable_direct",
    "vulnerable_reachable_transitive",
    "vulnerable_dev_only",
    "patched_dependency",
    "container_vulnerable_layer",
    "clean_control",
)

CATEGORY_COUNTS: dict[str, int] = {
    "vulnerable_reachable_direct": 8,
    "vulnerable_unreachable_direct": 8,
    "vulnerable_reachable_transitive": 8,
    "vulnerable_dev_only": 7,
    "patched_dependency": 7,
    "container_vulnerable_layer": 6,
    "clean_control": 6,
}

ACTIONABILITY_LABELS: tuple[str, ...] = (
    "actionable",
    "non_actionable",
    "fixed",
    "clean",
    "unknown_until_scanned",
)

REQUIRED_METADATA_FIELDS: tuple[str, ...] = (
    "case_id",
    "ecosystem",
    "category",
    "intended_case_type",
    "package_manager",
    "vulnerable_package_expected",
    "vulnerable_version_expected",
    "expected_dependency_scope",
    "expected_dependency_context",
    "expected_reachability",
    "expected_actionability_label",
    "scanner_confirmed_vulnerability",
    "scanner_confirmation_source",
    "notes",
    "explanation",
    "safety_note",
)

EXTERNAL_TARGET_PATTERN = re.compile(r"https?://|ssh://|git://", re.IGNORECASE)


@dataclass(frozen=True)
class DependencySpec:
    name: str
    version: str
    scope: str
    ecosystem: str


@dataclass(frozen=True)
class TestbedCase:
    case_id: str
    ecosystem: str
    category: str
    package_manager: str
    vulnerable_package_expected: str | None
    vulnerable_version_expected: str | None
    expected_dependency_scope: str
    expected_reachability: str
    expected_actionability_label: str
    explanation: str
    safety_note: str
    dependencies: tuple[DependencySpec, ...]
    files: dict[str, str]

    def metadata(self) -> dict[str, object]:
        payload = {
            "case_id": self.case_id,
            "ecosystem": self.ecosystem,
            "category": self.category,
            "intended_case_type": self.category,
            "package_manager": self.package_manager,
            "vulnerable_package_expected": self.vulnerable_package_expected,
            "vulnerable_version_expected": self.vulnerable_version_expected,
            "expected_dependency_scope": self.expected_dependency_scope,
            "expected_dependency_context": {
                "scope": self.expected_dependency_scope,
                "reachability": self.expected_reachability,
                "actionability_label": self.expected_actionability_label,
                "package_under_study": self.vulnerable_package_expected,
                "version_under_study": self.vulnerable_version_expected,
            },
            "expected_reachability": self.expected_reachability,
            "expected_actionability_label": self.expected_actionability_label,
            "scanner_confirmed_vulnerability": None,
            "scanner_confirmation_source": None,
            "notes": (
                "Scanner confirmation is intentionally unset until local scanner output is generated "
                "and normalized by the pipeline."
            ),
            "explanation": self.explanation,
            "safety_note": self.safety_note,
            "dependencies": [asdict(item) for item in self.dependencies],
            "scanner_confirmation_status": "not_scanned",
            "ground_truth_scope": (
                "Project-context expectation for local research only; this metadata "
                "does not assert scanner-confirmed vulnerability presence."
            ),
        }
        validate_metadata(payload)
        return payload


NODE_SCENARIOS: dict[str, dict[str, object]] = {
    "vulnerable_reachable_direct": {
        "package": "lodash",
        "version": "4.17.20",
        "patched_version": "4.17.21",
        "source": 'const lodash = require("lodash");\n\nfunction normalize(items) {\n  return lodash.uniq(items.map((item) => String(item).trim()).filter(Boolean));\n}\n\nmodule.exports = { normalize };\n',
    },
    "vulnerable_unreachable_direct": {
        "package": "minimist",
        "version": "0.0.8",
        "patched_version": "1.2.8",
        "source": 'function parseLocalFlag(value) {\n  return { enabled: value === "yes" };\n}\n\nmodule.exports = { parseLocalFlag };\n',
    },
    "vulnerable_reachable_transitive": {
        "direct_package": "express",
        "direct_version": "4.16.0",
        "package": "qs",
        "version": "6.5.1",
        "source": 'const express = require("express");\n\nfunction createApp() {\n  const app = express();\n  app.set("case-mode", "local-only");\n  return app;\n}\n\nmodule.exports = { createApp };\n',
    },
    "vulnerable_dev_only": {
        "package": "minimist",
        "version": "0.0.8",
        "source": 'function buildMessage(name) {\n  return `local build fixture: ${name}`;\n}\n\nmodule.exports = { buildMessage };\n',
    },
    "patched_dependency": {
        "package": "lodash",
        "version": "4.17.21",
        "source": 'const lodash = require("lodash");\n\nfunction normalize(items) {\n  return lodash.compact(items.map((item) => String(item).trim()));\n}\n\nmodule.exports = { normalize };\n',
    },
    "clean_control": {
        "package": "nanoid",
        "version": "5.0.7",
        "source": 'function localId(seed) {\n  return `case-${seed}`;\n}\n\nmodule.exports = { localId };\n',
    },
}

PYTHON_SCENARIOS: dict[str, dict[str, object]] = {
    "vulnerable_reachable_direct": {
        "package": "PyYAML",
        "version": "5.3.1",
        "patched_version": "6.0.1",
        "import_name": "yaml",
        "source": '"""Local fixture using a dependency without network activity."""\n\nimport yaml\n\n\ndef parse_config(text: str) -> object:\n    return yaml.safe_load(text)\n',
    },
    "vulnerable_unreachable_direct": {
        "package": "requests",
        "version": "2.19.1",
        "patched_version": "2.31.0",
        "import_name": None,
        "source": '"""Local fixture with an intentionally unused declared dependency."""\n\n\ndef summarize(values: list[str]) -> dict[str, int]:\n    return {"count": len(values)}\n',
    },
    "vulnerable_reachable_transitive": {
        "direct_package": "Flask",
        "direct_version": "0.12.2",
        "package": "Jinja2",
        "version": "2.10",
        "import_name": "flask",
        "source": '"""Local fixture importing a direct framework dependency."""\n\nimport flask\n\n\ndef create_app() -> flask.Flask:\n    app = flask.Flask(__name__)\n    app.config["SUPPLYTRACE_LOCAL_ONLY"] = True\n    return app\n',
    },
    "vulnerable_dev_only": {
        "package": "urllib3",
        "version": "1.24.1",
        "import_name": None,
        "source": '"""Runtime source does not import the development-only dependency."""\n\n\ndef add(left: int, right: int) -> int:\n    return left + right\n',
    },
    "patched_dependency": {
        "package": "PyYAML",
        "version": "6.0.2",
        "import_name": "yaml",
        "source": '"""Local fixture using a patched dependency candidate."""\n\nimport yaml\n\n\ndef parse_config(text: str) -> object:\n    return yaml.safe_load(text)\n',
    },
    "clean_control": {
        "package": "packaging",
        "version": "24.1",
        "import_name": "packaging",
        "source": '"""Local clean-control fixture."""\n\nfrom packaging.version import Version\n\n\ndef normalize_version(value: str) -> str:\n    return str(Version(value))\n',
    },
}

CONTAINER_SCENARIOS: tuple[dict[str, str], ...] = (
    {
        "base": "scratch",
        "package": "openssl",
        "version": "1.1.1d-0+deb10u3",
    },
    {
        "base": "scratch",
        "package": "libssl1.1",
        "version": "1.1.1d-0+deb10u3",
    },
    {
        "base": "scratch",
        "package": "libc6",
        "version": "2.28-10",
    },
)


def validate_metadata(metadata: dict[str, object]) -> None:
    """Validate per-case metadata before writing it to disk."""

    missing = [field for field in REQUIRED_METADATA_FIELDS if field not in metadata]
    if missing:
        raise ValueError(f"metadata missing required fields: {', '.join(missing)}")

    category = str(metadata["category"])
    if category not in CATEGORIES:
        raise ValueError(f"unsupported category: {category}")

    label = str(metadata["expected_actionability_label"])
    if label not in ACTIONABILITY_LABELS:
        raise ValueError(f"unsupported actionability label: {label}")

    case_id = str(metadata["case_id"])
    if not re.fullmatch(r"case_\d{3}", case_id):
        raise ValueError(f"case_id must use case_NNN format: {case_id}")

    text = json.dumps(metadata, sort_keys=True)
    if EXTERNAL_TARGET_PATTERN.search(text):
        raise ValueError(f"metadata contains an external target marker: {case_id}")


def validate_case_files(case: TestbedCase) -> None:
    """Validate generated file content for local-only safety constraints."""

    for relative_path, content in case.files.items():
        if EXTERNAL_TARGET_PATTERN.search(content):
            raise ValueError(f"{case.case_id}/{relative_path} contains an external target URL")


def _json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _node_lockfile(
    case_name: str,
    dependencies: Iterable[DependencySpec],
    *,
    transitive_parent: DependencySpec | None = None,
) -> str:
    root_deps = {
        dep.name: dep.version
        for dep in dependencies
        if dep.scope in {"runtime", "development"}
    }
    packages: dict[str, object] = {
        "": {
            "name": case_name,
            "version": "0.1.0",
            "dependencies": {
                dep.name: dep.version
                for dep in dependencies
                if dep.scope == "runtime" and dep.name in root_deps
            },
            "devDependencies": {
                dep.name: dep.version
                for dep in dependencies
                if dep.scope == "development"
            },
        }
    }
    for dep in dependencies:
        if dep.scope == "transitive":
            continue
        package_entry: dict[str, object] = {"version": dep.version}
        if transitive_parent and dep.name == transitive_parent.name:
            package_entry["dependencies"] = {"qs": "6.5.1"}
        packages[f"node_modules/{dep.name}"] = package_entry
    for dep in dependencies:
        if dep.scope == "transitive":
            packages[f"node_modules/{dep.name}"] = {"version": dep.version}

    return _json(
        {
            "name": case_name,
            "version": "0.1.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": packages,
        }
    )


def _python_lockfile(dependencies: Iterable[DependencySpec]) -> str:
    return "".join(f"{dep.name}=={dep.version}\n" for dep in dependencies)


def _readme(case: TestbedCase) -> str:
    expected_package = case.vulnerable_package_expected or "none"
    expected_version = case.vulnerable_version_expected or "none"
    return f"""# {case.case_id}

This is a controlled local SupplyTrace-VEX testbed case.

- Ecosystem: {case.ecosystem}
- Category: {case.category}
- Package manager: {case.package_manager}
- Expected package under study: {expected_package}
- Expected version under study: {expected_version}
- Expected actionability label: {case.expected_actionability_label}

The metadata records intended project-context expectations for local research. It is not scanner output and does not assert universal CVE truth. The source files avoid exploit payloads, network calls, and third-party targets.
"""


def _node_case(case_id: str, category: str, variant: int) -> TestbedCase:
    scenario = NODE_SCENARIOS[category]
    case_name = f"supplytrace-{case_id}"
    dependencies: list[DependencySpec]
    expected_scope: str
    expected_reachability: str
    expected_label: str

    if category == "vulnerable_reachable_transitive":
        direct = DependencySpec(
            name=str(scenario["direct_package"]),
            version=str(scenario["direct_version"]),
            scope="runtime",
            ecosystem="npm",
        )
        transitive = DependencySpec(
            name=str(scenario["package"]),
            version=str(scenario["version"]),
            scope="transitive",
            ecosystem="npm",
        )
        dependencies = [direct, transitive]
        expected_scope = "transitive"
        expected_reachability = "reachable_via_imported_parent"
        expected_label = "actionable"
        lockfile = _node_lockfile(case_name, dependencies, transitive_parent=direct)
    elif category == "vulnerable_dev_only":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="development",
                ecosystem="npm",
            )
        ]
        expected_scope = "development"
        expected_reachability = "not_reachable_from_runtime_source"
        expected_label = "non_actionable"
        lockfile = _node_lockfile(case_name, dependencies)
    elif category == "vulnerable_unreachable_direct":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="npm",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "declared_but_not_imported"
        expected_label = "non_actionable"
        lockfile = _node_lockfile(case_name, dependencies)
    elif category == "patched_dependency":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="npm",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "reachable_patched_version"
        expected_label = "fixed"
        lockfile = _node_lockfile(case_name, dependencies)
    elif category == "clean_control":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="npm",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "no_expected_vulnerable_dependency"
        expected_label = "clean"
        lockfile = _node_lockfile(case_name, dependencies)
    else:
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="npm",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "direct_import_observed"
        expected_label = "actionable"
        lockfile = _node_lockfile(case_name, dependencies)

    package_json = {
        "name": case_name,
        "version": "0.1.0",
        "private": True,
        "type": "commonjs",
        "scripts": {"test": "node src/index.js"},
        "dependencies": {
            dep.name: dep.version
            for dep in dependencies
            if dep.scope == "runtime"
        },
        "devDependencies": {
            dep.name: dep.version
            for dep in dependencies
            if dep.scope == "development"
        },
    }

    vulnerable_package = None if category == "clean_control" else str(scenario["package"])
    vulnerable_version = None if category == "clean_control" else str(scenario["version"])
    case = TestbedCase(
        case_id=case_id,
        ecosystem="nodejs",
        category=category,
        package_manager="npm",
        vulnerable_package_expected=vulnerable_package,
        vulnerable_version_expected=vulnerable_version,
        expected_dependency_scope=expected_scope,
        expected_reachability=expected_reachability,
        expected_actionability_label=expected_label,
        explanation=(
            f"Intended {category} Node.js fixture variant {variant}. "
            "The label describes project-context actionability before scanner confirmation."
        ),
        safety_note="Local source fixture only; it contains no exploit payloads, network calls, or external targets.",
        dependencies=tuple(dependencies),
        files={
            "package.json": _json(package_json),
            "package-lock.json": lockfile,
            "src/index.js": str(scenario["source"]),
        },
    )
    case.files["README.md"] = _readme(case)
    case.files["metadata.json"] = _json(case.metadata())
    validate_case_files(case)
    return case


def _python_case(case_id: str, category: str, variant: int) -> TestbedCase:
    scenario = PYTHON_SCENARIOS[category]
    dependencies: list[DependencySpec]
    expected_scope: str
    expected_reachability: str
    expected_label: str

    if category == "vulnerable_reachable_transitive":
        direct = DependencySpec(
            name=str(scenario["direct_package"]),
            version=str(scenario["direct_version"]),
            scope="runtime",
            ecosystem="pypi",
        )
        transitive = DependencySpec(
            name=str(scenario["package"]),
            version=str(scenario["version"]),
            scope="transitive",
            ecosystem="pypi",
        )
        dependencies = [direct, transitive]
        expected_scope = "transitive"
        expected_reachability = "reachable_via_imported_parent"
        expected_label = "actionable"
    elif category == "vulnerable_dev_only":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="development",
                ecosystem="pypi",
            )
        ]
        expected_scope = "development"
        expected_reachability = "not_reachable_from_runtime_source"
        expected_label = "non_actionable"
    elif category == "vulnerable_unreachable_direct":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="pypi",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "declared_but_not_imported"
        expected_label = "non_actionable"
    elif category == "patched_dependency":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="pypi",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "reachable_patched_version"
        expected_label = "fixed"
    elif category == "clean_control":
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="pypi",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "no_expected_vulnerable_dependency"
        expected_label = "clean"
    else:
        dependencies = [
            DependencySpec(
                name=str(scenario["package"]),
                version=str(scenario["version"]),
                scope="runtime",
                ecosystem="pypi",
            )
        ]
        expected_scope = "runtime"
        expected_reachability = "direct_import_observed"
        expected_label = "actionable"

    runtime_requirements = "".join(
        f"{dep.name}=={dep.version}\n"
        for dep in dependencies
        if dep.scope == "runtime"
    )
    dev_requirements = "".join(
        f"{dep.name}=={dep.version}\n"
        for dep in dependencies
        if dep.scope == "development"
    )

    vulnerable_package = None if category == "clean_control" else str(scenario["package"])
    vulnerable_version = None if category == "clean_control" else str(scenario["version"])
    case = TestbedCase(
        case_id=case_id,
        ecosystem="python",
        category=category,
        package_manager="pip",
        vulnerable_package_expected=vulnerable_package,
        vulnerable_version_expected=vulnerable_version,
        expected_dependency_scope=expected_scope,
        expected_reachability=expected_reachability,
        expected_actionability_label=expected_label,
        explanation=(
            f"Intended {category} Python fixture variant {variant}. "
            "The label describes project-context actionability before scanner confirmation."
        ),
        safety_note="Local source fixture only; it contains no exploit payloads, network calls, or external targets.",
        dependencies=tuple(dependencies),
        files={
            "requirements.txt": runtime_requirements,
            "requirements-dev.txt": dev_requirements,
            "requirements.lock": _python_lockfile(dependencies),
            "app/main.py": str(scenario["source"]),
        },
    )
    case.files["README.md"] = _readme(case)
    case.files["metadata.json"] = _json(case.metadata())
    validate_case_files(case)
    return case


def _container_case(case_id: str, category: str, variant: int) -> TestbedCase:
    scenario = CONTAINER_SCENARIOS[(variant - 1) % len(CONTAINER_SCENARIOS)]
    package = scenario["package"]
    version = scenario["version"]
    dependencies = (
        DependencySpec(
            name=package,
            version=version,
            scope="container_layer",
            ecosystem="linux-package",
        ),
    )
    manifest = {
        "base_image_expected": scenario["base"],
        "packages_expected": [asdict(dep) for dep in dependencies],
        "scanner_confirmation_status": "not_scanned",
        "note": "Container package expectations are intended local context for image scanning experiments.",
    }
    source = 'def describe_case() -> str:\n    return "local container context fixture"\n'
    layer_note = (
        f"expected_package={package}\n"
        f"expected_version={version}\n"
        "scanner_confirmation_status=not_scanned\n"
    )
    dockerfile = f"""FROM {scenario["base"]}
LABEL org.opencontainers.image.title="supplytrace-{case_id}"
COPY container-layer.txt /container-layer.txt
"""
    case = TestbedCase(
        case_id=case_id,
        ecosystem="container",
        category=category,
        package_manager="dockerfile",
        vulnerable_package_expected=package,
        vulnerable_version_expected=version,
        expected_dependency_scope="container_layer",
        expected_reachability="present_in_base_layer_until_scanned",
        expected_actionability_label="unknown_until_scanned",
        explanation=(
            f"Intended container layer fixture variant {variant}. "
            "Actionability remains unknown until a local image scanner confirms package evidence."
        ),
        safety_note="Dockerfile builds a local fixture image and does not contact application targets or run exploit code.",
        dependencies=dependencies,
        files={
            "Dockerfile": dockerfile,
            "container-manifest.json": _json(manifest),
            "container-layer.txt": layer_note,
            "app/main.py": source,
        },
    )
    case.files["README.md"] = _readme(case)
    case.files["metadata.json"] = _json(case.metadata())
    validate_case_files(case)
    return case


def _ecosystem_for(category: str, variant: int) -> str:
    if category == "container_vulnerable_layer":
        return "container"
    if variant % 2 == 0:
        return "python"
    return "nodejs"


def build_case_specs() -> list[TestbedCase]:
    """Return the deterministic 50-case corpus in case ID order."""

    cases: list[TestbedCase] = []
    ordinal = 1
    for category in CATEGORIES:
        for variant in range(1, CATEGORY_COUNTS[category] + 1):
            case_id = f"case_{ordinal:03d}"
            ecosystem = _ecosystem_for(category, variant)
            if ecosystem == "nodejs":
                cases.append(_node_case(case_id, category, variant))
            elif ecosystem == "python":
                cases.append(_python_case(case_id, category, variant))
            else:
                cases.append(_container_case(case_id, category, variant))
            ordinal += 1
    return cases


def _ground_truth_row(case: TestbedCase) -> dict[str, object]:
    metadata = case.metadata()
    row = {field: metadata[field] for field in REQUIRED_METADATA_FIELDS}
    row["expected_dependency_context"] = json.dumps(row["expected_dependency_context"], sort_keys=True)
    return row


def _write_ground_truth_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(REQUIRED_METADATA_FIELDS))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _relative_to_root(config: ProjectConfig, path: Path) -> str:
    try:
        return path.relative_to(config.project_root).as_posix()
    except ValueError:
        return path.as_posix()


def validate_generated_corpus(config: ProjectConfig) -> dict[str, object]:
    """Validate generated case directories and aggregate ground truth files."""

    case_dirs = sorted(path for path in config.cases_dir.glob("case_*") if path.is_dir())
    if len(case_dirs) != 50:
        raise ValueError(f"expected 50 generated case directories, found {len(case_dirs)}")

    category_counts = {category: 0 for category in CATEGORIES}
    for case_dir in case_dirs:
        metadata_path = case_dir / "metadata.json"
        if not metadata_path.exists():
            raise ValueError(f"missing metadata.json for {case_dir.name}")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        validate_metadata(metadata)
        category_counts[str(metadata["category"])] += 1
        for file_path in case_dir.rglob("*"):
            if file_path.is_file() and EXTERNAL_TARGET_PATTERN.search(file_path.read_text(encoding="utf-8", errors="ignore")):
                raise ValueError(f"external target marker found in {file_path}")

    if category_counts != CATEGORY_COUNTS:
        raise ValueError(f"category distribution mismatch: {category_counts}")
    if not (config.ground_truth_dir / "ground_truth.json").exists():
        raise ValueError("missing ground_truth.json")
    if not (config.ground_truth_dir / "ground_truth.csv").exists():
        raise ValueError("missing ground_truth.csv")
    return {
        "case_count": len(case_dirs),
        "category_counts": category_counts,
        "ground_truth_json": _relative_to_root(config, config.ground_truth_dir / "ground_truth.json"),
        "ground_truth_csv": _relative_to_root(config, config.ground_truth_dir / "ground_truth.csv"),
    }


def build_testbed(config: ProjectConfig, *, overwrite: bool = False) -> dict[str, object]:
    """Create 50 local testbed cases and project-context ground truth files."""

    config.cases_dir.mkdir(parents=True, exist_ok=True)
    config.ground_truth_dir.mkdir(parents=True, exist_ok=True)

    cases = build_case_specs()
    built_cases: list[dict[str, object]] = []
    ground_truth_rows: list[dict[str, object]] = []

    for case in cases:
        case_dir = config.cases_dir / case.case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        written_files: list[str] = []
        skipped_files: list[str] = []

        for relative_path, content in sorted(case.files.items()):
            target = case_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and not overwrite:
                skipped_files.append(relative_path)
                continue
            target.write_text(content, encoding="utf-8", newline="\n")
            written_files.append(relative_path)

        metadata = case.metadata()
        ground_truth_rows.append(_ground_truth_row(case))
        built_cases.append(
            {
                "case_id": case.case_id,
                "path": _relative_to_root(config, case_dir),
                "ecosystem": case.ecosystem,
                "category": case.category,
                "metadata": _relative_to_root(config, case_dir / "metadata.json"),
                "written_files": written_files,
                "skipped_files": skipped_files,
            }
        )
        if "metadata.json" in skipped_files and overwrite:
            raise RuntimeError(f"metadata was unexpectedly skipped for {case.case_id}")
        validate_metadata(metadata)

    ground_truth_payload = {
        "schema_version": "1.0",
        "case_count": len(cases),
        "category_counts": CATEGORY_COUNTS,
        "ground_truth_scope": (
            "Expected project-context actionability labels for controlled local cases; "
            "not scanner-confirmed vulnerability findings."
        ),
        "cases": ground_truth_rows,
    }
    write_json(config.ground_truth_dir / "ground_truth.json", ground_truth_payload)
    _write_ground_truth_csv(config.ground_truth_dir / "ground_truth.csv", ground_truth_rows)
    write_json(
        config.ground_truth_dir / "index.json",
        {
            "cases": built_cases,
            "ground_truth_json": _relative_to_root(config, config.ground_truth_dir / "ground_truth.json"),
            "ground_truth_csv": _relative_to_root(config, config.ground_truth_dir / "ground_truth.csv"),
            "ground_truth_scope": ground_truth_payload["ground_truth_scope"],
        },
    )
    validation = validate_generated_corpus(config)
    return {
        "case_count": len(cases),
        "cases": built_cases,
        "validation": validation,
        "ground_truth_scope": ground_truth_payload["ground_truth_scope"],
    }
