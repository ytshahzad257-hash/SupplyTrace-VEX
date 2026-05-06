from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.reachability.graph_builder import analyze_case, analyze_reachability
from supplytrace.reachability.js_analyzer import analyze_js_file, imported_packages
from supplytrace.reachability.py_analyzer import analyze_python_file, imported_modules, map_import_to_package
from supplytrace.run_context import create_run_context


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def _case(root: Path, case_id: str = "case_001") -> Path:
    case_dir = root / "testbed" / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


def _write_package_json(case_dir: Path, dependencies: dict[str, str] | None = None, dev_dependencies: dict[str, str] | None = None) -> None:
    (case_dir / "package.json").write_text(
        json.dumps(
            {
                "name": case_dir.name,
                "version": "0.1.0",
                "dependencies": dependencies or {},
                "devDependencies": dev_dependencies or {},
            }
        ),
        encoding="utf-8",
    )


def _matrix_rows(config: ProjectConfig) -> list[dict[str, str]]:
    with (config.artifacts_dir / "reachability" / "reachability_matrix.csv").open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_python_import_extraction_and_package_mapping(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text("import yaml\nfrom packaging.version import Version\nvalue = yaml.safe_load('a: 1')\n", encoding="utf-8")

    analysis = analyze_python_file(source)

    assert imported_modules(source) == {"yaml", "packaging"}
    assert any(item.module == "yaml" and item.used_in_call for item in analysis.imports)
    assert map_import_to_package("yaml", {"PyYAML"}) == "PyYAML"


def test_js_import_and_require_extraction(tmp_path: Path) -> None:
    source = tmp_path / "index.js"
    source.write_text('const lodash = require("lodash");\nimport chalk from "chalk";\nlodash.uniq([]);\n', encoding="utf-8")

    analysis = analyze_js_file(source)

    assert imported_packages(source) == {"lodash", "chalk"}
    lodash = next(item for item in analysis.imports if item.package == "lodash")
    chalk = next(item for item in analysis.imports if item.package == "chalk")
    assert lodash.used_in_call is True
    assert chalk.used_in_call is False


def test_dev_dependency_classification(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case_dir = _case(tmp_path)
    _write_package_json(case_dir, dev_dependencies={"minimist": "0.0.8"})
    (case_dir / "src").mkdir()
    (case_dir / "src" / "index.js").write_text("module.exports = {};\n", encoding="utf-8")

    result = analyze_case(config, case_dir)

    row = result["matrix_rows"][0]
    assert row["package_name"] == "minimist"
    assert row["reachability_status"] == "dev_only"
    assert result["context_rows"][0]["dev_dependency"] is True


def test_declared_but_unused_dependency(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case_dir = _case(tmp_path)
    _write_package_json(case_dir, dependencies={"lodash": "4.17.20"})
    (case_dir / "src").mkdir()
    (case_dir / "src" / "index.js").write_text("function localOnly() { return 1; }\n", encoding="utf-8")

    row = analyze_case(config, case_dir)["matrix_rows"][0]

    assert row["reachability_status"] == "declared_not_used"
    assert row["imported"] is False


def test_unknown_dynamic_import_case(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case_dir = _case(tmp_path)
    _write_package_json(case_dir, dependencies={"lodash": "4.17.20"})
    (case_dir / "src").mkdir()
    (case_dir / "src" / "index.js").write_text('const name = "lodash";\nconst lib = require(name);\n', encoding="utf-8")

    row = analyze_case(config, case_dir)["matrix_rows"][0]

    assert row["reachability_status"] == "unknown"
    assert "dynamic import" in row["evidence_reason"]


def test_graph_json_generation(tmp_path: Path) -> None:
    config = _config(tmp_path)
    case_dir = _case(tmp_path)
    _write_package_json(case_dir, dependencies={"lodash": "4.17.20"})
    (case_dir / "src").mkdir()
    (case_dir / "src" / "index.js").write_text('const lodash = require("lodash");\nlodash.uniq([]);\n', encoding="utf-8")
    context = create_run_context(config, run_id="reachability-test")

    summary = analyze_reachability(config, context)

    graph_path = config.artifacts_dir / "reachability" / "dependency_graphs" / "case_001.json"
    assert graph_path.exists()
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert graph["case_id"] == "case_001"
    assert graph["nodes"]
    assert summary["dependency_count"] == 1
    assert _matrix_rows(config)[0]["reachability_status"] == "reachable"

