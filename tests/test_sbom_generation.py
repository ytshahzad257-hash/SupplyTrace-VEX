from __future__ import annotations

import csv
import json
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.run_context import create_run_context
from supplytrace.sbom.generator import generate_sboms
from supplytrace.sbom.parsers import parse_package_json, parse_requirements
from supplytrace.testbed_builder.build_cases import build_testbed


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def test_parse_package_json_dependencies(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.20"},
                "devDependencies": {"minimist": "0.0.8"},
            }
        ),
        encoding="utf-8",
    )

    components = parse_package_json(package_json)

    assert [(item.name, item.version, item.dependency_scope) for item in components] == [
        ("lodash", "4.17.20", "runtime"),
        ("minimist", "0.0.8", "development"),
    ]
    assert all(item.direct_or_transitive == "direct" for item in components)


def test_parse_requirements_dependencies(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "# local fixture\nPyYAML==5.3.1\nrequests==2.31.0 ; python_version >= '3.11'\n",
        encoding="utf-8",
    )

    components = parse_requirements(requirements)

    assert [(item.name, item.version, item.ecosystem) for item in components] == [
        ("PyYAML", "5.3.1", "pypi"),
        ("requests", "2.31.0", "pypi"),
    ]


def test_fallback_sbom_generation_for_every_case(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("supplytrace.sbom.generator.shutil.which", lambda _: None)
    monkeypatch.setattr("supplytrace.sbom.generator.importlib.util.find_spec", lambda _: None)
    config = _config(tmp_path)
    build_testbed(config)
    context = create_run_context(config, run_id="sbom-test")

    result = generate_sboms(config, context)

    assert result["case_count"] == 50
    internal_files = sorted((config.artifacts_dir / "sbom" / "internal").glob("case_*.json"))
    assert len(internal_files) == 50
    payload = json.loads((config.artifacts_dir / "sbom" / "internal" / "case_001.json").read_text(encoding="utf-8"))
    assert payload["format"] == "internal_fallback"
    assert payload["sbom_format"] == "internal_fallback"
    assert payload["tool_status"] == "generated"
    assert payload["components"]


def test_metadata_csv_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("supplytrace.sbom.generator.shutil.which", lambda _: None)
    monkeypatch.setattr("supplytrace.sbom.generator.importlib.util.find_spec", lambda _: None)
    config = _config(tmp_path)
    build_testbed(config)
    context = create_run_context(config, run_id="sbom-test")

    generate_sboms(config, context)

    metadata_path = config.artifacts_dir / "sbom" / "sbom_generation_metadata.csv"
    assert metadata_path.exists()
    with metadata_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 50
    assert rows[0]["case_id"] == "case_001"
    assert rows[0]["internal_tool_status"] == "generated"
    assert rows[0]["syft_tool_status"] == "unavailable"
    assert rows[0]["cyclonedx_tool_status"] == "unavailable"
    assert rows[0]["spdx_tool_status"] == "unavailable"
    assert rows[0]["sbom_completeness_score"] == "0.25"
    assert (config.artifacts_dir / "sbom" / "sbom_tool_summary.csv").exists()


def test_no_fake_external_sbom_output_when_tool_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("supplytrace.sbom.generator.shutil.which", lambda _: None)
    monkeypatch.setattr("supplytrace.sbom.generator.importlib.util.find_spec", lambda _: None)
    config = _config(tmp_path)
    build_testbed(config)
    context = create_run_context(config, run_id="sbom-test")

    generate_sboms(config, context)

    assert not (config.artifacts_dir / "sbom" / "cyclonedx" / "case_001.json").exists()
    assert not (config.artifacts_dir / "sbom" / "spdx" / "case_001.json").exists()
    assert not (config.artifacts_dir / "sbom" / "syft" / "case_001.json").exists()
    assert (config.artifacts_dir / "sbom" / "internal" / "case_001.json").exists()
