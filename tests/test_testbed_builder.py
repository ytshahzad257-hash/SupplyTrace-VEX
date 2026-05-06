from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from supplytrace.config import ProjectConfig
from supplytrace.testbed_builder.build_cases import (
    CATEGORY_COUNTS,
    build_testbed,
    validate_generated_corpus,
)


EXTERNAL_TARGET_RE = re.compile(r"https?://|ssh://|git://", re.IGNORECASE)


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def test_build_testbed_generates_50_cases(tmp_path: Path) -> None:
    config = _config(tmp_path)

    result = build_testbed(config)

    case_dirs = sorted(path for path in config.cases_dir.glob("case_*") if path.is_dir())
    assert result["case_count"] == 50
    assert len(case_dirs) == 50
    assert case_dirs[0].name == "case_001"
    assert case_dirs[-1].name == "case_050"


def test_every_case_has_metadata_and_required_files(tmp_path: Path) -> None:
    config = _config(tmp_path)
    build_testbed(config)

    for case_dir in sorted(config.cases_dir.glob("case_*")):
        assert (case_dir / "metadata.json").exists()
        assert (case_dir / "README.md").exists()
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["scanner_confirmation_status"] == "not_scanned"
        if metadata["ecosystem"] == "nodejs":
            assert (case_dir / "package.json").exists()
            assert (case_dir / "package-lock.json").exists()
        elif metadata["ecosystem"] == "python":
            assert (case_dir / "requirements.txt").exists()
            assert (case_dir / "requirements.lock").exists()
        elif metadata["ecosystem"] == "container":
            assert (case_dir / "Dockerfile").exists()
            assert (case_dir / "container-manifest.json").exists()


def test_ground_truth_files_exist_and_validate(tmp_path: Path) -> None:
    config = _config(tmp_path)
    build_testbed(config)

    validation = validate_generated_corpus(config)

    assert validation["case_count"] == 50
    assert (config.ground_truth_dir / "ground_truth.json").exists()
    assert (config.ground_truth_dir / "ground_truth.csv").exists()
    payload = json.loads((config.ground_truth_dir / "ground_truth.json").read_text(encoding="utf-8"))
    assert payload["case_count"] == 50
    assert len(payload["cases"]) == 50


def test_categories_are_distributed_correctly(tmp_path: Path) -> None:
    config = _config(tmp_path)
    build_testbed(config)

    counts: dict[str, int] = {}
    for metadata_path in config.cases_dir.glob("case_*/metadata.json"):
        category = json.loads(metadata_path.read_text(encoding="utf-8"))["category"]
        counts[category] = counts.get(category, 0) + 1

    assert counts == CATEGORY_COUNTS


def test_no_case_contains_external_target_urls(tmp_path: Path) -> None:
    config = _config(tmp_path)
    build_testbed(config)

    for path in config.cases_dir.rglob("*"):
        if path.is_file():
            assert not EXTERNAL_TARGET_RE.search(path.read_text(encoding="utf-8"))


def test_generated_files_are_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_testbed(_config(first))
    build_testbed(_config(second))

    assert _tree_digest(first / "testbed") == _tree_digest(second / "testbed")

