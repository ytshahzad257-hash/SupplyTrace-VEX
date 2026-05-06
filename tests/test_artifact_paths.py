from pathlib import Path

import pytest

from supplytrace.config import ProjectConfig, artifact_path


def test_artifact_path_rejects_unknown_kind(tmp_path: Path) -> None:
    config = ProjectConfig(
        project_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        testbed_dir=tmp_path / "testbed",
    )

    with pytest.raises(ValueError):
        artifact_path(config, "unknown")


def test_artifact_path_uses_configured_root(tmp_path: Path) -> None:
    config = ProjectConfig(
        project_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        testbed_dir=tmp_path / "testbed",
    )

    assert artifact_path(config, "sbom", "run-1", "index.json") == tmp_path / "artifacts" / "sbom" / "run-1" / "index.json"

