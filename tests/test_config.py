from pathlib import Path

from supplytrace.config import ARTIFACT_SUBDIRS, ProjectConfig, ensure_artifact_dirs, load_config
from supplytrace.run_context import generate_run_id


def test_ensure_artifact_dirs_creates_expected_paths(tmp_path: Path) -> None:
    config = ProjectConfig(
        project_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        testbed_dir=tmp_path / "testbed",
    )

    paths = ensure_artifact_dirs(config)

    assert set(paths) == set(ARTIFACT_SUBDIRS)
    for path in paths.values():
        assert path.exists()
        assert path.is_dir()
    assert config.cases_dir.exists()
    assert config.ground_truth_dir.exists()


def test_generate_run_id_is_sortable_shape() -> None:
    run_id = generate_run_id()

    assert "T" in run_id
    assert run_id.endswith(run_id.split("-")[-1])
    assert len(run_id.split("-")[-1]) == 8


def test_npm_audit_offline_defaults_false(tmp_path: Path) -> None:
    config = load_config(project_root=tmp_path, env_file=tmp_path / "missing.env")

    assert config.npm_audit_offline is False


def test_npm_audit_offline_can_be_enabled_by_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SUPPLYTRACE_NPM_AUDIT_OFFLINE=true\n", encoding="utf-8")

    config = load_config(project_root=tmp_path, env_file=env_file)

    assert config.npm_audit_offline is True
