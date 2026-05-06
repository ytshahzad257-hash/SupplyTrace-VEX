from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from supplytrace.config import ProjectConfig
from supplytrace.run_context import CommandResult, UnsafeCommand, create_run_context
from supplytrace.scanners.base import run_scanner_pipeline, validate_local_command
from supplytrace.scanners.npm_audit import NpmAuditScanner


def _config(root: Path, scanners: tuple[str, ...] = ("osv",)) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
        scanners=scanners,
    )


def _case(root: Path, case_id: str = "case_001") -> Path:
    case_dir = root / "testbed" / "cases" / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "package.json").write_text(
        json.dumps({"name": "local-case", "version": "0.1.0", "dependencies": {"lodash": "4.17.20"}}),
        encoding="utf-8",
    )
    (case_dir / "package-lock.json").write_text(
        json.dumps({"name": "local-case", "lockfileVersion": 3, "packages": {}}),
        encoding="utf-8",
    )
    (case_dir / "metadata.json").write_text(
        json.dumps({"case_id": case_id, "ecosystem": "nodejs"}),
        encoding="utf-8",
    )
    return case_dir


def test_missing_scanner_records_unavailable_without_raw_output(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    _case(tmp_path)
    context = create_run_context(config, run_id="scan-test")
    monkeypatch.setattr("supplytrace.scanners.base.shutil.which", lambda _: None)

    result = run_scanner_pipeline(config, context)

    record = result["records"][0]
    assert record["status"] == "unavailable"
    assert record["tool_available"] is False
    assert record["output_path"] is None
    assert not (config.artifacts_dir / "scanner_raw" / "osv" / "case_001.json").exists()


def test_successful_scanner_output_is_saved(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    _case(tmp_path)
    context = create_run_context(config, run_id="scan-test")
    monkeypatch.setattr("supplytrace.scanners.base.shutil.which", lambda _: "osv-scanner")

    def fake_run(command, **kwargs):
        if "--version" in command:
            return CommandResult(tuple(command), 0, "osv-scanner 1.0.0\n", "", 0.01)
        return CommandResult(tuple(command), 0, '{"results":[]}\n', "", 0.02)

    monkeypatch.setattr("supplytrace.scanners.base.safe_subprocess_run", fake_run)

    result = run_scanner_pipeline(config, context)

    record = result["records"][0]
    output_path = config.artifacts_dir / "scanner_raw" / "osv" / "case_001.json"
    assert record["status"] == "success"
    assert record["tool_version"] == "osv-scanner 1.0.0"
    assert output_path.exists()
    assert json.loads(output_path.read_text(encoding="utf-8")) == {"results": []}


def test_failed_scanner_output_saves_failure_metadata(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    _case(tmp_path)
    context = create_run_context(config, run_id="scan-test")
    monkeypatch.setattr("supplytrace.scanners.base.shutil.which", lambda _: "osv-scanner")

    def fake_run(command, **kwargs):
        if "--version" in command:
            return CommandResult(tuple(command), 0, "osv-scanner 1.0.0\n", "", 0.01)
        return CommandResult(tuple(command), 2, "not json\n", "failure detail\n", 0.02)

    monkeypatch.setattr("supplytrace.scanners.base.safe_subprocess_run", fake_run)

    result = run_scanner_pipeline(config, context)

    record = result["records"][0]
    assert record["status"] == "failed"
    assert record["exit_code"] == 2
    assert record["output_path"] is None
    assert (config.project_root / record["stdout_path"]).exists()
    assert (config.project_root / record["stderr_path"]).exists()


def test_scanner_metadata_files_are_created(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path, scanners=("osv", "npm-audit"))
    _case(tmp_path)
    context = create_run_context(config, run_id="scan-test")
    monkeypatch.setattr("supplytrace.scanners.base.shutil.which", lambda _: None)

    run_scanner_pipeline(config, context)

    metadata_json = config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.json"
    metadata_csv = config.artifacts_dir / "scanner_raw" / "scanner_execution_metadata.csv"
    assert metadata_json.exists()
    assert metadata_csv.exists()
    payload = json.loads(metadata_json.read_text(encoding="utf-8"))
    assert payload["execution_count"] == 2
    with metadata_csv.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert {row["scanner_name"] for row in rows} == {"osv", "npm_audit"}
    assert all(row["ecosystem"] == "nodejs" for row in rows)
    assert (config.artifacts_dir / "scanner_raw" / "scanner_summary.csv").exists()
    assert (config.artifacts_dir / "scanner_raw" / "scanner_summary.json").exists()


def test_external_url_blocking() -> None:
    with pytest.raises(UnsafeCommand):
        validate_local_command(["osv-scanner", "--format", "json", "https://example.invalid/project"])


def test_npm_audit_command_is_online_by_default(tmp_path: Path) -> None:
    config = _config(tmp_path, scanners=("npm-audit",))
    command = NpmAuditScanner().command_for_case(tmp_path, config)

    assert "--offline" not in command
    assert command[:3] == ["npm", "audit", "--json"]


def test_npm_audit_offline_mode_is_opt_in(tmp_path: Path) -> None:
    config = ProjectConfig(
        project_root=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
        testbed_dir=tmp_path / "testbed",
        scanners=("npm-audit",),
        npm_audit_offline=True,
    )

    command = NpmAuditScanner().command_for_case(tmp_path, config)

    assert "--offline" in command
