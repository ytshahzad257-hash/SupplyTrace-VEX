from pathlib import Path

from typer.testing import CliRunner

from supplytrace.cli import app


runner = CliRunner()


def test_help_displays_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "build-testbed" in result.stdout
    assert "debug-evidence" in result.stdout
    assert "evidence-check" in result.stdout
    assert "run-all" in result.stdout


def test_evidence_check_command_writes_outputs_without_tests(tmp_path: Path) -> None:
    result = runner.invoke(app, ["evidence-check", "--project-root", str(tmp_path), "--run-id", "cli-evidence", "--skip-tests"])

    assert result.exit_code == 0
    assert (tmp_path / "artifacts" / "audit" / "evidence_readiness_report.md").exists()
    assert (tmp_path / "artifacts" / "audit" / "evidence_readiness_summary.csv").exists()


def test_build_testbed_command_creates_local_cases(tmp_path: Path) -> None:
    result = runner.invoke(app, ["build-testbed", "--project-root", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / "testbed" / "cases" / "case_001" / "metadata.json").exists()
    assert (tmp_path / "testbed" / "cases" / "case_050" / "metadata.json").exists()
    assert (tmp_path / "testbed" / "ground_truth" / "ground_truth.json").exists()
    assert (tmp_path / "testbed" / "ground_truth" / "ground_truth.csv").exists()
