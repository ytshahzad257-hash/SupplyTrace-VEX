from __future__ import annotations

import csv
from pathlib import Path

from typer.testing import CliRunner

from supplytrace.cli import app
from supplytrace.config import ProjectConfig
from supplytrace.reporting.figures import FIGURE_OUTPUTS
from supplytrace.reporting.html_report import generate_html_report
from supplytrace.reporting.tables import TABLE_OUTPUTS
from supplytrace.run_context import create_run_context


runner = CliRunner()


def _config(root: Path) -> ProjectConfig:
    return ProjectConfig(
        project_root=root,
        artifacts_dir=root / "artifacts",
        testbed_dir=root / "testbed",
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_report_files_generated(tmp_path: Path) -> None:
    config = _config(tmp_path)

    result = generate_html_report(create_run_context(config, run_id="report-test"))

    assert Path(result["report_path"]).exists()
    assert Path(result["html_path"]).exists()
    assert Path(result["manuscript_support_path"]).exists()
    assert (config.artifacts_dir / "reports" / "report.md").exists()
    assert (config.artifacts_dir / "reports" / "report.html").exists()


def test_table_files_generated(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = generate_html_report(create_run_context(config, run_id="report-test"))

    table_paths = result["table_paths"]

    assert set(table_paths) == {filename for filename, _title in TABLE_OUTPUTS}
    for filename in table_paths:
        path = config.artifacts_dir / "reports" / "tables" / filename
        assert path.exists()
        assert path.read_text(encoding="utf-8").splitlines()[0]


def test_figure_data_generated(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = generate_html_report(create_run_context(config, run_id="report-test"))

    figure_paths = result["figure_paths"]

    assert set(figure_paths) == set(FIGURE_OUTPUTS)
    for filename in FIGURE_OUTPUTS:
        path = config.artifacts_dir / "figures_data" / filename
        assert path.exists()
        assert path.read_text(encoding="utf-8")


def test_missing_data_handled_without_fake_metrics(tmp_path: Path) -> None:
    config = _config(tmp_path)
    generate_html_report(create_run_context(config, run_id="report-test"))

    report = (config.artifacts_dir / "reports" / "report.md").read_text(encoding="utf-8")
    manuscript = (config.project_root / "docs" / "manuscript_support.md").read_text(encoding="utf-8")
    alert_rows = _read_csv(config.artifacts_dir / "figures_data" / "alert_reduction.csv")

    assert "missing" in report.lower()
    assert "not_available" in report
    assert "no normalized scanner findings" in manuscript.lower()
    assert alert_rows[0]["status"] == "not_available"
    assert alert_rows[0]["value"] == "0.0"
    assert "do not claim prioritization improvement" in report.lower()
    assert "do not claim prioritization improvement because no scanner-confirmed findings were normalized" in manuscript.lower()


def test_report_cli_generates_markdown_html_tables_and_figures(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "--project-root", str(tmp_path), "--run-id", "report-cli"])

    assert result.exit_code == 0
    assert (tmp_path / "artifacts" / "reports" / "report.md").exists()
    assert (tmp_path / "artifacts" / "reports" / "report.html").exists()
    assert (tmp_path / "docs" / "manuscript_support.md").exists()
    assert (tmp_path / "artifacts" / "reports" / "tables" / "table_01_testbed_taxonomy.csv").exists()
    assert (tmp_path / "artifacts" / "figures_data" / "pipeline_mermaid.md").exists()
