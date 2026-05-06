"""Typer-based command-line interface for SupplyTrace-VEX."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from supplytrace.config import load_config, to_project_relative_path
from supplytrace.audit import run_debug_evidence, run_evidence_check, run_publication_audit
from supplytrace.evaluation import evaluate_run
from supplytrace.logging_utils import configure_logging, get_logger
from supplytrace.normalize import normalize_findings
from supplytrace.reachability import analyze_reachability
from supplytrace.reporting.html_report import generate_html_report
from supplytrace.reporting.markdown_report import generate_markdown_report
from supplytrace.run_context import capture_tool_version, create_run_context, write_json
from supplytrace.scanners.base import run_scanner_pipeline
from supplytrace.sbom import generate_sboms
from supplytrace.scoring import score_findings
from supplytrace.testbed_builder import build_testbed as build_testbed_impl
from supplytrace.vex import generate_vex as generate_vex_impl


app = typer.Typer(
    name="supplytrace",
    help="Defensive local software supply-chain vulnerability prioritization research pipeline.",
    no_args_is_help=True,
)
logger = get_logger(__name__)


def _context(project_root: Optional[Path], run_id: Optional[str] = None):
    config = load_config(project_root)
    return config, create_run_context(config, run_id=run_id)


def _print_json(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("build-testbed")
def build_testbed(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite generated testbed files."),
) -> None:
    """Build deterministic local testbed projects."""

    configure_logging()
    config, _ = _context(project_root)
    payload = build_testbed_impl(config, overwrite=overwrite)
    _print_json(payload)


@app.command("generate-sbom")
def generate_sbom(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Generate manifest-derived SBOMs for local testbed cases."""

    configure_logging()
    config, context = _context(project_root, run_id)
    _print_json(generate_sboms(config, context))


@app.command("run-scans")
def run_scans(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Run configured scanners against local testbed case directories only."""

    configure_logging()
    config, context = _context(project_root, run_id)
    _print_json(run_scanner_pipeline(config, context))


@app.command("normalize")
def normalize(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Normalize raw scanner evidence into a shared schema."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(normalize_findings(context))


@app.command("analyze-reachability")
def reachability(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Analyze static dependency reachability in local testbed source."""

    configure_logging()
    config, context = _context(project_root, run_id)
    _print_json(analyze_reachability(config, context))


@app.command("score")
def score(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Score normalized findings using local context evidence."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(score_findings(context))


@app.command("generate-vex")
def generate_vex(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Generate VEX-style vulnerability status statements."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(generate_vex_impl(context))


@app.command("evaluate")
def evaluate(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Evaluate outputs when explicit local labels are available."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(evaluate_run(context))


@app.command("report")
def report(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
    html: bool = typer.Option(False, "--html", help="Compatibility flag; report now generates Markdown and HTML."),
) -> None:
    """Generate Markdown, HTML, table, figure, and manuscript-support artifacts."""

    configure_logging()
    _, context = _context(project_root, run_id)
    payload = generate_html_report(context)
    if not html:
        payload["note"] = "Markdown and HTML reports are both generated by default."
    _print_json(payload)


@app.command("audit")
def audit(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Run publication-readiness audit over generated local artifacts."""

    configure_logging()
    config, context = _context(project_root, run_id)
    tools = [
        ("python", ("--version",)),
        ("osv-scanner", ("--version",)),
        ("trivy", ("--version",)),
        ("grype", ("version",)),
        ("npm", ("--version",)),
        ("pip-audit", ("--version",)),
    ]
    payload = {
        "run_id": context.run_id,
        "project_root": to_project_relative_path(config.project_root, config),
        "tools": [capture_tool_version(tool, args) for tool, args in tools],
    }
    output_path = context.run_dir("audit") / "tool_versions.json"
    write_json(output_path, payload)
    audit_payload = run_publication_audit(context, run_tests=True)
    _print_json({**audit_payload, "tool_versions_path": to_project_relative_path(output_path, config)})


@app.command("evidence-check")
def evidence_check(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
    run_tests: bool = typer.Option(True, "--run-tests/--skip-tests", help="Run pytest as part of readiness scoring."),
) -> None:
    """Check whether generated artifacts are strong enough for paper-result claims."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(run_evidence_check(context, run_tests=run_tests))


@app.command("debug-evidence")
def debug_evidence(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
) -> None:
    """Diagnose why generated scanner evidence is empty or incomplete."""

    configure_logging()
    _, context = _context(project_root, run_id)
    _print_json(run_debug_evidence(context))


@app.command("run-all")
def run_all(
    project_root: Optional[Path] = typer.Option(None, "--project-root", help="Repository root."),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Reuse an existing run ID."),
    overwrite_testbed: bool = typer.Option(False, "--overwrite-testbed", help="Overwrite generated testbed files."),
) -> None:
    """Run the complete local pipeline without fabricating missing evidence."""

    configure_logging()
    config, context = _context(project_root, run_id)
    build_testbed_impl(config, overwrite=overwrite_testbed)
    sbom_payload = generate_sboms(config, context)

    scan_payload = run_scanner_pipeline(config, context)

    normalize_payload = normalize_findings(context)
    reachability_payload = analyze_reachability(config, context)
    score_payload = score_findings(context)
    vex_payload = generate_vex_impl(context)
    evaluation_payload = evaluate_run(context)
    report_payload = generate_html_report(context)
    evidence_payload = run_evidence_check(context, run_tests=False)
    audit_payload = {
        "run_id": context.run_id,
        "project_root": to_project_relative_path(config.project_root, config),
        "tools": [
            capture_tool_version("python", ("--version",)),
            capture_tool_version("osv-scanner", ("--version",)),
            capture_tool_version("trivy", ("--version",)),
            capture_tool_version("grype", ("version",)),
            capture_tool_version("npm", ("--version",)),
            capture_tool_version("pip-audit", ("--version",)),
        ],
    }
    write_json(context.run_dir("audit") / "tool_versions.json", audit_payload)

    _print_json(
        {
            "run_id": context.run_id,
            "sbom": sbom_payload,
            "scans": scan_payload,
            "normalization": normalize_payload,
            "reachability_cases": len(reachability_payload.get("cases", [])),
            "scored_findings": len(score_payload.get("scored_findings", [])),
            "vex_statements": len(vex_payload.get("statements", [])),
            "evaluation": evaluation_payload,
            "report": report_payload,
            "evidence_check": {
                "ready_for_paper_results": evidence_payload["ready_for_paper_results"],
                "readiness_score_out_of_10": evidence_payload["readiness_score_out_of_10"],
                "report_md": evidence_payload["report_md"],
            },
            "audit": to_project_relative_path(context.run_dir("audit") / "tool_versions.json", config),
        }
    )
