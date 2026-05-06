"""Figure-ready data generation for SupplyTrace-VEX reports."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext

from .tables import read_csv, write_csv


FIGURE_OUTPUTS: tuple[str, ...] = (
    "architecture_mermaid.md",
    "pipeline_mermaid.md",
    "scanner_overlap.csv",
    "risk_distribution.csv",
    "topk_actionability.csv",
    "alert_reduction.csv",
    "vex_status_distribution.csv",
    "ablation_chart_data.csv",
    "runtime_chart_data.csv",
)


def _write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _architecture_mermaid() -> str:
    return """```mermaid
flowchart LR
  A["Local testbed cases"] --> B["SBOM generation"]
  A --> C["Local scanner adapters"]
  A --> D["Static reachability analysis"]
  B --> E["Normalized evidence"]
  C --> E
  D --> F["Context enrichment"]
  E --> G["Risk scoring"]
  F --> G
  G --> H["VEX-style status generation"]
  G --> I["Evaluation"]
  H --> J["Reports and manuscript artifacts"]
  I --> J
```
"""


def _pipeline_mermaid() -> str:
    return """```mermaid
flowchart TD
  T["build-testbed"] --> S["generate-sbom"]
  S --> R["run-scans"]
  R --> N["normalize"]
  N --> A["analyze-reachability"]
  A --> P["score"]
  P --> V["generate-vex"]
  V --> E["evaluate"]
  E --> O["report"]
```
"""


def _scanner_overlap_rows(scanner_disagreement: list[dict[str, str]], findings: list[dict[str, str]]) -> list[dict[str, Any]]:
    pair_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"overlap_count": 0, "disagreement_count": 0})
    source_rows = scanner_disagreement
    if source_rows:
        for row in source_rows:
            scanners = [item for item in (row.get("scanner_names") or "").split(";") if item]
            for left_index, left in enumerate(scanners):
                for right in scanners[left_index + 1 :]:
                    key = tuple(sorted((left, right)))
                    pair_counts[key]["overlap_count"] += 1
                    if str(row.get("disagreement_flag") or "").lower() == "true":
                        pair_counts[key]["disagreement_count"] += 1
    else:
        for row in findings:
            scanners = [item.strip() for item in (row.get("scanner_name") or "").replace(",", ";").split(";") if item.strip()]
            for left_index, left in enumerate(scanners):
                for right in scanners[left_index + 1 :]:
                    key = tuple(sorted((left, right)))
                    pair_counts[key]["overlap_count"] += 1

    rows = [
        {
            "scanner_a": left,
            "scanner_b": right,
            "overlap_count": values["overlap_count"],
            "disagreement_count": values["disagreement_count"],
        }
        for (left, right), values in sorted(pair_counts.items())
    ]
    if not rows:
        rows = [{"scanner_a": "not_available", "scanner_b": "", "overlap_count": 0, "disagreement_count": 0}]
    return rows


def _risk_distribution_rows(risk_scores: list[dict[str, str]]) -> list[dict[str, Any]]:
    buckets = {
        "critical": [85.0, 100.0],
        "high": [70.0, 84.999],
        "medium": [45.0, 69.999],
        "low": [20.0, 44.999],
        "informational": [0.0, 19.999],
    }
    counts = Counter((row.get("proposed_priority") or "unknown").lower() for row in risk_scores)
    rows = [
        {
            "priority": priority,
            "score_min": limits[0],
            "score_max": limits[1],
            "finding_count": counts.get(priority, 0),
        }
        for priority, limits in buckets.items()
    ]
    unknown_count = sum(count for priority, count in counts.items() if priority not in buckets)
    if unknown_count:
        rows.append({"priority": "unknown", "score_min": "", "score_max": "", "finding_count": unknown_count})
    return rows


def _alert_reduction_rows(metrics_summary: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in metrics_summary:
        if row.get("metric") in {"false_positive_reduction", "actionable_findings_retained"}:
            rows.append(
                {
                    "method": row.get("method"),
                    "metric": row.get("metric"),
                    "value": row.get("value"),
                    "numerator": row.get("numerator"),
                    "denominator": row.get("denominator"),
                    "status": row.get("status"),
                }
            )
    if not rows:
        rows = [
            {
                "method": "proposed_full_model",
                "metric": "false_positive_reduction",
                "value": 0.0,
                "numerator": 0,
                "denominator": 0,
                "status": "not_available",
            }
        ]
    return rows


def _copy_rows_or_missing(rows: list[dict[str, str]], fields: list[str]) -> list[dict[str, Any]]:
    if rows:
        return [dict(row) for row in rows]
    return [{field: ("not_available" if index == 0 else 0) for index, field in enumerate(fields)}]


def _runtime_chart_rows(runtime_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not runtime_rows:
        return [{"case_id": "not_available", "total_duration_seconds": 0.0, "scanner_count": 0, "unavailable_count": 0}]
    return [
        {
            "case_id": row.get("case_id"),
            "total_duration_seconds": _float(row.get("total_duration_seconds")),
            "scanner_count": row.get("scanner_count") or 0,
            "unavailable_count": row.get("unavailable_count") or 0,
        }
        for row in runtime_rows
    ]


def generate_figure_data(context: RunContext) -> dict[str, str]:
    """Generate Mermaid diagrams and CSV files suitable for paper figures."""

    artifacts = context.config.artifacts_dir
    output_dir = artifacts / "figures_data"
    findings = read_csv(artifacts / "normalized" / "findings_normalized.csv")
    scanner_disagreement = read_csv(artifacts / "evaluation" / "scanner_disagreement.csv")
    risk_scores = read_csv(artifacts / "evaluation" / "risk_scores.csv")
    topk = read_csv(artifacts / "evaluation" / "topk_comparison.csv")
    metrics_summary = read_csv(artifacts / "evaluation" / "metrics_summary.csv")
    vex_distribution = read_csv(artifacts / "vex" / "vex_status_distribution.csv")
    ablation = read_csv(artifacts / "evaluation" / "ablation_results.csv")
    runtime = read_csv(artifacts / "evaluation" / "runtime_summary.csv")

    paths: dict[str, str] = {}
    paths["architecture_mermaid.md"] = str(_write_text(output_dir / "architecture_mermaid.md", _architecture_mermaid()))
    paths["pipeline_mermaid.md"] = str(_write_text(output_dir / "pipeline_mermaid.md", _pipeline_mermaid()))

    paths["scanner_overlap.csv"] = str(
        write_csv(
            output_dir / "scanner_overlap.csv",
            _scanner_overlap_rows(scanner_disagreement, findings),
            ["scanner_a", "scanner_b", "overlap_count", "disagreement_count"],
        )
    )
    paths["risk_distribution.csv"] = str(
        write_csv(
            output_dir / "risk_distribution.csv",
            _risk_distribution_rows(risk_scores),
            ["priority", "score_min", "score_max", "finding_count"],
        )
    )
    paths["topk_actionability.csv"] = str(
        write_csv(
            output_dir / "topk_actionability.csv",
            _copy_rows_or_missing(topk, ["method", "k", "evaluated_count", "actionable_count", "topk_actionability", "status", "notes"]),
            ["method", "k", "evaluated_count", "actionable_count", "topk_actionability", "status", "notes"],
        )
    )
    paths["alert_reduction.csv"] = str(
        write_csv(
            output_dir / "alert_reduction.csv",
            _alert_reduction_rows(metrics_summary),
            ["method", "metric", "value", "numerator", "denominator", "status"],
        )
    )
    paths["vex_status_distribution.csv"] = str(
        write_csv(
            output_dir / "vex_status_distribution.csv",
            _copy_rows_or_missing(vex_distribution, ["status", "count"]),
            ["status", "count"],
        )
    )
    paths["ablation_chart_data.csv"] = str(
        write_csv(
            output_dir / "ablation_chart_data.csv",
            _copy_rows_or_missing(ablation, ["variant", "top5_actionability", "top10_actionability", "ndcg", "map", "status"]),
            ["variant", "top5_actionability", "top10_actionability", "ndcg", "map", "status"],
        )
    )
    paths["runtime_chart_data.csv"] = str(
        write_csv(
            output_dir / "runtime_chart_data.csv",
            _runtime_chart_rows(runtime),
            ["case_id", "total_duration_seconds", "scanner_count", "unavailable_count"],
        )
    )
    return {name: to_project_relative_path(path, context.config) or path for name, path in paths.items()}


def write_score_distribution_data(context: RunContext, scores: list[dict[str, object]]) -> str:
    """Compatibility helper for older callers."""

    path = context.run_dir("figures_data") / "score_distribution.csv"
    write_csv(
        path,
        [
            {
                "finding_id": item.get("finding_id"),
                "contextual_risk_score": item.get("contextual_risk_score") or item.get("proposed_score"),
            }
            for item in scores
        ],
        ["finding_id", "contextual_risk_score"],
    )
    return to_project_relative_path(path, context.config) or str(path)
