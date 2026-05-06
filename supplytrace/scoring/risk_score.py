"""Contextual vulnerability prioritization scoring."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext, write_json

from .baselines import BASELINE_NAMES, scanner_native_priority, score_baseline


RISK_SCORE_FIELDS: tuple[str, ...] = (
    "finding_id",
    "case_id",
    "package_name",
    "vulnerability_id",
    "proposed_score",
    "proposed_priority",
    "confidence",
    "score_explanation",
    "evidence_fields_used",
)

BASELINE_FIELDS: tuple[str, ...] = (
    "baseline_name",
    "rank",
    "finding_id",
    "case_id",
    "package_name",
    "vulnerability_id",
    "baseline_score",
)

SCORING_WARNING_FIELDS: tuple[str, ...] = (
    "finding_id",
    "case_id",
    "package_name",
    "warning",
)


def _load_json(path: Path, default: dict[str, object]) -> dict[str, object]:
    if not path.exists():
        return default
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else default


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, object]], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def _split_scanners(value: object) -> list[str]:
    if not value:
        return []
    return [item for item in str(value).replace(",", ";").split(";") if item.strip()]


def _priority(score: float) -> str:
    if score >= 85.0:
        return "critical"
    if score >= 70.0:
        return "high"
    if score >= 45.0:
        return "medium"
    if score >= 20.0:
        return "low"
    return "informational"


def _clamp(value: float) -> float:
    return max(0.0, min(value, 100.0))


def _context_indexes(context: RunContext) -> tuple[dict[tuple[str, str], dict[str, object]], dict[tuple[str, str], dict[str, object]]]:
    reachability_rows = _read_csv(context.config.artifacts_dir / "reachability" / "reachability_matrix.csv")
    context_rows = _read_csv(context.config.artifacts_dir / "reachability" / "context_enrichment.csv")
    reachability_index = {
        (row.get("case_id", ""), row.get("package_name", "").lower()): dict(row)
        for row in reachability_rows
        if row.get("case_id") and row.get("package_name")
    }
    context_index = {
        (row.get("case_id", ""), row.get("package_name", "").lower()): dict(row)
        for row in context_rows
        if row.get("case_id") and row.get("package_name")
    }
    return reachability_index, context_index


def _merged_context(
    finding: dict[str, object],
    reachability_index: dict[tuple[str, str], dict[str, object]],
    context_index: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    key = (str(finding.get("case_id") or ""), str(finding.get("package_name") or "").lower())
    merged: dict[str, object] = {}
    merged.update(reachability_index.get(key, {}))
    merged.update(context_index.get(key, {}))
    return merged


def _missing_evidence_fields(finding: dict[str, object], context: dict[str, object]) -> list[str]:
    missing: list[str] = []
    if finding.get("severity") in (None, "", "unknown") and finding.get("cvss_score") in (None, "", "unknown"):
        missing.append("severity_or_cvss")
    for field in ("dependency_scope", "direct_or_transitive"):
        if context.get(field) in (None, "", "unknown"):
            missing.append(field)
    if context.get("reachability_status") in (None, "", "unknown"):
        missing.append("reachability_status")
    if finding.get("scanner_confidence") in (None, "", "unknown"):
        missing.append("scanner_confidence")
    return missing


def _low_confidence(value: object) -> bool:
    if value is None:
        return False
    lowered = str(value).strip().lower()
    return lowered in {"low", "very low", "negligible", "untrusted"}


def _score_one(
    finding: dict[str, object],
    context: dict[str, object],
    weights: dict[str, float],
) -> dict[str, object]:
    base = scanner_native_priority(finding)
    score = base
    explanation: list[str] = [f"scanner_native_priority={round(base, 2)}"]
    evidence_fields: list[str] = ["severity", "cvss_score"]

    reachability_status = str(context.get("reachability_status") or "")
    if _truthy(context.get("package_reachable")) or reachability_status == "reachable":
        score += weights["reachable"]
        explanation.append(f"reachable=+{weights['reachable']}")
        evidence_fields.extend(["package_reachable", "reachability_status"])
    elif reachability_status == "declared_not_used":
        score += weights["declared_not_used"]
        explanation.append(f"declared_not_used={weights['declared_not_used']}")
        evidence_fields.append("reachability_status")
    elif reachability_status == "dev_only":
        score += weights["dev_only"]
        explanation.append(f"dev_only={weights['dev_only']}")
        evidence_fields.append("reachability_status")
    elif reachability_status == "transitive_only":
        score += weights["transitive_only"]
        explanation.append(f"transitive_only={weights['transitive_only']}")
        evidence_fields.append("reachability_status")
    elif reachability_status == "unknown":
        score += weights["unknown_reachability"]
        explanation.append(f"unknown_reachability={weights['unknown_reachability']}")
        evidence_fields.append("reachability_status")

    if _truthy(context.get("runtime_dependency")):
        score += weights["runtime_dependency"]
        explanation.append(f"runtime_dependency=+{weights['runtime_dependency']}")
        evidence_fields.append("runtime_dependency")
    if _truthy(context.get("dev_dependency")):
        score += weights["dev_only"]
        explanation.append(f"dev_dependency={weights['dev_only']}")
        evidence_fields.append("dev_dependency")
    if _truthy(context.get("direct_dependency")):
        score += weights["direct_dependency"]
        explanation.append(f"direct_dependency=+{weights['direct_dependency']}")
        evidence_fields.append("direct_dependency")
    if _truthy(context.get("transitive_dependency")) and not _truthy(context.get("package_reachable")):
        score += weights["transitive_only"]
        explanation.append(f"transitive_without_reachable_path={weights['transitive_only']}")
        evidence_fields.append("transitive_dependency")
    if _truthy(context.get("containerized")):
        score += weights["containerized"]
        explanation.append(f"containerized=+{weights['containerized']}")
        evidence_fields.append("containerized")
    if _truthy(context.get("exposed_service")):
        score += weights["exposed_service"]
        explanation.append(f"exposed_service=+{weights['exposed_service']}")
        evidence_fields.append("exposed_service")
    fixed_available = _truthy(context.get("fixed_version_available")) or bool(finding.get("fixed_version"))
    if fixed_available:
        score += weights["fixed_version_available"]
        explanation.append(f"fixed_version_available=+{weights['fixed_version_available']}")
        evidence_fields.extend(["fixed_version", "fixed_version_available"])

    scanner_count = len(set(_split_scanners(finding.get("scanner_name"))))
    if scanner_count > 1:
        agreement_bonus = min((scanner_count - 1) * weights["scanner_agreement"], weights["scanner_agreement"] * 3)
        score += agreement_bonus
        explanation.append(f"scanner_agreement_count={scanner_count}=+{agreement_bonus}")
        evidence_fields.append("scanner_name")

    if _low_confidence(finding.get("scanner_confidence")):
        score += weights["low_confidence"]
        explanation.append(f"low_scanner_confidence={weights['low_confidence']}")
        evidence_fields.append("scanner_confidence")

    missing = _missing_evidence_fields(finding, context)
    if missing:
        penalty = max(len(missing) * weights["missing_evidence"], weights["missing_evidence_cap"])
        score += penalty
        explanation.append(f"missing_evidence({','.join(missing)})={penalty}")
        evidence_fields.extend(missing)

    proposed_score = round(_clamp(score), 2)
    confidence = "high"
    if missing:
        confidence = "medium" if len(missing) <= 2 else "low"
    if context.get("reachability_confidence") == "low" or _low_confidence(finding.get("scanner_confidence")):
        confidence = "low"
    score_explanation = "; ".join(explanation) + "; prioritization score only, not an exploitability claim"
    return {
        "finding_id": finding.get("finding_id"),
        "case_id": finding.get("case_id"),
        "package_name": finding.get("package_name"),
        "vulnerability_id": finding.get("vulnerability_id"),
        "proposed_score": proposed_score,
        "proposed_priority": _priority(proposed_score),
        "confidence": confidence,
        "score_explanation": score_explanation,
        "evidence_fields_used": ";".join(sorted(set(item for item in evidence_fields if item))),
        "context": context,
        "source_finding": finding,
    }


def _baseline_rows(findings: list[dict[str, object]], contexts: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for baseline_name in BASELINE_NAMES:
        scored: list[dict[str, object]] = []
        for finding in findings:
            finding_id = str(finding.get("finding_id"))
            context = contexts.get(finding_id, {})
            scored.append(
                {
                    "baseline_name": baseline_name,
                    "finding_id": finding_id,
                    "case_id": finding.get("case_id"),
                    "package_name": finding.get("package_name"),
                    "vulnerability_id": finding.get("vulnerability_id"),
                    "baseline_score": round(score_baseline(baseline_name, finding, context), 2),
                }
            )
        scored.sort(key=lambda item: (float(item["baseline_score"]), str(item["finding_id"])), reverse=True)
        for rank, row in enumerate(scored, start=1):
            rows.append({**row, "rank": rank})
    return rows


def score_findings(context: RunContext) -> dict[str, object]:
    """Score normalized findings using scanner evidence and local project context."""

    normalized_path = context.config.artifacts_dir / "normalized" / "findings_normalized.json"
    normalized = _load_json(normalized_path, {"findings": []})
    findings = [item for item in normalized.get("findings", []) if isinstance(item, dict)]
    reachability_index, context_index = _context_indexes(context)

    scored: list[dict[str, object]] = []
    contexts_by_finding: dict[str, dict[str, object]] = {}
    for finding in findings:
        merged_context = _merged_context(finding, reachability_index, context_index)
        finding_id = str(finding.get("finding_id"))
        contexts_by_finding[finding_id] = merged_context
        scored.append(_score_one(finding, merged_context, context.config.scoring_weights))

    scored.sort(key=lambda item: (float(item["proposed_score"]), str(item["finding_id"])), reverse=True)
    baseline_rows = _baseline_rows(findings, contexts_by_finding)

    output_dir = context.config.artifacts_dir / "evaluation"
    output_dir.mkdir(parents=True, exist_ok=True)
    risk_json = output_dir / "risk_scores.json"
    risk_csv = output_dir / "risk_scores.csv"
    baseline_csv = output_dir / "baseline_rankings.csv"
    warnings_csv = output_dir / "scoring_warnings.csv"

    public_rows = [{field: row.get(field) for field in RISK_SCORE_FIELDS} for row in scored]
    warning_rows: list[dict[str, object]] = []
    if not findings:
        warning_rows.append(
            {
                "finding_id": "",
                "case_id": "all",
                "package_name": "",
                "warning": "zero normalized findings; no risk scores were generated and prioritization claims are unsupported",
            }
        )
    for row in scored:
        missing_markers = [
            marker
            for marker in str(row.get("score_explanation", "")).split("; ")
            if marker.startswith("missing_evidence(")
        ]
        if missing_markers:
            warning_rows.append(
                {
                    "finding_id": row.get("finding_id"),
                    "case_id": row.get("case_id"),
                    "package_name": row.get("package_name"),
                    "warning": "; ".join(missing_markers),
                }
            )
    write_json(
        risk_json,
        {
            "run_id": context.run_id,
            "scoring_weights": context.config.scoring_weights,
            "risk_scores": public_rows,
            "warning_count": len(warning_rows),
            "claim_scope": (
                "Scores prioritize actionability from scanner and local context evidence. "
                "They do not prove exploitability."
            ),
        },
    )
    _write_csv(risk_csv, public_rows, RISK_SCORE_FIELDS)
    _write_csv(baseline_csv, baseline_rows, BASELINE_FIELDS)
    _write_csv(warnings_csv, warning_rows, SCORING_WARNING_FIELDS)

    compatibility_rows = [
        {
            **row["source_finding"],
            "contextual_risk_score": row["proposed_score"],
            "proposed_score": row["proposed_score"],
            "proposed_priority": row["proposed_priority"],
            "score_explanation": row["score_explanation"],
            "evidence_fields_used": row["evidence_fields_used"],
            "score_interpretation": "Heuristic prioritization score, not an exploitability claim.",
        }
        for row in scored
    ]
    run_output_dir = context.run_dir("evaluation")
    write_json(run_output_dir / "scores.json", {"run_id": context.run_id, "scored_findings": compatibility_rows})
    _write_csv(run_output_dir / "scores.csv", public_rows, RISK_SCORE_FIELDS)

    rel = lambda path: to_project_relative_path(path, context.config) or str(path)
    return {
        "run_id": context.run_id,
        "finding_count": len(findings),
        "risk_score_count": len(public_rows),
        "risk_scores_json": rel(risk_json),
        "risk_scores_csv": rel(risk_csv),
        "baseline_rankings_csv": rel(baseline_csv),
        "scoring_warnings_csv": rel(warnings_csv),
        "scored_findings": compatibility_rows,
        "claim_scope": "Risk scores are actionability rankings and do not prove exploitability.",
    }
