"""Generate project-evidence-based VEX-style status artifacts."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext, write_json

from .vex_schema import (
    STANDARD_LIMITATIONS,
    VEX_DISTRIBUTION_FIELDS,
    VEX_STATUSES,
    VEX_SUMMARY_FIELDS,
    VexEvidence,
    VexRecord,
    validate_status,
)


CONTEXT_FIELD_NAMES: tuple[str, ...] = (
    "runtime_dependency",
    "dev_dependency",
    "direct_dependency",
    "transitive_dependency",
    "package_reachable",
    "containerized",
    "exposed_service",
    "fixed_version_available",
)

VEX_WARNING_FIELDS: tuple[str, ...] = (
    "case_id",
    "finding_id",
    "warning",
)

NON_AFFECTED_REACHABILITY = {"declared_not_used", "dev_only", "transitive_only", "imported_not_called"}
UNCERTAIN_REACHABILITY = {"", "unknown"}


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else default


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return bool(value)


def _split_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    seen: set[str] = set()
    items: list[str] = []
    for raw in str(value).replace(",", ";").split(";"):
        item = raw.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        items.append(item)
    return items


def _index_rows(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    return {
        (row.get("case_id", ""), row.get("package_name", "").lower()): row
        for row in rows
        if row.get("case_id") and row.get("package_name")
    }


def _load_findings(context: RunContext) -> list[dict[str, Any]]:
    payload = _load_json(context.config.artifacts_dir / "normalized" / "findings_normalized.json", {"findings": []})
    findings = payload.get("findings", [])
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _load_scores(context: RunContext) -> dict[str, dict[str, Any]]:
    stable_payload = _load_json(context.config.artifacts_dir / "evaluation" / "risk_scores.json", {"risk_scores": []})
    rows = stable_payload.get("risk_scores", [])
    if not isinstance(rows, list) or not rows:
        compatibility_payload = _load_json(context.run_dir("evaluation") / "scores.json", {"scored_findings": []})
        rows = compatibility_payload.get("scored_findings", [])
    return {
        str(row.get("finding_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("finding_id")
    }


def _case_metadata(context: RunContext) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for case_dir in sorted(context.config.cases_dir.glob("case_*")):
        path = case_dir / "metadata.json"
        if path.exists():
            payload = _load_json(path, {})
            if payload.get("case_id"):
                metadata[str(payload["case_id"])] = payload
    ground_truth = _load_json(context.config.ground_truth_dir / "ground_truth.json", {"cases": []})
    for item in ground_truth.get("cases", []) if isinstance(ground_truth.get("cases"), list) else []:
        if isinstance(item, dict) and item.get("case_id"):
            metadata.setdefault(str(item["case_id"]), item)
    return metadata


def _case_ids(context: RunContext, findings: list[dict[str, Any]], metadata: dict[str, dict[str, Any]]) -> list[str]:
    ids = {path.name for path in context.config.cases_dir.glob("case_*") if path.is_dir()}
    ids.update(str(item.get("case_id")) for item in findings if item.get("case_id"))
    ids.update(metadata)
    return sorted(item for item in ids if item)


def _metadata_says_fixed(finding: dict[str, Any], metadata: dict[str, Any] | None) -> bool:
    if not metadata:
        return False
    if metadata.get("expected_actionability_label") != "fixed":
        return False
    expected_package = str(metadata.get("vulnerable_package_expected") or "").lower()
    expected_version = str(metadata.get("vulnerable_version_expected") or "")
    finding_package = str(finding.get("package_name") or "").lower()
    finding_version = str(finding.get("package_version") or "")
    if expected_package and expected_package != finding_package:
        return False
    if expected_version and expected_version != finding_version:
        return False
    return True


def _context_for(
    finding: dict[str, Any],
    reachability_index: dict[tuple[str, str], dict[str, str]],
    context_index: dict[tuple[str, str], dict[str, str]],
) -> dict[str, Any]:
    key = (str(finding.get("case_id") or ""), str(finding.get("package_name") or "").lower())
    merged: dict[str, Any] = {}
    merged.update(reachability_index.get(key, {}))
    merged.update(context_index.get(key, {}))
    return merged


def _context_fields(context_row: dict[str, Any]) -> dict[str, Any]:
    return {field: _truthy(context_row.get(field)) for field in CONTEXT_FIELD_NAMES}


def _risk_score(score_row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not score_row:
        return None
    return {
        "proposed_score": score_row.get("proposed_score") or score_row.get("contextual_risk_score"),
        "proposed_priority": score_row.get("proposed_priority"),
        "score_explanation": score_row.get("score_explanation"),
        "evidence_fields_used": score_row.get("evidence_fields_used"),
    }


def _score_value(score_row: dict[str, Any] | None) -> float | None:
    if not score_row:
        return None
    value = score_row.get("proposed_score", score_row.get("contextual_risk_score"))
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _confidence_level(
    finding: dict[str, Any],
    context_row: dict[str, Any],
    score_row: dict[str, Any] | None,
) -> str:
    scanner_confidence = str(finding.get("scanner_confidence") or "").strip().lower()
    reachability_status = str(context_row.get("reachability_status") or "").strip().lower()
    missing_context = not context_row
    missing_score = score_row is None
    if scanner_confidence in {"low", "very low", "unknown", ""}:
        return "low"
    if reachability_status in UNCERTAIN_REACHABILITY or missing_context:
        return "low"
    if missing_score:
        return "medium"
    return "high"


def _scanner_disagreement_is_high(finding: dict[str, Any], score_row: dict[str, Any] | None) -> bool:
    text = " ".join(
        str(value or "")
        for value in (
            finding.get("normalization_notes"),
            finding.get("scanner_confidence"),
            score_row.get("score_explanation") if score_row else "",
        )
    ).lower()
    return "disagreement" in text or "conflict" in text


def _status_and_justification(
    finding: dict[str, Any],
    context_row: dict[str, Any],
    score_row: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
) -> tuple[str, str]:
    reachability_status = str(context_row.get("reachability_status") or "").strip().lower()
    context_fields = _context_fields(context_row)
    confidence = _confidence_level(finding, context_row, score_row)
    score_value = _score_value(score_row)

    if _metadata_says_fixed(finding, metadata):
        return (
            "fixed",
            "Local testbed metadata marks this package version as the intended fixed dependency for the case; scanner evidence is retained for review.",
        )

    if _scanner_disagreement_is_high(finding, score_row):
        return (
            "under_investigation",
            "Scanner evidence contains disagreement or conflict markers, so the project keeps the status under investigation.",
        )

    if confidence == "low" or reachability_status in UNCERTAIN_REACHABILITY:
        return (
            "under_investigation",
            "Evidence is incomplete or static reachability is unknown, so the status is not promoted to affected or not_affected.",
        )

    if (
        reachability_status in NON_AFFECTED_REACHABILITY
        or context_fields["dev_dependency"]
        or not context_fields["package_reachable"]
        and reachability_status in {"declared_not_used", "transitive_only", "imported_not_called"}
    ):
        return (
            "not_affected",
            "Scanner evidence exists, but local context shows a development-only, unused, unreachable, or non-executed dependency path.",
        )

    actionable_score = score_value is not None and score_value >= 45.0
    if context_fields["package_reachable"] and context_fields["runtime_dependency"] and actionable_score:
        return (
            "affected",
            "Scanner evidence is paired with local reachable runtime dependency evidence and an actionable prioritization score.",
        )

    return (
        "under_investigation",
        "Available evidence does not meet the project threshold for affected, not_affected, or fixed.",
    )


def _record_for_finding(
    finding: dict[str, Any],
    context_row: dict[str, Any],
    score_row: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    status, justification = _status_and_justification(finding, context_row, score_row, metadata)
    scanner_names = _split_list(finding.get("scanner_name"))
    scanner_output_paths = _split_list(finding.get("raw_reference"))
    reachability_status = str(context_row.get("reachability_status") or "unknown")
    dependency_scope = str(
        context_row.get("dependency_scope")
        or finding.get("dependency_scope")
        or "unknown"
    )
    evidence = VexEvidence(
        scanner_names=scanner_names,
        scanner_output_paths=scanner_output_paths,
        reachability_status=reachability_status,
        dependency_scope=dependency_scope,
        context_fields=_context_fields(context_row),
        risk_score=_risk_score(score_row),
        confidence_level=_confidence_level(finding, context_row, score_row),
    )
    record = VexRecord(
        case_id=str(finding.get("case_id") or "unknown"),
        finding_id=str(finding.get("finding_id") or "unknown"),
        vulnerability_id=str(finding.get("vulnerability_id") or "unknown"),
        package_name=str(finding.get("package_name") or "unknown"),
        package_version=finding.get("package_version") if finding.get("package_version") not in ("", None) else None,
        status=validate_status(status),
        justification=justification,
        evidence=evidence,
        generated_at=generated_at,
        limitations=list(STANDARD_LIMITATIONS),
    )
    return record.to_dict()


def _summary_row(record: dict[str, Any]) -> dict[str, Any]:
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    risk_score = evidence.get("risk_score") if isinstance(evidence.get("risk_score"), dict) else {}
    return {
        "case_id": record.get("case_id"),
        "finding_id": record.get("finding_id"),
        "vulnerability_id": record.get("vulnerability_id"),
        "package_name": record.get("package_name"),
        "package_version": record.get("package_version"),
        "status": record.get("status"),
        "confidence_level": evidence.get("confidence_level"),
        "risk_score": risk_score.get("proposed_score") if risk_score else None,
        "scanner_names": ";".join(evidence.get("scanner_names", [])) if isinstance(evidence.get("scanner_names"), list) else "",
        "reachability_status": evidence.get("reachability_status"),
        "dependency_scope": evidence.get("dependency_scope"),
        "justification": record.get("justification"),
    }


def _compatibility_openvex(context: RunContext, records: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    for record in records:
        statements.append(
            {
                "vulnerability": {"name": record.get("vulnerability_id")},
                "products": [
                    {
                        "@id": record.get("case_id"),
                        "subcomponents": [
                            {
                                "name": record.get("package_name"),
                                "version": record.get("package_version"),
                            }
                        ],
                    }
                ],
                "status": record.get("status"),
                "impact_statement": record.get("justification"),
                "action_statement": "Review linked SupplyTrace-VEX evidence before operational use.",
                "timestamp": generated_at,
            }
        )
    return {
        "@id": f"urn:supplytrace-vex:{context.run_id}",
        "author": "SupplyTrace-VEX",
        "timestamp": generated_at,
        "version": 1,
        "statements": statements,
        "claim_scope": "Compatibility summary only; canonical outputs are project-evidence-based VEX-style case files.",
    }


def generate_vex(context: RunContext) -> dict[str, Any]:
    """Generate per-case VEX-style records from normalized findings and local context evidence."""

    generated_at = datetime.now(timezone.utc).isoformat()
    output_dir = context.config.artifacts_dir / "vex"
    output_dir.mkdir(parents=True, exist_ok=True)

    findings = _load_findings(context)
    scores = _load_scores(context)
    reachability_index = _index_rows(_read_csv(context.config.artifacts_dir / "reachability" / "reachability_matrix.csv"))
    context_index = _index_rows(_read_csv(context.config.artifacts_dir / "reachability" / "context_enrichment.csv"))
    metadata = _case_metadata(context)

    records_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    all_records: list[dict[str, Any]] = []
    for finding in findings:
        case_id = str(finding.get("case_id") or "unknown")
        context_row = _context_for(finding, reachability_index, context_index)
        score_row = scores.get(str(finding.get("finding_id")))
        record = _record_for_finding(
            finding=finding,
            context_row=context_row,
            score_row=score_row,
            metadata=metadata.get(case_id),
            generated_at=generated_at,
        )
        records_by_case[case_id].append(record)
        all_records.append(record)

    case_files: list[str] = []
    for case_id in _case_ids(context, findings, metadata):
        payload = {
            "case_id": case_id,
            "run_id": context.run_id,
            "generated_at": generated_at,
            "document_type": "SupplyTrace-VEX project-evidence-based VEX-style status document",
            "claim_scope": (
                "This file contains local research status records derived from normalized scanner findings, "
                "reachability evidence, context enrichment, and scoring artifacts. It is not an official vendor VEX claim."
            ),
            "records": records_by_case.get(case_id, []),
            "notes": (
                "No scanner-backed finding records were available for this case."
                if not records_by_case.get(case_id)
                else "Records are limited to scanner-backed findings present in normalized artifacts."
            ),
        }
        path = output_dir / f"{case_id}.vex.json"
        write_json(path, payload)
        case_files.append(to_project_relative_path(path, context.config) or str(path))

    summary_rows = [_summary_row(record) for record in all_records]
    warning_rows: list[dict[str, Any]] = []
    if not all_records:
        warning_rows.append(
            {
                "case_id": "all",
                "finding_id": "",
                "warning": (
                    "zero scanner-backed findings were available; no vulnerability-level VEX-style "
                    "records were generated"
                ),
            }
        )
    for record in all_records:
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        if evidence.get("confidence_level") == "low" or record.get("status") == "under_investigation":
            warning_rows.append(
                {
                    "case_id": record.get("case_id"),
                    "finding_id": record.get("finding_id"),
                    "warning": "weak or incomplete evidence kept the VEX-style status conservative",
                }
            )
    status_counts = Counter(str(record["status"]) for record in all_records)
    distribution_rows = [
        {"status": status, "count": status_counts.get(status, 0)}
        for status in sorted(VEX_STATUSES)
    ]
    summary_csv = output_dir / "vex_summary.csv"
    distribution_csv = output_dir / "vex_status_distribution.csv"
    warnings_csv = output_dir / "vex_generation_warnings.csv"
    _write_csv(summary_csv, summary_rows, VEX_SUMMARY_FIELDS)
    _write_csv(distribution_csv, distribution_rows, VEX_DISTRIBUTION_FIELDS)
    _write_csv(warnings_csv, warning_rows, VEX_WARNING_FIELDS)

    compatibility_payload = _compatibility_openvex(context, all_records, generated_at)
    run_vex_dir = context.run_dir("vex")
    write_json(run_vex_dir / "openvex.json", compatibility_payload)
    write_json(
        run_vex_dir / "vex_summary.json",
        {
            "run_id": context.run_id,
            "generated_at": generated_at,
            "record_count": len(all_records),
            "status_distribution": distribution_rows,
            "warning_count": len(warning_rows),
            "claim_scope": compatibility_payload["claim_scope"],
        },
    )

    rel = lambda path: to_project_relative_path(path, context.config) or str(path)
    return {
        "run_id": context.run_id,
        "case_file_count": len(case_files),
        "record_count": len(all_records),
        "case_files": case_files,
        "vex_summary_csv": rel(summary_csv),
        "vex_status_distribution_csv": rel(distribution_csv),
        "vex_generation_warnings_csv": rel(warnings_csv),
        "warning_count": len(warning_rows),
        "status_distribution": distribution_rows,
        "records": all_records,
        "statements": compatibility_payload["statements"],
        "claim_scope": (
            "SupplyTrace-VEX generates project-evidence-based VEX-style statuses for local research only; "
            "records are not official vendor VEX claims and do not prove exploitability."
        ),
    }
