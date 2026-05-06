"""Comparison helpers for prioritized finding rankings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .metrics import (
    classification_metrics,
    false_positive_reduction,
    mean_average_precision,
    ndcg_at_k,
    scanner_overlap,
    top_k_actionability,
)


ACTIONABLE_LABEL = "actionable"
NON_ACTIONABLE_LABELS = {"non_actionable", "fixed", "clean"}
UNKNOWN_LABELS = {"unknown_until_scanned", "unknown", ""}
PRIORITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
SEVERITY_ORDER = {
    "CRITICAL": 90.0,
    "HIGH": 70.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "NEGLIGIBLE": 5.0,
    "INFO": 5.0,
    "INFORMATIONAL": 5.0,
    "UNKNOWN": 0.0,
}


def truth_by_case(ground_truth_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    """Index ground-truth rows by case ID."""

    return {row["case_id"]: row for row in ground_truth_rows if row.get("case_id")}


def split_scanners(value: Any) -> list[str]:
    """Split a normalized scanner-name cell into stable scanner names."""

    if value in (None, ""):
        return []
    seen: set[str] = set()
    scanners: list[str] = []
    for raw in str(value).replace(",", ";").split(";"):
        scanner = raw.strip()
        if scanner and scanner not in seen:
            scanners.append(scanner)
            seen.add(scanner)
    return scanners


def truth_label_for_finding(finding: dict[str, Any], truth: dict[str, dict[str, str]]) -> tuple[bool | None, str]:
    """Map one scanner-backed finding to the local project-context ground truth when covered."""

    case_id = str(finding.get("case_id") or "")
    row = truth.get(case_id)
    if not row:
        return None, "missing_ground_truth"

    label = str(row.get("expected_actionability_label") or "").strip()
    if label in UNKNOWN_LABELS:
        return None, "ground_truth_unknown_until_scanned"

    expected_package = str(row.get("vulnerable_package_expected") or "").strip().lower()
    finding_package = str(finding.get("package_name") or "").strip().lower()
    if expected_package and finding_package and expected_package != finding_package:
        return None, "package_not_covered_by_ground_truth"

    if label == ACTIONABLE_LABEL:
        return True, "labeled_actionable"
    if label in NON_ACTIONABLE_LABELS:
        return False, f"labeled_{label}"
    return None, "unsupported_ground_truth_label"


def severity_score(finding: dict[str, Any]) -> float:
    """Return scanner-provided CVSS-derived score when available, else severity-derived score."""

    value = finding.get("cvss_score")
    try:
        if value not in (None, ""):
            return max(0.0, min(100.0, float(value) * 10.0))
    except (TypeError, ValueError):
        pass
    severity = str(finding.get("severity") or "UNKNOWN").upper()
    return SEVERITY_ORDER.get(severity, 0.0)


def proposed_score(item: dict[str, Any]) -> float:
    """Return the proposed SupplyTrace-VEX score for ranking."""

    score_row = item.get("risk_score")
    if isinstance(score_row, dict):
        raw_score = score_row.get("proposed_score")
        try:
            return float(raw_score) if raw_score not in (None, "") else 0.0
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def proposed_prediction(item: dict[str, Any]) -> bool:
    """Return whether the proposed method would retain a finding as actionable."""

    vex = item.get("vex")
    if isinstance(vex, dict) and vex.get("status") == "affected":
        return True
    if isinstance(vex, dict) and vex.get("status") in {"not_affected", "fixed"}:
        return False
    score_row = item.get("risk_score")
    if isinstance(score_row, dict):
        priority = str(score_row.get("proposed_priority") or "").lower()
        if priority in {"critical", "high", "medium"}:
            return True
        try:
            return float(score_row.get("proposed_score", 0.0)) >= 45.0
        except (TypeError, ValueError):
            return False
    return False


def context_filter_prediction(item: dict[str, Any]) -> bool:
    """Return whether local context keeps the finding in a retained set."""

    reachability = str(item.get("reachability_status") or "").lower()
    context = item.get("context") if isinstance(item.get("context"), dict) else {}
    if reachability in {"dev_only", "declared_not_used", "transitive_only", "imported_not_called"}:
        return False
    if str(context.get("dev_dependency") or "").lower() == "true":
        return False
    if str(context.get("package_reachable") or "").lower() == "true":
        return True
    return proposed_prediction(item)


def build_evaluation_items(
    findings: list[dict[str, Any]],
    ground_truth_rows: list[dict[str, str]],
    reachability_rows: list[dict[str, str]],
    risk_score_rows: list[dict[str, str]],
    vex_rows: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Join finding, ground truth, reachability, scoring, and VEX summary rows."""

    truth = truth_by_case(ground_truth_rows)
    reachability_index = {
        (row.get("case_id", ""), row.get("package_name", "").lower()): row
        for row in reachability_rows
        if row.get("case_id") and row.get("package_name")
    }
    score_index = {
        row["finding_id"]: row
        for row in risk_score_rows
        if row.get("finding_id")
    }
    vex_index = {
        row["finding_id"]: row
        for row in vex_rows
        if row.get("finding_id")
    }

    items: list[dict[str, Any]] = []
    for finding in findings:
        label, label_status = truth_label_for_finding(finding, truth)
        key = (str(finding.get("case_id") or ""), str(finding.get("package_name") or "").lower())
        reachability = reachability_index.get(key, {})
        finding_id = str(finding.get("finding_id") or "")
        item = {
            "finding": finding,
            "finding_id": finding_id,
            "case_id": finding.get("case_id"),
            "package_name": finding.get("package_name"),
            "vulnerability_id": finding.get("vulnerability_id"),
            "label": label,
            "label_status": label_status,
            "context": reachability,
            "reachability_status": reachability.get("reachability_status"),
            "risk_score": score_index.get(finding_id),
            "vex": vex_index.get(finding_id),
            "scanner_names": split_scanners(finding.get("scanner_name")),
            "severity_score": severity_score(finding),
        }
        items.append(item)
    return items


def labeled_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only findings with a binary local actionability label."""

    return [item for item in items if isinstance(item.get("label"), bool)]


def ranking_quality(method: str, ranked: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute top-k, NDCG, and MAP for a ranked item list."""

    labels = [bool(item["label"]) for item in ranked if isinstance(item.get("label"), bool)]
    actionable = sum(1 for label in labels if label)
    status = "ok" if labels else "not_available"
    notes = "computed over labeled scanner-backed findings" if labels else "no labeled scanner-backed findings available"
    return {
        "method": method,
        "finding_count": len(ranked),
        "labeled_count": len(labels),
        "actionable_count": actionable,
        "top5_actionability": top_k_actionability(labels, 5)["topk_actionability"] if labels else 0.0,
        "top10_actionability": top_k_actionability(labels, 10)["topk_actionability"] if labels else 0.0,
        "ndcg": ndcg_at_k(labels) if labels else 0.0,
        "map": mean_average_precision(labels) if labels else 0.0,
        "status": status,
        "notes": notes,
    }


def proposed_ranking(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank findings by SupplyTrace-VEX proposed score."""

    return sorted(items, key=lambda item: (proposed_score(item), str(item.get("finding_id"))), reverse=True)


def baseline_rankings(items: list[dict[str, Any]], baseline_rows: list[dict[str, str]]) -> dict[str, list[dict[str, Any]]]:
    """Build baseline rankings from baseline CSV rows, falling back to severity-only when needed."""

    item_by_id = {str(item.get("finding_id")): item for item in items}
    grouped: dict[str, list[tuple[float, int, dict[str, Any]]]] = defaultdict(list)
    for row in baseline_rows:
        finding_id = row.get("finding_id")
        method = row.get("baseline_name")
        if not finding_id or not method or finding_id not in item_by_id:
            continue
        try:
            score = float(row.get("baseline_score") or 0.0)
        except ValueError:
            score = 0.0
        try:
            rank = int(float(row.get("rank") or 0))
        except ValueError:
            rank = 0
        grouped[method].append((score, -rank, item_by_id[finding_id]))

    if "severity_only" not in grouped and items:
        grouped["severity_only"] = [
            (float(item.get("severity_score") or 0.0), 0, item)
            for item in items
        ]

    rankings: dict[str, list[dict[str, Any]]] = {}
    for method, rows in grouped.items():
        rows.sort(key=lambda entry: (entry[0], entry[1], str(entry[2].get("finding_id"))), reverse=True)
        rankings[method] = [entry[2] for entry in rows]
    return rankings


def binary_method_metrics(method: str, items: list[dict[str, Any]], prediction_kind: str) -> dict[str, Any]:
    """Compute binary actionability metrics for raw, context, or proposed prediction modes."""

    scoped = labeled_items(items)
    if not scoped:
        return {
            "method": method,
            "status": "not_available",
            "true_positive": 0,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "notes": "no labeled scanner-backed findings available",
        }
    labels = [bool(item["label"]) for item in scoped]
    if prediction_kind == "raw":
        predictions = [True for _ in scoped]
    elif prediction_kind == "context_filter":
        predictions = [context_filter_prediction(item) for item in scoped]
    elif prediction_kind == "proposed":
        predictions = [proposed_prediction(item) for item in scoped]
    else:
        raise ValueError(f"unsupported prediction kind: {prediction_kind}")
    metrics = classification_metrics(labels, predictions)
    return {
        "method": method,
        "status": "ok",
        **metrics,
        "notes": "computed over labeled scanner-backed findings",
    }


def compare_binary_methods(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Return raw, context filter, proposed metrics and false-positive reduction."""

    raw = binary_method_metrics("raw_scanner", items, "raw")
    context = binary_method_metrics("context_filter", items, "context_filter")
    proposed = binary_method_metrics("proposed_full_model", items, "proposed")
    reduction = false_positive_reduction(
        int(raw["false_positive"]),
        int(proposed["false_positive"]),
    )
    return {
        "raw": raw,
        "context_filter": context,
        "proposed": proposed,
        "false_positive_reduction": reduction,
        "actionable_findings_retained": int(proposed["true_positive"]),
    }


def scanner_disagreement_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one scanner-overlap/disagreement row per normalized finding."""

    rows: list[dict[str, Any]] = []
    for item in items:
        finding = item["finding"]
        scanners = item["scanner_names"]
        notes = " ".join(
            str(finding.get(field) or "")
            for field in ("normalization_notes", "scanner_confidence")
        ).lower()
        disagreement = "disagreement" in notes or "conflict" in notes
        if disagreement:
            reason = "normalization notes or scanner confidence mention disagreement/conflict"
        elif len(scanners) > 1:
            reason = "multiple scanners reported the same normalized finding; no disagreement marker was present"
        else:
            reason = "single-scanner finding"
        rows.append(
            {
                "finding_id": item.get("finding_id"),
                "case_id": item.get("case_id"),
                "package_name": item.get("package_name"),
                "vulnerability_id": item.get("vulnerability_id"),
                "scanner_names": ";".join(scanners),
                "scanner_count": len(scanners),
                "scanner_overlap": len(scanners) > 1,
                "disagreement_flag": disagreement,
                "disagreement_reason": reason,
            }
        )
    return rows


def scanner_disagreement_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize scanner overlap and disagreement."""

    scanner_sets = [set(item["scanner_names"]) for item in items]
    overlap = scanner_overlap(scanner_sets)
    disagreement_count = sum(1 for row in scanner_disagreement_rows(items) if row["disagreement_flag"])
    finding_count = len(items)
    return {
        **overlap,
        "scanner_disagreement_count": disagreement_count,
        "scanner_disagreement_rate": round(disagreement_count / finding_count, 6) if finding_count else 0.0,
    }
