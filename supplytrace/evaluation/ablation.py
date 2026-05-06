"""Deterministic ablation rankings for SupplyTrace-VEX scoring evidence."""

from __future__ import annotations

from typing import Any

from .comparison import ranking_quality, severity_score, split_scanners


ABLATION_VARIANTS: tuple[str, ...] = (
    "full_model",
    "no_reachability",
    "no_dependency_scope",
    "no_scanner_agreement",
    "severity_only",
    "context_only",
)


def available_ablation_dimensions() -> list[str]:
    """Return supported ablation variant names."""

    return list(ABLATION_VARIANTS)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return bool(value)


def _proposed_score(item: dict[str, Any]) -> float:
    score = item.get("risk_score")
    if isinstance(score, dict):
        try:
            return float(score.get("proposed_score") or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _reachability_signal(item: dict[str, Any], weights: dict[str, float]) -> float:
    reachability = str(item.get("reachability_status") or "").lower()
    context = item.get("context") if isinstance(item.get("context"), dict) else {}
    if reachability == "reachable" or _truthy(context.get("package_reachable")):
        return weights.get("reachable", 20.0)
    if reachability == "dev_only":
        return weights.get("dev_only", -22.0)
    if reachability == "declared_not_used":
        return weights.get("declared_not_used", -18.0)
    if reachability == "transitive_only":
        return weights.get("transitive_only", -12.0)
    if reachability == "unknown":
        return weights.get("unknown_reachability", -6.0)
    return 0.0


def _dependency_scope_signal(item: dict[str, Any], weights: dict[str, float]) -> float:
    context = item.get("context") if isinstance(item.get("context"), dict) else {}
    score = 0.0
    if _truthy(context.get("runtime_dependency")):
        score += weights.get("runtime_dependency", 10.0)
    if _truthy(context.get("dev_dependency")):
        score += weights.get("dev_only", -22.0)
    if _truthy(context.get("direct_dependency")):
        score += weights.get("direct_dependency", 8.0)
    if _truthy(context.get("transitive_dependency")) and not _truthy(context.get("package_reachable")):
        score += weights.get("transitive_only", -12.0)
    if _truthy(context.get("containerized")):
        score += weights.get("containerized", 4.0)
    if _truthy(context.get("exposed_service")):
        score += weights.get("exposed_service", 8.0)
    return score


def _scanner_agreement_signal(item: dict[str, Any], weights: dict[str, float]) -> float:
    scanner_count = len(set(split_scanners(item["finding"].get("scanner_name"))))
    if scanner_count <= 1:
        return 0.0
    return min((scanner_count - 1) * weights.get("scanner_agreement", 5.0), weights.get("scanner_agreement", 5.0) * 3)


def ablation_score(item: dict[str, Any], variant: str, weights: dict[str, float]) -> float:
    """Compute one deterministic ablation score for ranking only."""

    if variant not in ABLATION_VARIANTS:
        raise ValueError(f"unsupported ablation variant: {variant}")
    if variant == "full_model":
        return _proposed_score(item)

    base = severity_score(item["finding"])
    reachability = _reachability_signal(item, weights)
    scope = _dependency_scope_signal(item, weights)
    scanner_agreement = _scanner_agreement_signal(item, weights)

    if variant == "severity_only":
        return base
    if variant == "context_only":
        return max(0.0, min(100.0, reachability + scope + scanner_agreement + 50.0))
    if variant == "no_reachability":
        return max(0.0, min(100.0, base + scope + scanner_agreement))
    if variant == "no_dependency_scope":
        return max(0.0, min(100.0, base + reachability + scanner_agreement))
    if variant == "no_scanner_agreement":
        return max(0.0, min(100.0, base + reachability + scope))
    return 0.0


def run_ablation(items: list[dict[str, Any]], weights: dict[str, float]) -> list[dict[str, Any]]:
    """Rank findings under each ablation variant and summarize actionability metrics."""

    rows: list[dict[str, Any]] = []
    for variant in ABLATION_VARIANTS:
        ranked = sorted(
            items,
            key=lambda item: (ablation_score(item, variant, weights), str(item.get("finding_id"))),
            reverse=True,
        )
        quality = ranking_quality(variant, ranked)
        rows.append(
            {
                "variant": variant,
                "finding_count": quality["finding_count"],
                "labeled_count": quality["labeled_count"],
                "actionable_count": quality["actionable_count"],
                "top5_actionability": quality["top5_actionability"],
                "top10_actionability": quality["top10_actionability"],
                "ndcg": quality["ndcg"],
                "map": quality["map"],
                "status": quality["status"],
                "notes": (
                    "ablation ranking computed from available local evidence"
                    if quality["status"] == "ok"
                    else "no labeled scanner-backed findings available"
                ),
            }
        )
    return rows
