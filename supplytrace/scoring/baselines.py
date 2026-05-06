"""Baseline ranking functions for SupplyTrace-VEX."""

from __future__ import annotations

from typing import Any


SEVERITY_BASELINE = {
    "CRITICAL": 90.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "MODERATE": 50.0,
    "LOW": 25.0,
    "INFO": 10.0,
    "INFORMATIONAL": 10.0,
    "UNKNOWN": 10.0,
    None: 10.0,
}


def severity_baseline(severity: str | None) -> float:
    """Map scanner severity text to a 0-100 baseline."""

    if severity is None:
        return SEVERITY_BASELINE[None]
    return SEVERITY_BASELINE.get(severity.upper(), SEVERITY_BASELINE["UNKNOWN"])


def cvss_baseline(cvss_score: Any) -> float:
    """Map scanner-provided CVSS to a 0-100 baseline."""

    if isinstance(cvss_score, (int, float)):
        return max(0.0, min(float(cvss_score) * 10.0, 100.0))
    return 10.0


def scanner_native_priority(finding: dict[str, object]) -> float:
    """Prefer CVSS when present, otherwise scanner severity."""

    cvss = finding.get("cvss_score")
    if isinstance(cvss, (int, float)):
        return cvss_baseline(cvss)
    return severity_baseline(finding.get("severity") if isinstance(finding.get("severity"), str) else None)


def direct_dependency_first(finding: dict[str, object], context: dict[str, object]) -> float:
    """Baseline that prioritizes direct dependencies before severity."""

    base = scanner_native_priority(finding)
    if _truthy(context.get("direct_dependency")):
        base += 20.0
    if _truthy(context.get("transitive_dependency")):
        base -= 10.0
    return _clamp(base)


def runtime_dependency_first(finding: dict[str, object], context: dict[str, object]) -> float:
    """Baseline that prioritizes runtime dependencies before severity."""

    base = scanner_native_priority(finding)
    if _truthy(context.get("runtime_dependency")):
        base += 20.0
    if _truthy(context.get("dev_dependency")):
        base -= 20.0
    return _clamp(base)


def reachability_only(finding: dict[str, object], context: dict[str, object]) -> float:
    """Baseline based only on static reachability category."""

    status = str(context.get("reachability_status") or "")
    if _truthy(context.get("package_reachable")) or status == "reachable":
        return 100.0
    if status == "imported_not_called":
        return 60.0
    if status == "unknown":
        return 35.0
    if status in {"declared_not_used", "dev_only", "transitive_only"}:
        return 15.0
    return 10.0


def score_baseline(name: str, finding: dict[str, object], context: dict[str, object]) -> float:
    """Score a finding under a named baseline."""

    if name == "severity_only":
        return severity_baseline(finding.get("severity") if isinstance(finding.get("severity"), str) else None)
    if name == "cvss_only":
        return cvss_baseline(finding.get("cvss_score"))
    if name == "scanner_native_priority":
        return scanner_native_priority(finding)
    if name == "direct_dependency_first":
        return direct_dependency_first(finding, context)
    if name == "runtime_dependency_first":
        return runtime_dependency_first(finding, context)
    if name == "reachability_only":
        return reachability_only(finding, context)
    raise ValueError(f"Unknown baseline: {name}")


BASELINE_NAMES: tuple[str, ...] = (
    "severity_only",
    "cvss_only",
    "scanner_native_priority",
    "direct_dependency_first",
    "runtime_dependency_first",
    "reachability_only",
)


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def _clamp(value: float) -> float:
    return max(0.0, min(value, 100.0))

