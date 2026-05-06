"""Project configuration and artifact path management."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from pathlib import Path


ARTIFACT_SUBDIRS: tuple[str, ...] = (
    "sbom",
    "scanner_raw",
    "normalized",
    "reachability",
    "vex",
    "evaluation",
    "reports",
    "figures_data",
    "audit",
)

DEFAULT_SCANNERS: tuple[str, ...] = (
    "osv",
    "trivy",
    "grype",
    "npm-audit",
    "pip-audit",
)

DEFAULT_SCORING_WEIGHTS: dict[str, float] = {
    "reachable": 20.0,
    "runtime_dependency": 10.0,
    "direct_dependency": 8.0,
    "containerized": 4.0,
    "exposed_service": 8.0,
    "fixed_version_available": 5.0,
    "scanner_agreement": 5.0,
    "dev_only": -22.0,
    "declared_not_used": -18.0,
    "unreachable": -18.0,
    "transitive_only": -12.0,
    "low_confidence": -8.0,
    "unknown_reachability": -6.0,
    "missing_evidence": -4.0,
    "missing_evidence_cap": -20.0,
}


@dataclass(frozen=True)
class ProjectConfig:
    """Resolved project configuration."""

    project_root: Path
    artifacts_dir: Path
    testbed_dir: Path
    scanners: tuple[str, ...] = field(default_factory=lambda: DEFAULT_SCANNERS)
    allow_network_scanner_updates: bool = False
    npm_audit_offline: bool = False
    scoring_weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_SCORING_WEIGHTS))

    @property
    def ground_truth_dir(self) -> Path:
        return self.testbed_dir / "ground_truth"

    @property
    def cases_dir(self) -> Path:
        return self.testbed_dir / "cases"


def discover_project_root(start: Path | None = None) -> Path:
    """Find the repository root by walking upward from ``start``."""

    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "supplytrace").is_dir():
            return candidate
    return current


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _env_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_scoring_weights(path_value: str | None) -> dict[str, float]:
    weights = dict(DEFAULT_SCORING_WEIGHTS)
    if not path_value:
        return weights
    path = Path(path_value)
    if not path.exists():
        return weights
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return weights
    for key, value in payload.items():
        if key in weights and isinstance(value, (int, float)):
            weights[key] = float(value)
    return weights


def load_config(project_root: Path | None = None, env_file: Path | None = None) -> ProjectConfig:
    """Load configuration from defaults, ``.env``, and environment variables."""

    root = discover_project_root(project_root).resolve()
    env_values = _read_env_file(env_file or (root / ".env"))

    def get(name: str, default: str | None = None) -> str | None:
        return os.environ.get(name, env_values.get(name, default))

    artifacts_value = get("SUPPLYTRACE_ARTIFACTS_DIR", "artifacts")
    testbed_value = get("SUPPLYTRACE_TESTBED_DIR", "testbed")
    scanner_value = get("SUPPLYTRACE_SCANNERS", ",".join(DEFAULT_SCANNERS))
    scoring_weights_file = get("SUPPLYTRACE_SCORING_WEIGHTS_FILE")

    scanners = tuple(
        item.strip()
        for item in (scanner_value or "").split(",")
        if item.strip()
    ) or DEFAULT_SCANNERS

    artifacts_dir = Path(artifacts_value or "artifacts")
    testbed_dir = Path(testbed_value or "testbed")
    if not artifacts_dir.is_absolute():
        artifacts_dir = root / artifacts_dir
    if not testbed_dir.is_absolute():
        testbed_dir = root / testbed_dir

    return ProjectConfig(
        project_root=root,
        artifacts_dir=artifacts_dir.resolve(),
        testbed_dir=testbed_dir.resolve(),
        scanners=scanners,
        allow_network_scanner_updates=_env_bool(
            get("SUPPLYTRACE_ALLOW_NETWORK_SCANNER_UPDATES"),
            default=False,
        ),
        npm_audit_offline=_env_bool(
            get("SUPPLYTRACE_NPM_AUDIT_OFFLINE"),
            default=False,
        ),
        scoring_weights=_load_scoring_weights(scoring_weights_file),
    )


def ensure_artifact_dirs(config: ProjectConfig) -> dict[str, Path]:
    """Create and return the canonical artifact directories."""

    config.artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name in ARTIFACT_SUBDIRS:
        path = config.artifacts_dir / name
        path.mkdir(parents=True, exist_ok=True)
        paths[name] = path
    config.cases_dir.mkdir(parents=True, exist_ok=True)
    config.ground_truth_dir.mkdir(parents=True, exist_ok=True)
    return paths


def artifact_path(config: ProjectConfig, artifact_kind: str, *parts: str) -> Path:
    """Return a path inside a known artifact directory."""

    if artifact_kind not in ARTIFACT_SUBDIRS:
        allowed = ", ".join(ARTIFACT_SUBDIRS)
        raise ValueError(f"Unknown artifact kind '{artifact_kind}'. Expected one of: {allowed}")
    base = config.artifacts_dir / artifact_kind
    return base.joinpath(*parts)


def to_project_relative_path(path: str | Path | None, config: ProjectConfig) -> str | None:
    """Return a stable project-relative path for generated artifact metadata."""

    if path in (None, ""):
        return None
    candidate = Path(str(path))
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(config.project_root.resolve()).as_posix()
    except ValueError:
        return candidate.as_posix()


def project_path_from_artifact_reference(config: ProjectConfig, value: str | Path | None) -> Path | None:
    """Resolve a stored artifact path that may be project-relative or absolute."""

    if value in (None, ""):
        return None
    path = Path(str(value))
    if path.is_absolute():
        return path
    return config.project_root / path
