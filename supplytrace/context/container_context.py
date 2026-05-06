"""Container context helpers."""

from __future__ import annotations

import json
from pathlib import Path


def detect_container_files(case_dir: Path) -> dict[str, object]:
    """Detect local container files and fixture package metadata."""

    files = [
        str(path)
        for name in ("Dockerfile", "docker-compose.yml", "compose.yml", "container-manifest.json")
        for path in [case_dir / name]
        if path.exists()
    ]
    manifest_path = case_dir / "container-manifest.json"
    packages: list[dict[str, object]] = []
    base_image_expected = None
    if manifest_path.exists():
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        base_image_expected = payload.get("base_image_expected")
        raw_packages = payload.get("packages_expected", [])
        if isinstance(raw_packages, list):
            packages = [item for item in raw_packages if isinstance(item, dict)]
    return {
        "containerized": bool(files),
        "files": files,
        "base_image_expected": base_image_expected,
        "packages_expected": packages,
        "claim_scope": "Container context is read from local Dockerfile and fixture metadata only.",
    }

