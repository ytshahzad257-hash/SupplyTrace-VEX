"""Static exposure context inference for local projects."""

from __future__ import annotations

from pathlib import Path


EXPOSURE_MARKERS = (
    "flask(",
    "fastapi(",
    "express(",
    ".listen(",
    "app.run(",
    "http.createserver",
    "https.createserver",
)


def infer_exposure(case_dir: Path) -> dict[str, object]:
    """Infer exposed-service indicators from local source text only."""

    matches: list[dict[str, object]] = []
    for suffix in ("*.py", "*.js", "*.ts", "*.mjs", "*.cjs"):
        for path in sorted(case_dir.rglob(suffix)):
            if "node_modules" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            for marker in EXPOSURE_MARKERS:
                if marker in lowered:
                    matches.append(
                        {
                            "source_file": str(path),
                            "marker": marker,
                            "reason": "static service exposure marker",
                        }
                    )
    return {
        "exposed_service": bool(matches),
        "evidence": matches,
        "claim_scope": "Static source marker inspection only; no service was executed or contacted.",
    }

