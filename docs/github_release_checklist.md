# GitHub Release Checklist

Use this checklist before publishing SupplyTrace-VEX or attaching an artifact bundle to a manuscript submission.

## Commit To The Repository

- Source code under `supplytrace/`
- Tests under `tests/`
- Documentation under `docs/`
- `README.md`, `AGENTS.md`, `LICENSE`, `CITATION.cff`, `.env.example`, `pyproject.toml`
- `Dockerfile` and `docker-compose.yml`
- GitHub Actions workflow files
- Empty artifact directory placeholders only if the repository policy requires them

## Do Not Commit

- `__pycache__/`
- `*.pyc`
- `.pytest_cache/`
- `*.egg-info/`
- `.mypy_cache/`
- `.ruff_cache/`
- local `.env` files
- temporary shell output
- local logs
- ad hoc scratch files
- bulky generated artifacts unless the release policy intentionally includes them

The `.gitignore` file is configured to exclude generated `artifacts/` and generated `testbed/cases/` content by default.

## Create A Reproducibility Artifact Package

1. Start from a clean clone.
2. Install the package with `python -m pip install -e ".[dev]"`.
3. Run the full local pipeline:

   ```bash
   python -m supplytrace build-testbed --overwrite
   python -m supplytrace generate-sbom --run-id release-artifact
   python -m supplytrace run-scans --run-id release-artifact
   python -m supplytrace normalize --run-id release-artifact
   python -m supplytrace analyze-reachability --run-id release-artifact
   python -m supplytrace score --run-id release-artifact
   python -m supplytrace generate-vex --run-id release-artifact
   python -m supplytrace evaluate --run-id release-artifact
   python -m supplytrace report --run-id release-artifact
   python -m supplytrace evidence-check --run-id release-artifact
   python -m supplytrace audit --run-id release-artifact
   ```

4. Package generated evidence separately from source code, for example:

   ```bash
   zip -r supplytrace-vex-artifacts-release-artifact.zip artifacts testbed/ground_truth docs/manuscript_support.md
   ```

5. Attach the artifact package to the GitHub release or manuscript artifact repository.

## Cite The Project

Use `CITATION.cff` for citation metadata. If a paper DOI or archive DOI is later assigned, update `CITATION.cff` and the README before release.

## Release Notes

Release notes should state:

- scanner tools available in the release environment
- scanner tools unavailable or failed
- normalized finding count
- risk score row count
- VEX-style record count
- evidence-readiness score
- publication-readiness recommendation
- Docker verification status

Do not describe unavailable metrics as improvements. Do not claim official VEX status. Do not upload cache directories or local environment files.
