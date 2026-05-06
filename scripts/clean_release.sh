#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

find "$ROOT_DIR" -type d \( \
  -name "__pycache__" -o \
  -name ".pytest_cache" -o \
  -name ".pytest-tmp" -o \
  -name ".tmp" -o \
  -name ".mypy_cache" -o \
  -name ".ruff_cache" -o \
  -name "*.egg-info" \
\) -prune -exec rm -rf {} +

find "$ROOT_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete

printf '%s\n' "Release cleanup complete. Generated research artifacts are not deleted by this script."
