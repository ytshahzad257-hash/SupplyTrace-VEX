$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$allowedRoot = $Root.Path.TrimEnd("\")

$directoryNames = @("__pycache__", ".pytest_cache", ".pytest-tmp", ".tmp", ".mypy_cache", ".ruff_cache")
foreach ($name in $directoryNames) {
    Get-ChildItem -LiteralPath $allowedRoot -Directory -Recurse -Force -Filter $name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase) } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -LiteralPath $allowedRoot -Directory -Recurse -Force -Filter "*.egg-info" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase) } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

foreach ($pattern in @("*.pyc", "*.pyo")) {
    Get-ChildItem -LiteralPath $allowedRoot -File -Recurse -Force -Filter $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "Release cleanup complete. Generated research artifacts are not deleted by this script."
