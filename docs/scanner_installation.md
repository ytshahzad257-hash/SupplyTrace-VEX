# Scanner Installation

SupplyTrace-VEX treats scanners as evidence producers. If a scanner is not installed, the adapter records `unavailable` metadata and the pipeline continues without inventing findings.

## Docker Path

The project Dockerfile installs Python 3.11 dependencies, Node.js/npm, `pip-audit`, Syft, Grype, Trivy, and a best-effort OSV-Scanner binary build. Build arguments let reviewers skip scanner installation when their network or platform policy requires it:

```bash
docker build -t supplytrace-vex:local .
docker build --build-arg INSTALL_SCANNER_TOOLS=false -t supplytrace-vex:python-only .
```

The Docker image sets `SUPPLYTRACE_ALLOW_NETWORK_SCANNER_UPDATES=false` by default for tools that maintain vulnerability databases. `npm audit` is the exception: it scans local `package-lock.json` files and queries the npm advisory service by default because offline npm audit can return an empty advisory set when no local advisory cache exists. Set `SUPPLYTRACE_NPM_AUDIT_OFFLINE=true` only for a deliberately cached offline npm-audit experiment. If a reviewer intentionally wants other scanner database updates, they must opt in:

```bash
SUPPLYTRACE_ALLOW_NETWORK_SCANNER_UPDATES=true docker compose run --rm run-scans
```

Do not use SupplyTrace-VEX to scan external application targets.

## Local Tool Commands

Install only the tools you intend to use locally. Confirm each version with the matching command before running the pipeline.

| Tool | Installation command | Version check |
| --- | --- | --- |
| Python 3.11 | Install from the Python distribution or OS package manager | `python --version` |
| Node.js/npm | Install Node.js from your OS package manager or Node.js distribution | `node --version` and `npm --version` |
| pip-audit | `python -m pip install pip-audit` | `pip-audit --version` |
| Syft | `curl -sSfL https://get.anchore.io/syft \| sudo sh -s -- -b /usr/local/bin` | `syft version` |
| Grype | `curl -sSfL https://get.anchore.io/grype \| sudo sh -s -- -b /usr/local/bin` | `grype version` |
| Trivy | Add the official Trivy apt repository, then `sudo apt-get install trivy` | `trivy --version` |
| OSV-Scanner | Use OSV-Scanner release binaries, Homebrew, WinGet, Scoop, Arch, Alpine, or FreeBSD package routes where available | `osv-scanner --version` |
| CycloneDX Python tooling | `python -m pip install cyclonedx-bom` | `cyclonedx-py --version` |
| pytest | `python -m pip install pytest` or `python -m pip install -e ".[dev]"` | `pytest --version` |

## Adapter Behavior

- `npm audit` scans local `package-lock.json` files. By default it does not pass `--offline`; set `SUPPLYTRACE_NPM_AUDIT_OFFLINE=true` only when the study intentionally relies on a local npm advisory cache.
- `pip-audit` scans pinned local requirements lockfiles with `--disable-pip --no-deps` to avoid installing arbitrary packages during scanning.
- `Trivy` scans local case directories with database updates disabled unless updates are explicitly allowed.
- `Grype` scans local directories and disables automatic database updates unless updates are explicitly allowed.
- `OSV-Scanner` scans local source directories. Offline vulnerability data is requested unless updates are explicitly allowed.

## References

- Syft installation and directory SBOM generation: https://oss.anchore.com/docs/guides/sbom/getting-started/
- Grype installation: https://oss.anchore.com/docs/installation/grype/
- Trivy installation: https://trivy.dev/docs/dev/getting-started/installation/
- OSV-Scanner installation: https://google.github.io/osv-scanner/installation/
- pip-audit usage and requirements-file auditing: https://pypi.org/project/pip-audit/
