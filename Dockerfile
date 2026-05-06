FROM python:3.11-slim

ARG INSTALL_SCANNER_TOOLS=true
ARG OSV_SCANNER_VERSION=latest

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SUPPLYTRACE_ALLOW_NETWORK_SCANNER_UPDATES=false \
    SUPPLYTRACE_NPM_AUDIT_OFFLINE=false \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      gnupg \
      golang-go \
      nodejs \
      npm \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY supplytrace ./supplytrace
COPY docs ./docs
COPY scripts ./scripts
COPY tests ./tests
COPY AGENTS.md CITATION.cff .env.example ./

RUN python -m pip install --upgrade pip \
    && python -m pip install -e ".[dev,tools]" \
    && chmod +x scripts/*.sh

RUN if [ "${INSTALL_SCANNER_TOOLS}" = "true" ]; then \
      curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
      curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list && \
      apt-get update && apt-get install -y --no-install-recommends trivy && rm -rf /var/lib/apt/lists/* && \
      if ! GOBIN=/usr/local/bin go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}; then \
        echo "OSV-Scanner installation did not complete; the adapter will report it unavailable."; \
      fi; \
    fi

RUN python --version \
    && node --version \
    && npm --version \
    && pytest --version \
    && pip-audit --version \
    && cyclonedx-py --version \
    && if [ "${INSTALL_SCANNER_TOOLS}" = "true" ]; then \
      syft version && grype version && trivy --version && \
      if command -v osv-scanner >/dev/null 2>&1; then osv-scanner --version; else echo "osv-scanner unavailable"; fi; \
    fi

ENTRYPOINT ["python", "-m", "supplytrace"]
CMD ["--help"]
