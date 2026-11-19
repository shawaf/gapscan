# syntax=docker/dockerfile:1.7
# GapScan offline image: scanners, GapScan itself and the data bundle, all preinstalled so that
#   docker run --rm --network none ... gapscan-offline scan /scan
# works on a machine with no network. Build it on a CONNECTED machine (it downloads the pinned
# scanners once); the finished image never needs the network.
#
#   make docker-build BUNDLE=build/bundle/gapscan-bundle.tar.gz
#
# Behind a TLS-inspecting proxy, give its CA bundle as a build secret (curl and pip only, never
# stored in a layer): DOCKER_BUILD_ARGS="--secret id=ca_bundle,src=/path/to/ca.pem" make docker-build
#
# The language model is NOT in this image: `scan`, `report` and `doctor` work fully offline, while
# `triage` needs an LLM endpoint on localhost or an internal host (hard rule), so run Ollama next to
# the container (--network host or a private network) when you want model review.
FROM python:3.12-slim-bookworm

ARG TARGETARCH
# Pinned scanner releases and the checksums the projects publish for them.
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.6.0
ARG TRIVY_VERSION=0.74.0
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG OSV_SHA256_ARM64=2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4
ARG OSV_SHA256_AMD64=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Go-based scanners: download, verify the pinned sha256, install. A mismatch fails the build.
RUN --mount=type=secret,id=ca_bundle,required=false set -eux; \
    if [ -s /run/secrets/ca_bundle ]; then export CURL_CA_BUNDLE=/run/secrets/ca_bundle; fi; \
    case "$TARGETARCH" in \
      arm64) GL=arm64; GL_SHA=$GITLEAKS_SHA256_ARM64; OSV=arm64; OSV_SHA=$OSV_SHA256_ARM64; TV=ARM64; TV_SHA=$TRIVY_SHA256_ARM64 ;; \
      amd64) GL=x64;   GL_SHA=$GITLEAKS_SHA256_AMD64; OSV=amd64; OSV_SHA=$OSV_SHA256_AMD64; TV=64bit; TV_SHA=$TRIVY_SHA256_AMD64 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSL -o gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz"; \
    echo "${GL_SHA}  gl.tgz" | sha256sum -c -; tar -xzf gl.tgz gitleaks; install -m 0755 gitleaks /usr/local/bin/gitleaks; \
    curl -fsSL -o osv "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV}"; \
    echo "${OSV_SHA}  osv" | sha256sum -c -; install -m 0755 osv /usr/local/bin/osv-scanner; \
    curl -fsSL -o tv.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TV}.tar.gz"; \
    echo "${TV_SHA}  tv.tgz" | sha256sum -c -; tar -xzf tv.tgz trivy; install -m 0755 trivy /usr/local/bin/trivy; \
    rm -f /tmp/gl.tgz /tmp/gitleaks /tmp/osv /tmp/tv.tgz /tmp/trivy

# Python scanners in their own environment so their dependencies cannot clash with GapScan's.
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi \
    && python -m venv /opt/scanners \
    && /opt/scanners/bin/pip install semgrep==1.176.0 bandit==1.9.4 checkov==3.3.20 \
    && ln -s /opt/scanners/bin/semgrep /opt/scanners/bin/bandit /opt/scanners/bin/checkov /usr/local/bin/

# GapScan, installed from the locked runtime requirements (make docker-build writes the lock file).
COPY docker/requirements.lock /tmp/requirements.lock
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi \
    && pip install -r /tmp/requirements.lock
COPY pyproject.toml README.md /opt/gapscan-src/
COPY packages /opt/gapscan-src/packages
RUN pip install --no-deps /opt/gapscan-src/packages/gapscan-core /opt/gapscan-src/packages/gapscan-engine \
    /opt/gapscan-src/packages/gapscan-security \
    /opt/gapscan-src/packages/gapscan-local

# Data: installed from the bundle with `gapscan update`, which verifies every checksum. The bundle is
# bind-mounted during the build, so it is not stored in any image layer.
COPY docker/gapscan.toml /opt/gapscan/gapscan.toml
RUN useradd --create-home --uid 10001 gapscan && mkdir -p /opt/gapscan/data /work \
    && chown -R gapscan:gapscan /opt/gapscan /work
ENV GAPSCAN_CONFIG=/opt/gapscan/gapscan.toml \
    HOME=/home/gapscan \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_VERSION_CHECK_URL=
USER gapscan
RUN --mount=type=bind,source=docker/bundle,target=/bundle \
    gapscan update --from /bundle/gapscan-bundle.tar.gz --no-model \
    && if [ -d /opt/gapscan/data/semgrep-rules ]; then \
         echo "This image contains the Semgrep community rules (Semgrep Rules License v1.0): internal use only, do not publish it." > /opt/gapscan/IMAGE-NOTICE.txt; \
       fi

WORKDIR /work
ENTRYPOINT ["gapscan"]
CMD ["--help"]
