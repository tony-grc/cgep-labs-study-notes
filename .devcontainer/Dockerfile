# CGE-P lab toolchain.
#
# Built for both amd64 and arm64, because every Mac sold since 2020 is arm64
# and the manual install path in Lab 0.1 is linux/amd64 only. Docker picks the
# arch from the host, so this image is native on an Apple Silicon laptop and
# native in a Codespace, from the same file.
#
# Versions are pinned here and in docs/00_01_prerequisites.md. They must move
# together; CI's pin-freshness job reports when a pin falls behind upstream.
FROM mcr.microsoft.com/devcontainers/base:bookworm

ARG TERRAFORM_VERSION=1.15.8
ARG OPA_VERSION=1.19.1
ARG CONFTEST_VERSION=0.69.0
ARG TRIVY_VERSION=0.74.0
ARG COSIGN_VERSION=3.1.3
ARG GH_VERSION=2.98.0

# Populated automatically by BuildKit from the target platform. It MUST stay
# undefaulted: a value here wins over BuildKit's, so `--platform linux/arm64`
# would silently download amd64 binaries and produce an image that cannot run.
# CI lints for this.
ARG TARGETARCH

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip tar gnupg jq git python3 python3-pip pipx \
    && rm -rf /var/lib/apt/lists/*

# Each project names architectures differently, which is the single most
# common reason a hand-written install line fails on a Mac.
RUN set -euxo pipefail; \
    case "${TARGETARCH}" in \
      amd64) TF_A=amd64; AWS_A=x86_64;  GC_A=x86_64; OPA_A=amd64; CT_A=x86_64; TV_A=64bit; CS_A=amd64 ;; \
      arm64) TF_A=arm64; AWS_A=aarch64; GC_A=arm;    OPA_A=arm64; CT_A=arm64;  TV_A=ARM64; CS_A=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    # Terraform ships checksums, so verify rather than trust the download.
    cd /tmp; \
    curl -fsSLO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TF_A}.zip"; \
    curl -fsSLO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS"; \
    grep " terraform_${TERRAFORM_VERSION}_linux_${TF_A}.zip\$" "terraform_${TERRAFORM_VERSION}_SHA256SUMS" | sha256sum -c -; \
    unzip -q "terraform_${TERRAFORM_VERSION}_linux_${TF_A}.zip" -d /usr/local/bin; \
    \
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_A}.zip" -o awscliv2.zip; \
    unzip -q awscliv2.zip; ./aws/install; \
    \
    curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-${GC_A}.tar.gz" -o gcloud.tar.gz; \
    tar -xzf gcloud.tar.gz -C /usr/local; \
    /usr/local/google-cloud-sdk/install.sh --quiet --usage-reporting=false --path-update=false; \
    \
    curl -fsSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${OPA_A}_static" -o /usr/local/bin/opa; \
    curl -fsSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_${CT_A}.tar.gz" | tar -xz -C /usr/local/bin conftest; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TV_A}.tar.gz" | tar -xz -C /usr/local/bin trivy; \
    curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${CS_A}" -o /usr/local/bin/cosign; \
    chmod 0755 /usr/local/bin/opa /usr/local/bin/conftest /usr/local/bin/trivy /usr/local/bin/cosign; \
    \
    curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TF_A}.tar.gz" \
      | tar -xz -C /usr/local/bin --strip-components=2 "gh_${GH_VERSION}_linux_${TF_A}/bin/gh"; \
    \
    rm -rf /tmp/*

ENV PATH="/usr/local/google-cloud-sdk/bin:/home/vscode/.local/bin:${PATH}"

# ENV PATH covers non-login shells. Login shells (which is what a VS Code
# devcontainer terminal opens) source /etc/profile and rebuild PATH from
# scratch, dropping both entries above. This covers those.
RUN printf '%s\n' \
      'export PATH="/usr/local/google-cloud-sdk/bin:$HOME/.local/bin:$PATH"' \
      > /etc/profile.d/10-cgep-path.sh \
    && chmod 0644 /etc/profile.d/10-cgep-path.sh

USER vscode

# trestle is Python and architecture-independent. pipx keeps it off the system
# interpreter, which Debian marks externally-managed (PEP 668).
RUN pipx install compliance-trestle && pipx ensurepath

# `aws login` writes here, and a container rebuild would otherwise throw the
# session away. devcontainer.json mounts a named volume over it.
RUN mkdir -p /home/vscode/.aws /home/vscode/.config/gcloud
