#!/usr/bin/env bash
# scripts/check-prereqs.sh
FAIL=0
check() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '  %-12s %s\n' "$1" "$($2 2>&1 | head -1)"
  else
    printf '  %-12s MISSING\n' "$1"; FAIL=1
  fi
}

echo "=== toolchain ==="
check terraform "terraform version"
check aws       "aws --version"
check gcloud    "gcloud version"
check opa       "opa version"
check conftest  "conftest --version"
check trivy     "trivy --version"
check cosign    "cosign version"
check trestle   "trestle version"
check jq        "jq --version"
check gh        "gh --version"

echo "=== AWS ==="
aws sts get-caller-identity --profile "${AWS_PROFILE:-cgep}" 2>&1 | head -4 || FAIL=1

echo "=== GCP ==="
gcloud config get-value project 2>&1 | head -1
gcloud auth application-default print-access-token >/dev/null 2>&1 \
  && echo "  ADC: OK" || { echo "  ADC: MISSING (run: gcloud auth application-default login)"; FAIL=1; }

echo
[[ $FAIL -eq 0 ]] && echo "PREREQS OK" || { echo "PREREQS INCOMPLETE"; exit 1; }
