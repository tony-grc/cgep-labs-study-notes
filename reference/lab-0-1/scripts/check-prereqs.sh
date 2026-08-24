#!/usr/bin/env bash
# scripts/check-prereqs.sh
FAIL=0
check() { # check TOOL COMMAND
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '  %-12s MISSING\n' "$1"; FAIL=1; return
  fi
  # eval, because some tools need a pipeline to yield a legible version.
  # cosign prints an ASCII banner, so `head -1` alone reported banner art and
  # the one tool whose whole job is supply-chain integrity was the one this
  # script never actually verified.
  out=$(eval "$2" 2>&1 | head -1)
  if [ -z "$out" ]; then
    # Installed but silent. Treat that as a failure: a check that prints
    # nothing and passes is the thing this course keeps warning about.
    printf '  %-12s INSTALLED, but reported no version\n' "$1"; FAIL=1
  else
    printf '  %-12s %s\n' "$1" "$out"
  fi
}

echo "=== toolchain ==="
check terraform "terraform version"
check aws       "aws --version"
check gcloud    "gcloud version"
check opa       "opa version"
check conftest  "conftest --version"
check trivy     "trivy --version"
check cosign    "cosign version 2>&1 | grep -iE \"gitversion\""
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
