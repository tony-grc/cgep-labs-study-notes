#!/usr/bin/env bash
# Verify one evidence bundle end to end.
#
# Chain of custody is four properties, and this checks all four:
#   integrity     the bytes have not changed        SHA-256 recompute
#   authenticity  a KNOWN signer made it            cosign + cert identity
#   timeliness    when it was signed                Rekor transparency log
#   completeness  nothing was quietly removed       manifest file list
#
# Usage: verify-evidence.sh <run_id> [--vault B] [--profile P] [--identity REGEX]
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault B] [--profile P] [--identity REGEX]}"
shift || true

VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
IDENTITY="${COSIGN_IDENTITY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)    VAULT="$2";   shift 2 ;;
    --profile)  PROFILE_ARG="--profile $2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHA256="sha256sum"
else SHA256="shasum -a 256"; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz 2>/dev/null | head -1)
[[ -z "$BUNDLE" ]] && { echo "FAIL: no bundle found at ${PREFIX}" >&2; exit 1; }

echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHA256 "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }
echo "  OK (${ACTUAL})"

echo "=== 2. Authenticity + timeliness (Cosign / Sigstore Rekor) ==="
# Derive the expected signer from the receipt unless overridden.
#
# --certificate-identity-regexp '.*' is the tempting default and it accepts
# a certificate issued to ANY workflow in ANY repository on GitHub. The
# signature is real; the question "whose signature" is never asked.
# Authenticity is not "a valid signature exists", it is "a valid signature
# from the identity I expect".
if [[ -z "$IDENTITY" && -f receipt.json ]]; then
  REPO=$(jq -r '.repo // empty' receipt.json)
  [[ -n "$REPO" ]] && IDENTITY="^https://github.com/${REPO}/\\.github/workflows/.*@refs/.*$"
fi
[[ -z "$IDENTITY" ]] && { echo "FAIL: no signer identity to check against." >&2; exit 1; }

cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"
echo "  OK (signed by an identity matching ${IDENTITY})"

echo "=== 3. Completeness (manifest) ==="
# The attack this catches: repackage the bundle without the file that showed
# the finding, and re-sign it. Integrity and authenticity both still pass.
mkdir -p extracted && tar xzf "${BUNDLE}" -C extracted
if [[ -f extracted/.manifest.txt ]]; then
  MISSING=0
  while IFS= read -r f; do
    [[ -e "extracted/$f" ]] || { echo "  MISSING: $f"; MISSING=1; }
  done < extracted/.manifest.txt
  [[ $MISSING -eq 0 ]] || { echo "FAIL: bundle is missing files listed in its manifest"; exit 1; }
  ( cd extracted && $SHA256 -c .sha256sums.txt --quiet ) \
    || { echo "FAIL: a bundled file does not match its recorded hash"; exit 1; }
  echo "  OK ($(wc -l < extracted/.manifest.txt) files present and matching)"
else
  echo "FAIL: no manifest in bundle; completeness cannot be established"; exit 1
fi

echo "=== 4. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
# Compare as EPOCH SECONDS, for robustness rather than to fix a live bug.
# The obvious shorthand, [[ "$RETAIN_UNTIL" > "$NOW" ]], gives the CORRECT
# answer for AWS's actual output over 200k tested cases: both strings share
# a fixed-width zero-padded ISO prefix, and the formats diverge only at the
# character after the seconds, which is consulted solely when the two are
# the same second, where "not in the future" is right either way.
#
# It is fragile, not broken. Feed it a non-UTC offset and it fails in both
# directions: 2026-08-18T16:00:00-05:00 is an hour ahead of 20:00:00Z and
# compares as expired. AWS returns UTC, so the string test is correct by
# coincidence. Epoch comparison is correct by construction.
RETAIN_EPOCH=$(date -d "$RETAIN_UNTIL" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%S" "${RETAIN_UNTIL%.*}" +%s)
NOW_EPOCH=$(date -u +%s)
[[ "$RETAIN_EPOCH" -gt "$NOW_EPOCH" ]] || { echo "FAIL: retention expired"; exit 1; }
echo "  OK (retain until ${RETAIN_UNTIL})"

echo
echo "CHAIN INTACT for run ${RUN_ID}"
