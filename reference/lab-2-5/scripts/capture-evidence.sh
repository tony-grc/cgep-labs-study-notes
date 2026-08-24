#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --vault <bucket>
#                       [--profile <p>] [--include-state] [--i-understand-compliance-mode]

set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
VAULT=""
INCLUDE_STATE=0
ACK_COMPLIANCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2";    shift 2 ;;
    --vault)     VAULT="$2";     shift 2 ;;
    --profile)   PROFILE_ARG="--profile $2"; shift 2 ;;
    --include-state) INCLUDE_STATE=1; shift ;;
    --i-understand-compliance-mode) ACK_COMPLIANCE=1; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

# Refuse the one irreversible combination: raw state into unbypassable storage.
if [[ $INCLUDE_STATE -eq 1 && $ACK_COMPLIANCE -eq 0 ]]; then
  MODE=$(aws $PROFILE_ARG s3api get-object-lock-configuration --bucket "$VAULT" \
          --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' \
          --output text 2>/dev/null || echo "NONE")
  if [[ "$MODE" == "COMPLIANCE" ]]; then
    echo "REFUSING: --include-state against a COMPLIANCE-mode vault." >&2
    echo "Terraform state contains every attribute in plaintext, including secrets." >&2
    echo "COMPLIANCE retention cannot be bypassed by anyone, including root." >&2
    echo "Pass --i-understand-compliance-mode if this is genuinely what you want." >&2
    exit 3
  fi
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum   >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

# plan.json: the configuration and intent. The primary artifact.
( cd "$WORKSPACE" && [[ -f tfplan ]] \
    && terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )

# The module's own attestation, if it emits one (Lab 2.3 does).
( cd "$WORKSPACE" && terraform output -json compliance_attestation \
    > "$BUNDLE_DIR/attestation.json" 2>/dev/null || true )

if [[ $INCLUDE_STATE -eq 1 ]]; then
  ( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )
fi

( cd "$WORKSPACE" && git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
    || echo "no git commit available" > "$BUNDLE_DIR/commit.txt" )
terraform version > "$BUNDLE_DIR/version.txt"

# manifest.json: filename, sha256, size, captured_at per file.
{
  echo "["
  FIRST=1
  for f in "$BUNDLE_DIR"/*; do
    base=$(basename "$f")
    [[ "$base" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$base" "$HASH" "$SIZE" "$CAPTURED_AT"
  done
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE_TGZ="$WORK/bundle-$RUN_ID.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )

KEY="runs/$RUN_ID/bundle.tar.gz"
VERSION_ID=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "$KEY" --body "$BUNDLE_TGZ" \
  --query VersionId --output text)

printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","captured_at_utc":"%s","includes_state":%s}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$CAPTURED_AT" \
  "$([[ $INCLUDE_STATE -eq 1 ]] && echo true || echo false)"