#!/usr/bin/env bash
# Verification for Lab 2.2. Every check asserts a value and exits non-zero if
# the account disagrees.
#
# Run it from the workspace that owns the outputs.
#
# What this replaces: `aws s3api get-bucket-encryption` printed a
# configuration and exited 0 whether the algorithm was aws:kms or AES256, and
# `get-bucket-versioning` printed nothing at all and still exited 0 when
# versioning had never been turned on. Both looked like verification.
set -uo pipefail

# Point this at the workspace whose `terraform output` describes the resources
# you want checked, so it does not matter where you run it from. Guessing the
# working directory is how a verification script cheerfully checks the wrong
# account and passes.
WORKSPACE="${1:-.}"
cd "$WORKSPACE" 2>/dev/null || { echo "no such workspace: $WORKSPACE" >&2; exit 1; }

FAILED=0

pass() { printf '  PASS  %-8s %s\n' "$1" "$2"; }
fail() { printf '  FAIL  %-8s %s\n' "$1" "$2" >&2; FAILED=1; }

check() { # check CONTROL LABEL EXPECTED ACTUAL
  if [[ "$3" == "$4" ]]; then
    pass "$1" "$2 is $4"
  else
    fail "$1" "$2: expected '$3', got '${4:-(nothing)}'"
  fi
}

BUCKET=$(terraform output -raw state_bucket)
KMS=$(terraform output -raw state_kms_key_arn)

echo "=== configuration ==="

check SC-28 "state encryption" "aws:kms" \
  "$(aws s3api get-bucket-encryption --bucket "$BUCKET" \
       --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
       --output text 2>/dev/null)"

# The key has to be yours, not the AWS managed aws/s3 key, or "encrypted with
# KMS" is true and meaningless.
check SC-28 "state CMK" "$KMS" \
  "$(aws s3api get-bucket-encryption --bucket "$BUCKET" \
       --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' \
       --output text 2>/dev/null)"

check CP-9 "versioning" "Enabled" \
  "$(aws s3api get-bucket-versioning --bucket "$BUCKET" \
       --query 'Status' --output text 2>/dev/null)"

PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>/dev/null)
[[ -z "$PAB" ]] && PAB='{}'
for flag in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
  check AC-3 "$flag" "true" \
    "$(jq -r ".PublicAccessBlockConfiguration.${flag} // empty" <<<"$PAB")"
done

# SC-8. The statement has to exist AND deny, so both are asserted rather than
# eyeballed out of a jq dump.
POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null)
[[ -z "$POLICY" ]] && POLICY='{"Statement":[]}'
check SC-8 "TLS deny effect" "Deny" \
  "$(jq -r '[.Statement[] | select(.Sid=="DenyInsecureTransport")][0].Effect // empty' <<<"$POLICY")"
check SC-8 "TLS deny condition" "false" \
  "$(jq -r '[.Statement[] | select(.Sid=="DenyInsecureTransport")][0].Condition.Bool."aws:SecureTransport" // empty' <<<"$POLICY")"

echo "=== enforcement ==="

# A control you have not watched deny something is a control you are guessing
# about. This is the statement above, actually refusing.
OUT=$(aws s3api list-objects-v2 --bucket "$BUCKET" \
  --endpoint-url "http://s3.us-east-1.amazonaws.com" 2>&1)
RC=$?
if [[ $RC -ne 0 && "$OUT" == *AccessDenied* ]]; then
  pass "SC-8" "plain HTTP was refused"
else
  fail "SC-8" "plain HTTP was NOT refused (exit $RC)"
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: every control asserted above holds in the account."
else
  echo "NOT VERIFIED: at least one control does not hold. Do not capture evidence yet." >&2
fi
exit $FAILED
