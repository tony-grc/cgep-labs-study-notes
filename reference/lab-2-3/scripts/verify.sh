#!/usr/bin/env bash
# Verification for Lab 2.3. Every check asserts a value and exits non-zero if
# the cloud disagrees.
#
# The point is that this script CAN fail. The describe calls it replaces could
# not. `aws s3api get-bucket-encryption` exits 0 whether the answer is aws:kms
# or AES256, and since S3 turned on default encryption for every bucket it
# essentially never fails at all. `get-bucket-versioning` on a bucket where
# versioning was never enabled prints nothing and also exits 0. Reading that
# output and nodding is not verification, it just feels like it.
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

refuse() { # refuse CONTROL LABEL COMMAND...
  local control=$1 label=$2 out rc
  shift 2
  out=$("$@" 2>&1)
  rc=$?
  if [[ $rc -ne 0 && "$out" == *AccessDenied* ]]; then
    pass "$control" "$label was refused"
  else
    fail "$control" "$label was NOT refused (exit $rc). A control you have not watched deny is a guess."
  fi
}

BUCKET=$(terraform output -raw bucket_name)
LOGS=$(terraform output -raw log_bucket_name)
KMS=$(terraform output -raw kms_key_arn)

echo "=== configuration ==="

# SC-28. The algorithm, not merely the presence of a configuration.
check SC-28 "bucket encryption" "aws:kms" \
  "$(aws s3api get-bucket-encryption --bucket "$BUCKET" \
       --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
       --output text 2>/dev/null)"

# SC-12 / SC-13. AWS renders booleans as True.
check SC-12 "key rotation" "True" \
  "$(aws kms get-key-rotation-status --key-id "$KMS" \
       --query 'KeyRotationEnabled' --output text 2>/dev/null)"

# CP-9 and AU-9. An unversioned bucket has no Status field at all, so this
# reads as empty and fails, where the bare describe printed nothing and passed.
check CP-9 "primary versioning" "Enabled" \
  "$(aws s3api get-bucket-versioning --bucket "$BUCKET" \
       --query 'Status' --output text 2>/dev/null)"
check AU-9 "log versioning" "Enabled" \
  "$(aws s3api get-bucket-versioning --bucket "$LOGS" \
       --query 'Status' --output text 2>/dev/null)"

# AC-3. All four flags, named individually so a failure says which one.
PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>/dev/null)
# A bucket with no public access block at all fails the call, and an empty
# string is not JSON, so jq would error instead of reporting the missing flag.
[[ -z "$PAB" ]] && PAB='{}'
for flag in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
  check AC-3 "$flag" "true" \
    "$(jq -r ".PublicAccessBlockConfiguration.${flag} // empty" <<<"$PAB")"
done

# AC-6.
check AC-6 "object ownership" "BucketOwnerEnforced" \
  "$(aws s3api get-bucket-ownership-controls --bucket "$BUCKET" \
       --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>/dev/null)"

# AU-3. The target has to be the log bucket, not merely some bucket.
check AU-3 "log target" "$LOGS" \
  "$(aws s3api get-bucket-logging --bucket "$BUCKET" \
       --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)"

# AU-11. Compared against the module's own attestation, so this catches drift
# between what the code claims and what the account actually holds.
EXPECTED_DAYS=$(terraform output -json compliance_attestation | jq -r '.log_retention_days')
check AU-11 "log expiry days" "$EXPECTED_DAYS" \
  "$(aws s3api get-bucket-lifecycle-configuration --bucket "$LOGS" \
       --query 'Rules[?ID==`expire-access-logs`].Expiration.Days | [0]' \
       --output text 2>/dev/null)"

echo "=== enforcement ==="

# SC-8. Configuration says TLS is required; this is the bucket saying no.
refuse SC-8 "plain HTTP" \
  aws s3api list-objects-v2 --bucket "$BUCKET" \
  --endpoint-url "http://s3.us-east-1.amazonaws.com"

echo test > /tmp/cgep-verify.txt

# SC-28. An upload with no encryption header.
refuse SC-28 "unencrypted upload" \
  aws s3 cp /tmp/cgep-verify.txt "s3://$BUCKET/verify.txt"

# The same upload done correctly has to succeed, or the policy is simply
# broken rather than strict.
if aws s3 cp /tmp/cgep-verify.txt "s3://$BUCKET/verify.txt" \
     --sse aws:kms --sse-kms-key-id "$KMS" >/dev/null 2>&1; then
  pass "SC-28" "correctly encrypted upload succeeded"
else
  fail "SC-28" "correctly encrypted upload was refused. The policy denies everything, which is not the control."
fi
rm -f /tmp/cgep-verify.txt

echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: every control asserted above holds in the account."
else
  echo "NOT VERIFIED: at least one control does not hold. Do not capture evidence yet." >&2
fi
exit $FAILED
