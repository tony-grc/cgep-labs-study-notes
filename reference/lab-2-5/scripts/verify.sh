#!/usr/bin/env bash
# Verification for Lab 2.5. Every check asserts a value and exits non-zero if
# the account disagrees.
#
# This lab's controls are the ones most worth watching refuse. Object Lock in
# COMPLIANCE mode means nobody deletes the object, including you, including
# the account root, until the retention date passes. Reading a describe call
# that says so is not the same as watching the delete fail.
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
    fail "$control" "$label was NOT refused (exit $rc)"
  fi
}

VAULT=$(terraform output -raw vault_name)
MODE=$(terraform output -raw lock_mode)
KEY="runs/test-001/bundle.tar.gz"

# capture-evidence.sh sets VERSION_ID inside its own process, which never
# reaches yours, so derive it here rather than assuming it is set.
VERSION_ID=$(aws s3api list-object-versions --bucket "$VAULT" \
  --prefix "runs/test-001/" --query 'Versions[0].VersionId' --output text 2>/dev/null)

echo "=== configuration ==="

check SI-7 "object lock" "Enabled" \
  "$(aws s3api get-object-lock-configuration --bucket "$VAULT" \
       --query 'ObjectLockConfiguration.ObjectLockEnabled' --output text 2>/dev/null)"

check SC-28 "vault encryption" "aws:kms" \
  "$(aws s3api get-bucket-encryption --bucket "$VAULT" \
       --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
       --output text 2>/dev/null)"

# The mode is the whole lesson. GOVERNANCE can be bypassed by anyone holding
# s3:BypassGovernanceRetention; COMPLIANCE cannot be bypassed by anyone.
check AU-9 "retention mode" "$MODE" \
  "$(aws s3api get-object-retention --bucket "$VAULT" --key "$KEY" \
       --query 'Retention.Mode' --output text 2>/dev/null)"

if [[ -z "$VERSION_ID" || "$VERSION_ID" == "None" ]]; then
  fail "AU-9" "no object version found under runs/test-001/. Run capture-evidence.sh first."
else
  pass "AU-9" "object version present: $VERSION_ID"
fi

echo "=== enforcement ==="

refuse SC-8 "plain HTTP" \
  aws s3api list-objects-v2 --bucket "$VAULT" \
  --endpoint-url "http://s3.us-east-1.amazonaws.com"

# The versioned delete is the real test. Deleting without a version id only
# writes a delete marker, which succeeds and proves nothing: the object is
# still there underneath. Naming the version is what Object Lock refuses.
if [[ -n "$VERSION_ID" && "$VERSION_ID" != "None" ]]; then
  refuse AU-9 "versioned delete under $MODE retention" \
    aws s3api delete-object --bucket "$VAULT" --key "$KEY" --version-id "$VERSION_ID"
fi

# The misleading success, asserted rather than described. A delete with no
# version id writes a delete marker: the call succeeds, the object disappears
# from listings, and nothing was destroyed. It is the most misread result in
# this lab, so the script both proves it and then puts the vault back.
if aws s3api delete-object --bucket "$VAULT" --key "$KEY" >/dev/null 2>&1; then
  pass "AU-9" "unversioned delete succeeded, having written only a delete marker"
  MARKER=$(aws s3api list-object-versions --bucket "$VAULT" --prefix "$KEY" \
    --query 'DeleteMarkers[0].VersionId' --output text 2>/dev/null)
  if [[ -n "$MARKER" && "$MARKER" != "None" ]]; then
    # Delete markers carry no retention of their own, so this is permitted
    # even under COMPLIANCE mode, and it leaves the object visible again.
    if aws s3api delete-object --bucket "$VAULT" --key "$KEY" \
         --version-id "$MARKER" >/dev/null 2>&1; then
      pass "AU-9" "delete marker removed, the object is listed again"
    else
      fail "AU-9" "delete marker $MARKER could not be removed. Remove it by hand."
    fi
  fi
else
  fail "AU-9" "unversioned delete was refused, which is not how Object Lock behaves"
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: every control asserted above holds in the account."
else
  echo "NOT VERIFIED: at least one control does not hold. Do not capture evidence yet." >&2
fi
exit $FAILED
