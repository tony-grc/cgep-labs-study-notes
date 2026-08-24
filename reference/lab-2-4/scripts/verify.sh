#!/usr/bin/env bash
# Verification for Lab 2.4. Every check asserts a value and exits non-zero if
# the project disagrees.
#
# Run it from consumers/dev, where the outputs live.
#
# One trap this replaces: gcloud's --format projection is a filter, not a
# query. Ask for a field it does not recognize and it prints the fields it did
# understand and says nothing about the one it did not, exit code 0. An earlier
# draft asked for `logging` instead of `logging_config` and simply had no
# logging section in its output. A control that is genuinely missing and a
# field name you typed wrong look identical.
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

BUCKET=$(terraform output -raw bucket_name)
LOGS=$(terraform output -raw log_bucket_name)
ATT=$(terraform output -json compliance_attestation)
KMS_ID=$(jq -r '.kms_key_id' <<<"$ATT")

# projects/P/locations/L/keyRings/R/cryptoKeys/K
KEY_PROJECT=$(awk -F/ '{print $2}' <<<"$KMS_ID")
KEY_LOCATION=$(awk -F/ '{print $4}' <<<"$KMS_ID")
KEY_RING=$(awk -F/ '{print $6}' <<<"$KMS_ID")
KEY_NAME=$(awk -F/ '{print $8}' <<<"$KMS_ID")

bucket_field() { # bucket_field BUCKET FIELD
  gcloud storage buckets describe "gs://$1" --format="value($2)" 2>/dev/null
}

# Booleans are read as JSON rather than through value(), which renders them
# with Python's capitalisation. Asserting against "True" when the tool happens
# to emit "true" is a failure that teaches nothing.
bucket_json() { # bucket_json BUCKET JQ_PATH
  gcloud storage buckets describe "gs://$1" --format=json 2>/dev/null \
    | jq -r "$2 // empty"
}

echo "=== configuration ==="

# SC-13 / SC-28. The key itself, not merely that some key is set.
check SC-28 "default CMEK" "$KMS_ID" "$(bucket_field "$BUCKET" default_kms_key)"

# SC-12. Ninety days, in seconds, because the API is not sorry about it.
check SC-12 "key rotation" "7776000s" \
  "$(gcloud kms keys describe "$KEY_NAME" --keyring="$KEY_RING" \
       --location="$KEY_LOCATION" --project="$KEY_PROJECT" \
       --format="value(rotationPeriod)" 2>/dev/null)"

# CP-9 and AU-9.
check CP-9 "data versioning" "true" "$(bucket_json "$BUCKET" .versioning_enabled)"
check AU-9 "log versioning"  "true" "$(bucket_json "$LOGS" .versioning_enabled)"

# AC-3 and AC-6.
check AC-3 "public access prevention" "enforced" \
  "$(bucket_field "$BUCKET" public_access_prevention)"
check AC-6 "uniform bucket access" "true" \
  "$(bucket_json "$BUCKET" .uniform_bucket_level_access)"

# AU-3. The target has to be the log bucket, not merely some bucket. This is
# the field that was silently absent when the name was wrong.
check AU-3 "log target" "$LOGS" "$(bucket_field "$BUCKET" logging_config.logBucket)"

# AU-11. Asserted against the module's own attestation, so a disagreement
# between the code and the project shows up as a failure rather than as two
# numbers nobody compared.
check AU-11 "retention seconds" \
  "$(( $(jq -r '.retention_period_days' <<<"$ATT") * 86400 ))" \
  "$(bucket_field "$BUCKET" retention_policy.retentionPeriod)"

echo "=== enforcement ==="

# AC-3, without touching anything. An unauthenticated read of the bucket
# listing must be refused. This is deliberately a read: the obvious GCP denial
# test is to try adding allUsers as a viewer, and if the control were missing
# that test would succeed and leave your bucket public. A check that damages
# the thing it is checking when it fails is not worth running.
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  "https://storage.googleapis.com/storage/v1/b/${BUCKET}/o" 2>/dev/null)
if [[ "$CODE" == "401" || "$CODE" == "403" ]]; then
  pass "AC-3" "anonymous listing refused with HTTP $CODE"
else
  fail "AC-3" "anonymous listing returned HTTP ${CODE:-(no response)}, expected 401 or 403"
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: every control asserted above holds in the project."
else
  echo "NOT VERIFIED: at least one control does not hold. Do not capture evidence yet." >&2
fi
exit $FAILED
