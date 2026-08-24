#!/usr/bin/env bash
# Verification for Lab 5.4. Every check asserts a value and exits non-zero if
# the project disagrees.
#
# Everything is read as JSON and compared with jq. gcloud's value() projection
# renders booleans with Python's capitalisation and silently omits any field
# name it does not recognize, so a typo and a missing control look the same.
set -uo pipefail

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

PROJECT="${TF_VAR_gcp_project:?set TF_VAR_gcp_project, or source cgep.env}"
SA=$(terraform output -raw service_account_email)
PROVIDER=$(terraform output -raw workload_identity_provider)
MODE=$(terraform output -raw enforce_mode)

# projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/NAME
POOL=$(awk -F/ '{print $6}' <<<"$PROVIDER")

# enforce writes spec; dry_run writes dryRunSpec. Asserting the wrong one
# passes a project where nothing is actually enforced.
if [[ "$MODE" == "enforce" ]]; then
  SPEC=".spec"
else
  SPEC=".dryRunSpec"
fi

echo "=== org policy constraints (mode: $MODE) ==="

for constraint in storage.uniformBucketLevelAccess storage.publicAccessPrevention \
                  iam.disableServiceAccountKeyCreation compute.requireOsLogin; do
  check ORG "$constraint" "true" \
    "$(gcloud org-policies describe "$constraint" --project="$PROJECT" --format=json 2>/dev/null \
       | jq -r "${SPEC}.rules[0].enforce // empty")"
done

echo "=== data access logging ==="

# AU-3 and AU-12. ADMIN_READ is on by default; DATA_READ and DATA_WRITE are
# the ones that cost money and are therefore the ones people quietly skip.
IAM=$(gcloud projects get-iam-policy "$PROJECT" --format=json 2>/dev/null)
[[ -z "$IAM" ]] && IAM='{}'
for service in storage.googleapis.com cloudkms.googleapis.com iam.googleapis.com; do
  for logtype in ADMIN_READ DATA_READ DATA_WRITE; do
    check AU-12 "$service $logtype" "$logtype" \
      "$(jq -r --arg s "$service" --arg t "$logtype" \
           '[.auditConfigs[]? | select(.service==$s) | .auditLogConfigs[]? | select(.logType==$t) | .logType][0] // empty' \
           <<<"$IAM")"
  done
done

echo "=== workload identity ==="

check AC-3 "pool state" "ACTIVE" \
  "$(gcloud iam workload-identity-pools describe "$POOL" --location=global \
       --project="$PROJECT" --format=json 2>/dev/null | jq -r '.state // empty')"

# AC-6. The gate service account must not carry primitive roles. Anything
# matching roles/owner, roles/editor or roles/viewer here defeats the point of
# a purpose-built identity.
PRIMITIVE=$(jq -r --arg sa "serviceAccount:$SA" \
  '[.bindings[]? | select(.members[]? == $sa) | .role
    | select(. == "roles/owner" or . == "roles/editor" or . == "roles/viewer")] | length' \
  <<<"$IAM")
check AC-6 "primitive roles on gate SA" "0" "$PRIMITIVE"

echo "=== enforcement ==="

# The service account key constraint, actually refusing.
#
# This one attempts a WRITE, which needs care: if the constraint is missing the
# attempt succeeds and leaves a real, long-lived private key on disk and in the
# project. So it is cleaned up immediately and reported as a failure, which is
# what it is.
KEYFILE=$(mktemp /tmp/cgep-sa-key.XXXXXX.json)
if gcloud iam service-accounts keys create "$KEYFILE" \
     --iam-account="$SA" --project="$PROJECT" >/dev/null 2>&1; then
  KEY_ID=$(jq -r '.private_key_id // empty' "$KEYFILE" 2>/dev/null)
  if [[ -n "$KEY_ID" ]]; then
    gcloud iam service-accounts keys delete "$KEY_ID" --iam-account="$SA" \
      --project="$PROJECT" --quiet >/dev/null 2>&1 \
      && fail "AC-6" "key creation SUCCEEDED and was rolled back. The constraint is not enforcing." \
      || fail "AC-6" "key creation SUCCEEDED and could not be rolled back. Delete key $KEY_ID by hand, now."
  else
    fail "AC-6" "key creation SUCCEEDED. The constraint is not enforcing."
  fi
else
  pass "AC-6" "service account key creation was refused"
fi
rm -f "$KEYFILE"

echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: every control asserted above holds in the project."
else
  echo "NOT VERIFIED: at least one control does not hold. Do not capture evidence yet." >&2
fi
exit $FAILED
