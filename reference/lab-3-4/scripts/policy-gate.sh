#!/usr/bin/env bash
# Fail-closed Conftest gate over a Terraform plan.
#
# Usage:
#   policy-gate.sh --workspace <dir>   # runs `terraform show -json tfplan` there
#   policy-gate.sh --plan <plan.json>  # uses an existing plan JSON
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
PLAN=""
EVIDENCE_DIR="evidence/lab-3-4"

NAMESPACES=(
  compliance.sc8_aws
  compliance.sc28_aws
  compliance.ac3_aws
  compliance.au9_aws
  compliance.cm6_aws
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --plan)      PLAN="$2";      shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    --evidence)  EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PLAN" ]]; then
  [[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <dir> | --plan <plan.json>" >&2; exit 2; }
  ( cd "$WORKSPACE" && terraform show -json tfplan > plan.json )
  PLAN="$WORKSPACE/plan.json"
fi

mkdir -p "$EVIDENCE_DIR"
RESULTS="$EVIDENCE_DIR/conftest-results.json"
EXIT=0

{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$PLAN" || true)
    echo "${OUT:-[]}"
    if ! echo "${OUT:-[]}" | jq -e 'all(.[]; (.failures // []) | length == 0)' >/dev/null 2>&1; then
      EXIT=1
    fi
  done
  echo "]"
} > "$RESULTS"

# Fail closed if the gate produced nothing. An empty result set is not a
# pass: a rule that matches nothing and a rule that found nothing wrong are
# indistinguishable in the output. This is the check that makes the gate a
# gate rather than a decoration.
if ! jq -e 'flatten | length > 0' "$RESULTS" >/dev/null 2>&1; then
  echo "policy-gate: FAIL (no policy results produced; gate did not run)" >&2
  exit 2
fi

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  jq -r 'flatten | .[] | (.failures // [])[] | .msg' "$RESULTS" >&2
fi
exit $EXIT
