#!/usr/bin/env bash
# Verification for Lab 3.3.
#
# The failure this exists to prevent: `opa eval` against a zero byte plan.json
# returns [] for every namespace and exits 0. An empty deny set is also what
# success looks like once you have fixed the fixture, so a pipeline that broke
# three commands earlier is indistinguishable from a clean run. This asserts
# the INPUT is real before it believes anything the policies say about it.
#
#   bash scripts/verify.sh                 # the shipped fixture, expect denials
#   bash scripts/verify.sh --expect-clean  # after you fix it, expect none
set -uo pipefail

EXPECT_CLEAN=0
[[ "${1:-}" == "--expect-clean" ]] && EXPECT_CLEAN=1

FAILED=0
pass() { printf '  PASS  %-8s %s\n' "$1" "$2"; }
fail() { printf '  FAIL  %-8s %s\n' "$1" "$2" >&2; FAILED=1; }

PLAN=terraform/plan.json

echo "=== the input ==="

if [[ ! -s "$PLAN" ]]; then
  fail INPUT "$PLAN is missing or empty. terraform plan probably failed, and every deny set below would read [] regardless."
  echo; echo "NOT VERIFIED: no plan to evaluate." >&2
  exit 1
fi
pass INPUT "$PLAN is $(wc -c < "$PLAN") bytes"

if ! jq -e . "$PLAN" >/dev/null 2>&1; then
  fail INPUT "$PLAN is not valid JSON."
  echo; echo "NOT VERIFIED: no plan to evaluate." >&2
  exit 1
fi

# A plan that parses can still describe nothing. Count what the policies read.
RESOURCES=$(jq '[.planned_values.root_module.resources[]?] | length' "$PLAN" 2>/dev/null)
if [[ "${RESOURCES:-0}" -gt 0 ]]; then
  pass INPUT "plan describes $RESOURCES resources"
else
  fail INPUT "plan parses but describes no resources, so every policy has nothing to judge."
  echo; echo "NOT VERIFIED: nothing to evaluate." >&2
  exit 1
fi

echo "=== deny sets ==="

# Expected counts for the fixture as shipped. Each broken resource is flagged
# exactly once by the control that owns it, and AC-3 owns two of them: the
# public bucket and the open SSH rule.
declare -A EXPECTED=( [sc28]=1 [ac3]=2 [cm6]=1 [au3]=1 [au9]=1 )

for ns in sc28 ac3 cm6 au3 au9; do
  count=$(opa eval -d policies -i "$PLAN" "data.compliance.$ns.deny" --format=json 2>/dev/null \
          | jq '[.result[]?.expressions[]?.value[]?] | length')
  count=${count:-0}
  if [[ $EXPECT_CLEAN -eq 1 ]]; then
    want=0
  else
    want=${EXPECTED[$ns]}
  fi
  if [[ "$count" == "$want" ]]; then
    pass "$ns" "$count denial(s)"
  else
    fail "$ns" "expected $want denial(s), got $count"
  fi
done

echo
if [[ $FAILED -eq 0 ]]; then
  if [[ $EXPECT_CLEAN -eq 1 ]]; then
    echo "VERIFIED: the fixture is clean, and the plan it was judged against was real."
  else
    echo "VERIFIED: every control fired exactly where expected."
  fi
else
  echo "NOT VERIFIED: the deny sets do not match. Do not capture evidence yet." >&2
fi
exit $FAILED
