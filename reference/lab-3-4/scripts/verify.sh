#!/usr/bin/env bash
# Verification for Lab 3.4.
#
# A gate has three outcomes and they must be told apart. Pass, fail on real
# findings, and fail closed because it had nothing to evaluate. The third is
# the one that gets faked: the guide used to test it with
#
#   policy-gate.sh --policy /tmp/no-policies-here plan.json
#
# which exits 2 because `plan.json` is not a recognized argument, before a
# single policy is loaded or the plan is read. Same exit code as the guard it
# claimed to be testing, so the guard could have been deleted entirely and
# that test would still have passed.
set -uo pipefail

WORKSPACE="${1:-.}"
cd "$WORKSPACE" 2>/dev/null || { echo "no such workspace: $WORKSPACE" >&2; exit 1; }

FAILED=0
pass() { printf '  PASS  %-10s %s\n' "$1" "$2"; }
fail() { printf '  FAIL  %-10s %s\n' "$1" "$2" >&2; FAILED=1; }

EV=$(mktemp -d)
trap 'rm -rf "$EV"' EXIT
EMPTY=$(mktemp -d)

run() { # run POLICY_DIR PLAN -> sets RC and OUT
  OUT=$(bash scripts/policy-gate.sh --policy "$1" --plan "$2" --evidence "$EV" 2>&1)
  RC=$?
}

echo "=== a compliant plan passes ==="
run policies fixtures/plan-compliant.json
if [[ $RC -eq 0 && "$OUT" == *"policy-gate: PASS"* ]]; then
  pass "compliant" "exit 0 and PASS"
else
  fail "compliant" "expected exit 0 with PASS, got exit $RC"
fi

echo "=== a degraded plan fails, citing the right controls ==="
run policies fixtures/plan-degraded.json
if [[ $RC -eq 1 ]]; then
  pass "degraded" "exit 1"
else
  fail "degraded" "expected exit 1, got $RC"
fi

CONTROLS=$(jq -r '[.[][]?.failures[]?.msg] | .[] | capture("\\[(?<c>[A-Z]+-[0-9.]+)\\]").c' \
  "$EV/conftest-results.json" 2>/dev/null | sort -u | paste -sd, -)
if [[ "$CONTROLS" == "AU-9,SC-28,SC-8" ]]; then
  pass "degraded" "cites AU-9, SC-28, SC-8"
else
  fail "degraded" "expected AU-9,SC-28,SC-8; got '${CONTROLS:-(none)}'"
fi

echo "=== a gate with no policies fails CLOSED, for the stated reason ==="
run "$EMPTY" fixtures/plan-compliant.json
if [[ $RC -eq 2 ]]; then
  pass "fail-closed" "exit 2"
else
  fail "fail-closed" "expected exit 2, got $RC"
fi

# Exit 2 alone proves nothing here: an argument typo produces it too. The
# message is what distinguishes a gate that refused to run from a gate that
# was never invoked.
if [[ "$OUT" == *"gate did not run"* ]]; then
  pass "fail-closed" "reported that the gate did not run"
else
  fail "fail-closed" "exit 2 for the wrong reason. Output was: $(head -1 <<<"$OUT")"
fi

# And prove the distinction is real, by making the mistake on purpose.
BAD=$(bash scripts/policy-gate.sh --policy policies fixtures/plan-compliant.json 2>&1)
BADRC=$?
if [[ $BADRC -eq 2 && "$BAD" == *"Unknown arg"* ]]; then
  pass "fail-closed" "a bad argument also exits 2, which is why the message is checked"
else
  fail "fail-closed" "expected a positional plan to be rejected with exit 2"
fi

rmdir "$EMPTY" 2>/dev/null
echo
if [[ $FAILED -eq 0 ]]; then
  echo "VERIFIED: the gate passes, fails, and fails closed, each for its own reason."
else
  echo "NOT VERIFIED: the gate does not behave as described. Do not capture evidence yet." >&2
fi
exit $FAILED
