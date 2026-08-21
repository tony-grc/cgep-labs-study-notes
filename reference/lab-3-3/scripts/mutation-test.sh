#!/usr/bin/env bash
# For each policy, apply a mutation that should break it, and require that
# `opa test` FAILS. A mutation that survives means no test constrains that
# rule, and the rule is decorative.
#
# A passing suite proves the policy returns the answer you expected on the
# inputs you thought of. It does not prove the policy is load-bearing. A rule
# with a typo in the resource type matches nothing, denies nothing, and passes
# every "compliant input produces zero denials" test you wrote. It is a control
# that cannot fail, which is to say it is not a control.
set -uo pipefail

POLICY_DIR="${1:-policies}"
FAILED=0

for f in "$POLICY_DIR"/*.rego; do
  cp "$f" "$f.bak"

  # Mutation: invert every equality comparison in the rule bodies.
  sed -i 's/ == / != /g' "$f"

  if opa test "$POLICY_DIR" >/dev/null 2>&1; then
    echo "SURVIVED: $f"
    echo "          tests still pass with the logic inverted."
    echo "          This rule is not constrained by any test."
    FAILED=1
  else
    echo "killed:   $f"
  fi

  mv "$f.bak" "$f"
done

if [[ $FAILED -eq 0 ]]; then
  echo "All policies are constrained by at least one test."
else
  echo "At least one policy is unconstrained. Treat it as enforcing nothing." >&2
fi
exit $FAILED
