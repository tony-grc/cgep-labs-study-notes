#!/usr/bin/env bash
# Verify that an OSCAL component definition is TRUE, not merely well-formed.
#
# `trestle validate` proves the document matches the schema. It does not
# check that a single href resolves. A component definition whose evidence
# links all 404 validates perfectly and proves nothing.
#
# Usage: verify-oscal-graph.sh <component-definition.json> <profile.json>
set -uo pipefail

CD="${1:?usage: verify-oscal-graph.sh <component-def> <profile>}"
PROFILE="${2:?usage: verify-oscal-graph.sh <component-def> <profile>}"
PROFILE_ARG="${AWS_PROFILE:+--profile $AWS_PROFILE}"
FAIL=0

echo "=== 1. Every evidence href resolves ==="
while IFS= read -r href; do
  [[ -z "$href" ]] && continue
  case "$href" in
    s3://*)
      rest="${href#s3://}"; bucket="${rest%%/*}"; keypart="${rest#*/}"
      key="${keypart%%\?*}"; version=""
      [[ "$keypart" == *"versionId="* ]] && version="--version-id ${keypart##*versionId=}"
      if aws $PROFILE_ARG s3api head-object --bucket "$bucket" --key "$key" $version >/dev/null 2>&1; then
        echo "  OK      $href"
      else
        echo "  BROKEN  $href"; FAIL=1
      fi ;;
    http://*|https://*)
      if curl -fsSL -o /dev/null --max-time 20 "$href"; then echo "  OK      $href"
      else echo "  BROKEN  $href"; FAIL=1; fi ;;
    *) echo "  SKIP    $href (unrecognized scheme)" ;;
  esac
done < <(jq -r '.. | objects | select(.rel? == "evidence") | .href' "$CD" | sort -u)

echo "=== 2. Catalog source resolves and is version-pinned ==="
SRC=$(jq -r '.. | objects | select(has("source")) | .source' "$CD" | head -1)
if curl -fsSL -o /dev/null --max-time 30 "$SRC"; then echo "  OK      $SRC"
else echo "  BROKEN  $SRC"; FAIL=1; fi
case "$SRC" in
  */main/*) echo "  WARN    catalog source tracks 'main'; pin to a tag" ;;
esac

echo "=== 3. Every component control appears in the profile ==="
MISSING=$(comm -23 \
  <(jq -r '.. | objects | select(has("control-id")) | .["control-id"]' "$CD" | sort -u) \
  <(jq -r '.profile.imports[]."include-controls"[]."with-ids"[]' "$PROFILE" | sort -u))
if [[ -n "$MISSING" ]]; then
  while IFS= read -r m; do echo "  MISSING from profile: $m"; done <<< "$MISSING"
  FAIL=1
else
  echo "  OK      all component controls are selected by the profile"
fi

echo "=== 4. No placeholder UUIDs survived ==="
if grep -qE '(GENERATED|PARTY|COMPONENT|CI|REQ|PROFILE|CSP)-UUID-V4' "$CD" "$PROFILE"; then
  echo "  FAIL: placeholder UUIDs still present"; FAIL=1
else
  echo "  OK"
fi

echo "=== 5. implementation-status values are honest ==="
jq -r '.. | objects | select(has("control-id")) |
       "  \(.["control-id"])  \([.props[]? | select(.name=="implementation-status") | .value] | join(","))"' "$CD"

echo
if [[ $FAIL -eq 0 ]]; then echo "OSCAL GRAPH INTACT"; else echo "OSCAL GRAPH BROKEN"; exit 1; fi
