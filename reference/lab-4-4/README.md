# Lab 4.4 reference: evidence chain of custody

Guide: [`docs/04_04_evidence_chain_of_custody.md`](../../docs/04_04_evidence_chain_of_custody.md)

```
scripts/verify-evidence.sh    the four-property check
.github/workflows/            grc-gate.yml with signing, 16 steps
```

Chain of custody is four properties. Most pipelines implement two.

| Property | Broken by | Closed by |
|---|---|---|
| Integrity | byte-level tampering | SHA-256 recompute |
| Authenticity | anyone can fabricate a bundle | Cosign + **constrained cert identity** |
| Timeliness | backdated evidence | Rekor transparency log |
| Completeness | quietly dropping a file | manifest list, checked |

```bash
EVIDENCE_VAULT=<your-vault> bash scripts/verify-evidence.sh <run_id>
```

## Constrain the signer, or you have not checked authenticity

The tempting default is `--certificate-identity-regexp '.*'`, and it accepts a
certificate issued to **any** workflow in **any** repository on GitHub. Anyone
with a public repo can produce a bundle that passes. The signature is real; the
question "whose signature" is never asked.

Authenticity is not "a valid signature exists", it is "a valid signature from
the identity I expect". This script derives the expected identity from the
receipt and refuses to run without one.

## Why epoch seconds, when string comparison also works

The obvious shorthand for the retention check is:

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]]
```

AWS returns `...+00:00`, `date -u` emits `...Z`, and comparing mismatched
formats as text looks obviously wrong.

It is not. Two hundred thousand generated cases produce **zero**
disagreements with an epoch comparison. Both strings share a fixed-width
zero-padded ISO prefix, so lexical order is chronological order, and the
formats diverge only at the character after the seconds, which decides the
result only at exact second-equality where "not in the future" is correct
either way.

A **non-UTC offset** does break it: `2026-08-18T16:00:00-05:00` is an hour
ahead of `2026-08-18T20:00:00Z` and compares as expired. AWS returns UTC, so
the string test is correct by coincidence rather than by construction.

This script uses epoch seconds for robustness, not to fix a live bug. The
distinction matters, because "these formats differ, therefore this is broken"
is a plausible inference that survives review and is wrong.

## Verified here

```
verify-evidence.sh        bash -n clean
grc-gate.yml              parses; 16 steps; last step is the gate decision
actions                   5 of 5 SHA-pinned, all five resolve upstream
completeness logic        tested against a real tar bundle: intact passes,
                          removing plan.json fails as intended
retention comparison      fuzzed 200k cases; non-UTC failure characterized
```

Not verified: nothing has been signed. Cosign keyless needs an OIDC flow, so
the signing path only exercises inside GitHub Actions. Steps 1, 3 and 4 of
the script are tested; step 2 is not.

## Why the gate decision is the last step

`if: always()` runs the signing and upload steps even when Conftest or Trivy
failed, and the pass/fail decision moves to the end. A failed run is exactly
the run whose evidence you will want later, so aborting before capture is
backwards.

## The tamper tests

Do all four before trusting this. Each breaks one property and should be
caught by exactly one step:

1. Append a byte to the bundle. Step 1 fails.
2. Re-sign it with your own identity. Step 2 fails on certificate identity.
   **Under a `.*` identity regex this attack succeeds.**
3. Repackage without `plan.json` and re-sign with the workflow identity.
   Steps 1 and 2 pass; step 3 fails. Integrity and authenticity alone
   cannot detect this.
4. Let a GOVERNANCE 1-day retention lapse. Step 4 fails.
