# Lab 6.1 reference: OSCAL

Guide: [`docs/06_01_introduction_to_oscal.md`](../../docs/06_01_introduction_to_oscal.md)

```
scripts/gen-oscal-requirements.py   policy catalog -> implemented-requirements
scripts/verify-oscal-graph.sh       proves the document is TRUE, not just valid
component-definitions/              compliant-s3-v2, 14 requirements
profiles/                           cge-p-minimum, 14 controls
evidence/policy-catalog.json        generated from Lab 3.3's Rego annotations
```

## The chain, authored once

```bash
# 1. Rego METADATA blocks -> a machine-readable catalog
opa inspect --annotations --format json ../lab-3-3/policies \
| jq '[.annotations[]? | select(.annotations.custom.control_id) | {
    control: .annotations.custom.control_id,
    severity: .annotations.custom.severity,
    title: .annotations.title,
    package: (.path | map(.value) | join(".")),
    remediation: (.annotations.custom.remediation // "see policy")
  }] | unique_by(.control) | sort_by(.control)' > evidence/policy-catalog.json

# 2. catalog -> OSCAL implemented-requirements
python3 scripts/gen-oscal-requirements.py evidence/policy-catalog.json \
  "s3://YOUR-VAULT/runs/RUN_ID/bundle.tar.gz?versionId=VERSION_ID"

# 3. validate the document, then verify the graph
trestle validate -f component-definitions/compliant-s3-v2/component-definition.json
bash scripts/verify-oscal-graph.sh \
  component-definitions/compliant-s3-v2/component-definition.json \
  profiles/cge-p-minimum/profile.json
```

**`.path` is a list of term objects, not strings.** `map(.value)` before
joining, or you get raw JSON in the package field. The guide had
`join(".")` alone and produced garbage; building this caught it.

## Two checks that answer different questions

`trestle validate` returns **VALID** for both documents here. It proves the
JSON matches the OSCAL schema.

`verify-oscal-graph.sh` on the *same* documents returns **OSCAL GRAPH
BROKEN**:

```
=== 1. Every evidence href resolves ===
  BROKEN  s3://cgep-lab-grc-evidence-vault-EXAMPLE/runs/RUN_ID/bundle.tar.gz?versionId=...
=== 2. Catalog source resolves and is version-pinned ===
  OK      .../oscal-content/v1.2.1/.../NIST_SP-800-53_rev5_catalog.json
=== 3. Every component control appears in the profile ===
  OK      all component controls are selected by the profile
=== 4. No placeholder UUIDs survived ===
  OK
```

**That failure is correct and this workspace ships in that state on purpose.**
The evidence URI is a placeholder until you point it at a real signed object
in your Lab 2.5 vault. A learner arrives here with OSCAL written and evidence
not yet wired, and the tool says so rather than letting a valid-looking
document imply a chain that does not exist.

Schema-valid and true are different properties. The capstone brief warns that
"an OSCAL file that doesn't actually describe your system is worse than no
OSCAL file"; this script is the mechanical answer to that warning.

## Honest implementation-status

Step 5 of the verifier prints every status so it cannot be skimmed past:

| Status | Count | Meaning |
|---|---|---|
| `implemented` | 13 | Code enforces it; point at the line |
| `partial` | 1 | `au-6`, see below |

`au-6` is `partial` deliberately. Lab 5.2 authored the Athena review queries;
nothing schedules them, and no named human reviews the output. Claiming
`implemented` there would be claiming a control on the strength of having
built the tooling for it.

For the GCP component, `sc-8` would be `inherited` with Google named as the
responsible party, because the Cloud Storage API is TLS-only and no module
code implements it.

## Version pinning

`oscal-version` is **1.2.1** and the catalog source is anchored to the
`v1.2.1` tag, matching `trestle version` (5.0.0, OSCAL 1.2.1). Check yours;
a mismatch between catalog, profile and component is the most common
`trestle validate` failure.

Check that whatever tag you pin actually exists: several plausible-looking
NIST tags return 404. Anchoring to `main` avoids that and is worse, because
NIST moves it and an assessor opening your component in a year gets a
different catalog than the one you assessed against.

## Verified here

```
opa inspect -> policy-catalog.json   5 controls extracted from Rego annotations
gen-oscal-requirements.py            14 requirements generated
trestle validate (component)         VALID
trestle validate (profile)           VALID
verify-oscal-graph.sh                runs; catches the placeholder evidence URI
catalog URL                          HTTP 200 at the pinned tag
profile coverage                     14 of 14 component controls selected
```
