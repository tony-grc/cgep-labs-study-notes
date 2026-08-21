# Lab 3.3 reference: writing compliance policies in Rego (GCP)

Guide: [`docs/03_03_writing_compliance_policies_rego.md`](../../docs/03_03_writing_compliance_policies_rego.md)

```
policies/          5 policies, one per control
policies/tests/    passing and failing fixtures for each
scripts/           mutation-test.sh
terraform/         mixed-compliance fixture (plan-only, never applied)
```

| Control | File | Enforces |
|---|---|---|
| SC-28 | `sc28_encryption.rego` | Every bucket has a CMEK `encryption` block |
| AC-3 | `ac3_no_public.rego` | Uniform access + prevention enforced; no 22/3389 to `0.0.0.0/0` |
| CM-6 | `cm6_required_tags.rego` | Four required labels |
| AU-3 | `au3_access_logging.rego` | Every bucket logs to a named target |
| AU-9 | `au9_log_immutability.rego` | The logging target is itself versioned |

```bash
opa test -v policies/               # 17/17
bash scripts/mutation-test.sh       # all 5 killed
opa inspect --annotations --format json policies/   # control IDs for Lab 6.1
```

## What the mutation test caught here

`cm6_required_tags.rego` **survived** the first mutation run, meaning no test
constrained its logic. The cause is worth understanding, because it is a
Rego-specific trap.

`labelable_type` is written as three alternative definitions:

```rego
labelable_type(t) if t == "google_storage_bucket"
labelable_type(t) if t == "google_compute_instance"
labelable_type(t) if t == "google_compute_disk"
```

Rego OR-s alternative definitions. Inverting all three `==` to `!=` leaves
`labelable_type("google_storage_bucket")` **still true**, because a bucket is
not an instance and not a disk. The mutation changed nothing any test could
observe.

The fix was not a better mutation, it was the missing test:
`test_non_labelable_type_ignored` asserts that a `google_compute_network`
with no labels produces zero denials. Invert `labelable_type` now and that
test fails, so the mutation is killed.

The lesson is the one the lab argues in general form: a passing suite proves
the policy answered correctly on inputs you thought of. Only a mutation that
dies proves a test is actually holding the rule in place.
