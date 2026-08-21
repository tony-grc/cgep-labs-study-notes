# Lab 3.4 reference: Conftest + Terraform (AWS)

Guide: [`docs/03_04_integrating_pac_with_terraform.md`](../../docs/03_04_integrating_pac_with_terraform.md)

Ten policies, six control IDs. The GCP rules from Lab 3.3 are carried
forward unchanged; the five `*_aws.rego` files are the AWS variants.

```
policies/            10 policies (5 GCP + 5 AWS)
policies/tests/      34 tests
scripts/             policy-gate.sh, mutation-test.sh
fixtures/            synthetic plan JSON so the gate runs without AWS creds
```

| Control | GCP | AWS |
|---|---|---|
| SC-8 | inherited (GCS is TLS-only) | `sc8_tls_required_aws.rego` |
| SC-28 | `sc28_encryption.rego` | `sc28_encryption_aws.rego` |
| AC-3 | `ac3_no_public.rego` | `ac3_no_public_aws.rego` |
| AU-3 | `au3_access_logging.rego` | (via AU-9 target check) |
| AU-9 | `au9_log_immutability.rego` | `au9_log_immutability_aws.rego` |
| CM-6 | `cm6_required_tags.rego` | `cm6_required_tags_aws.rego` |

```bash
opa test -v policies/                    # 34/34
bash scripts/mutation-test.sh policies   # all 10 killed
bash scripts/policy-gate.sh --plan fixtures/plan-compliant.json   # PASS
bash scripts/policy-gate.sh --plan fixtures/plan-degraded.json    # FAIL
```

## The three gate outcomes, all verified

`fixtures/plan-degraded.json` is the compliant fixture with three common
shortcuts taken: AES256 instead of a CMK, no bucket policy, log bucket
unversioned. The gate names all three:

```
[SC-8]  aws_s3_bucket.primary: no aws_s3_bucket_policy references this bucket
[SC-28] aws_s3_bucket.primary: encrypted with SSE-S3 (AES256), not a CMK
[AU-9]  aws_s3_bucket.log: used as an access-log target but has no versioning
exit=1
```

**The third outcome is the important one.** Point the gate at an empty
policy directory:

```
policy-gate: FAIL (no policy results produced; gate did not run)
exit=2
```

Zero failures out of zero tests is zero failures. Without that guard the
gate returns success when it loaded nothing, which is the same failure mode
the mutation test exists to catch, one layer up. Test this yourself before
trusting the gate; it is the difference between a control and a decoration.

## SC-8 is a two-tier rule, on purpose

A bucket policy is a JSON string built from bucket ARNs, which depend on the
`random_id` suffix, which does not exist at plan time. **The rendered policy
JSON is unknown**, so it cannot be parsed.

Tier 1 asserts a policy resource exists and references the bucket. That
always evaluates. Tier 2 parses the rendered JSON and checks for the
`aws:SecureTransport` deny, and only fires when the JSON happens to be known
(hardcoded names, or a re-plan against existing state).

Teach the limit explicitly. A student who believes tier 2 always runs will
trust a gate that is only doing tier 1. Post-apply verification and Security
Hub close the rest; policy-as-code is one layer of three.
