# Lab 5.4 reference: GCP security services baseline

Guide: [`docs/05_04_gcp_security_services.md`](../../docs/05_04_gcp_security_services.md)

Four Org Policy constraints, Workload Identity Federation, and Data Access
audit logs. Seven resource blocks; 12 resources with the default
variables, because two of them use for_each.

```bash
# Phase 1: observe. Violations are logged; nothing is blocked.
terraform apply -var=gcp_project=YOUR_PROJECT \
  -var=github_org=YOUR_ORG -var=github_repo=YOUR_REPO

# Phase 2, after a week of watching the violations:
terraform apply -var=enforce_mode=enforce ...
```

## Audit mode first

`enforce_mode` drives `dry_run_spec` or `spec` through a `dynamic` block.
Dry run evaluates the constraint and logs violations **without rejecting
anything**, which is how you introduce a preventive control without breaking
a team that has never heard of you.

**Do not try to audit by omitting the rules block.** It is a natural guess and
it is dangerously wrong: a policy with no rules is not auditing, it is not in
effect at all. You would observe zero violations and conclude you were
compliant.

`dry_run_spec` is confirmed present in the `google` provider (checked against
the schema at 5.45.2, not from memory).

Query what dry run found:

```bash
gcloud logging read \
  'protoPayload.status.details.violations.type="ORG_POLICY_DRY_RUN"' \
  --project=YOUR_PROJECT --limit=50
```

## Two layers on the WIF trust, not one

`attribute_condition` on the **provider** decides who may exchange a token at
all. Without it, any repository on the public internet can present a token
and impersonate your service account.

`principalSet` in the **binding** decides who may impersonate this particular
service account.

Set the condition and use `principalSet://.../*` in the binding and you have
one layer. Set both and a mistake in either is survivable. For an apply
pipeline, tighten further to `attribute.ref/refs/heads/main`.

## Watch it deny something

Configuration proves intent; a refusal proves enforcement.

```bash
gcloud iam service-accounts keys create /tmp/k.json \
  --iam-account=cgep-grc-gate-sa@YOUR_PROJECT.iam.gserviceaccount.com
# expect: FAILED_PRECONDITION, constraint iam.disableServiceAccountKeyCreation
```

Capture that transcript. It is better evidence than any configuration dump,
because the action **did not happen**. No finding three hours later, no
remediation ticket. That is the strongest layer of defence in depth, and the
one that will page you at 2am if you enable it carelessly, which is why the
lab rolls out in dry run first.

## What is deliberately not built

**VPC Service Controls (SC-7).** The genuine data-exfiltration boundary on
GCP: a service perimeter stops a principal with valid credentials copying
data to a project outside it, which IAM alone cannot do. It needs org-level
rights and careful planning, and misconfiguring one locks you out of your own
project. Name it as a gap with a remediation plan rather than pretending.

**`gcp.restrictNonCmekServices`.** The organizational form of what Lab 2.4's
module does per-bucket, same relationship as `publicAccessPrevention` here.

## SC-8 is inherited

There is no GCP equivalent of the `aws:SecureTransport` deny, because the
Google APIs are TLS-only. The control is satisfied and you did not implement
it. Lab 6.1 records that as `inherited` with GCP as the responsible party.

## Verified here

```
terraform fmt -check    clean
terraform validate      clean; 7 blocks, 12 resources at defaults
dry_run_spec            confirmed in the provider schema at google 5.45.2
```

Not verified: never applied. Org Policy propagation takes 5 to 10 minutes,
so a test immediately after apply may briefly succeed; that is propagation,
not a broken policy.
