# Lab 2.4 reference: Terraform modules for compliance (GCP)

Guide: [`docs/02_04_terraform_modules_for_compliance.md`](../../docs/02_04_terraform_modules_for_compliance.md)

```
modules/compliant-gcs-bucket/   the module: 6 resources, 9 controls
consumers/dev/                  environment=dev,  retention 30
consumers/prod/                 environment=prod, retention 365
consumers/negative-test/        environment=prod, retention 30  <- must FAIL
```

```bash
cd consumers/dev
terraform init
terraform plan -out=tfplan -var=gcp_project=your-gcp-project
terraform apply tfplan
```

## The module has no provider block

That is the point of the lab. Providers are configured by the root module
and inherited. A module carrying its own `provider` cannot be reused across
two regions or two projects, which is exactly the mistake Lab 2.3 makes on
purpose so you can feel the difference.

## Two negative tests, and a gotcha about how to run them

**`terraform validate` will NOT catch either of them.** Validate checks
syntax and references; variable validation runs at plan time. The
negative-test consumer passes `terraform validate` with exit 0 despite being
deliberately invalid, so do not "fix" it when CI goes green. Upstream CI runs
`fmt` and `validate`, which means CI cannot verify this lab's central
demonstration. Run the plan yourself.

**Test one: prod cannot have short retention.**

```bash
cd consumers/negative-test
terraform plan -var=gcp_project=example-project
```

```
Error: Invalid value for variable

  on main.tf line 29, in module "data_bucket":
  29:   retention_days     = 30
    ├────────────────
    │ var.environment is "prod"
    │ var.retention_days is 30

retention_days must be >= 365 when environment == "prod".

This was checked by the validation rule at
../../modules/compliant-gcs-bucket/variables.tf:54,3-13.
```

This fires **before any GCP API call**, so you can watch it work with no
credentials configured. You will see a provider-credentials error alongside
it; that is incidental noise, not the test. The compliance check happened at
plan time, before any resource existed, with a message specific enough that
a developer fixes it without filing a ticket. Preventive beats detective, and
it is cheaper.

**Test two: a consumer cannot suppress a compliance label.**

```bash
cd consumers/dev
echo 'merge({compliance_scope="not-in-scope", team="platform"}, {compliance_scope="cge-p-lab", managed_by="terraform"})' | terraform console
```

```
{
  "compliance_scope" = "cge-p-lab"
  "managed_by" = "terraform"
  "team" = "platform"
}
```

`local.effective_labels = merge(var.labels, local.required_labels)` puts the
required set **last**, and last wins. A consumer may add labels (`team`
survives) and cannot override the compliance ones (`compliance_scope` is
forced back). That asymmetry is the entire design, and it is enforced by
argument order rather than by documentation or code review.

## SC-8 is inherited, not implemented

On AWS you write a bucket policy denying `aws:SecureTransport = false`. On
GCP there is no equivalent resource, because the Cloud Storage API is
TLS-only. The control is satisfied and you did not implement it.

The attestation says so in the honest form:

```
transit_encryption = "inherited-gcp-tls-only"
```

Lab 6.1 maps that to an OSCAL `implementation-status` of `inherited` with
GCP named as the responsible party. Writing `implemented` there is the small
dishonesty that collapses when an assessor asks to see the code.

## Cleanup surprises

1. A **locked** retention policy makes the bucket undestroyable until every
   object ages out. With `retention_days = 365` that is a year. This is why
   `lock_retention_policy` defaults to `false` and says so loudly.
2. **KMS keys are never truly deleted.** Key versions enter a 30-day
   soft-delete; the keyring cannot be deleted at all. Free, but a
   `terraform destroy` reporting success has not removed them.
3. The **log bucket** may hold objects and refuse to destroy if it saw traffic.
