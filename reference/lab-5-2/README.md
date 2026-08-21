# Lab 5.2 reference: AWS security services baseline

Guide: [`docs/05_02_aws_security_services.md`](../../docs/05_02_aws_security_services.md)

16 resources: CMK, trail bucket on the shared baseline, multi-region trail
with log-file validation, Security Hub with two standards, and the Glue +
Athena setup that makes AU-6 claimable.

```bash
terraform apply \
  -var=evidence_vault_arn=arn:aws:s3:::YOUR-VAULT \
  -var=enable_security_hub=true
```

## THIS ONE COSTS REAL MONEY

| Item | Cost |
|---|---|
| CloudTrail management events, first trail | free |
| CloudTrail **data** events | ~$0.10 per 100k events |
| Security Hub | ~$0.001 per check/month, ~300 checks for NIST |
| Trail CMK | **$1/month** |
| S3 storage | pennies, bounded by the lifecycle rule |

Destroy within an hour: under $2. Leave it a month: **$10 to $15**. Set
`enable_security_hub = false` to deploy the trail alone while you
experiment.

## Where AU-6 is actually earned

Collecting logs is AU-3 plus AU-11. **Reviewing** them is AU-6, and it needs
something that reads them. AU-6 is the control most often claimed on the
strength of collection alone.

`queries/` holds the three that constitute a review: who touched the evidence
vault, console logins without MFA, and denied actions clustered by principal.
The Athena table DDL is in the guide; it uses partition projection so you
never run `MSCK REPAIR TABLE`.

**Running them once by hand does not satisfy AU-6.** What satisfies it is:
the query exists, it runs on a defined cadence, a named human reviews the
output, and the review is recorded. Schedule it (an EventBridge weekly rule
is enough) or claim `partial` in your OSCAL and say what is missing. A
`partial` you can defend beats an `implemented` that collapses in one
question.

## Data events are scoped to one bucket on purpose

`evidence_vault_arn` drives a `dynamic` block, so passing `null` disables
data events entirely. Point them at a busy bucket and the bill changes
character.

The vault is the right place to spend it: management events show the bucket
being *created*, never that it was *read*. Without data events, an insider
can read the evidence, learn what the auditor will see, and leave no record.

## A mapping worth arguing about

Log-file validation is commonly mapped to **AU-10 (non-repudiation)**. The
digest file proves the log was not altered; it does not bind an actor to an
action. **AU-9(3)** and **SI-7** are the stronger claim. Both are arguable.
The point is not the answer, it is that an assessor who disagrees will ask
you why, and you should have one.

Run the check, do not just enable it:

```bash
aws cloudtrail validate-logs --trail-arn "$(terraform output -raw trail_arn)" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)"
```

Enabling validation and never validating is the same shape of mistake as
writing a policy and never testing it.

## Verified here

```
terraform fmt -check      clean
terraform validate        clean, 16 resources
```

`terraform validate` caught a real error while this was written: the Athena
workgroup's encryption block takes **`kms_key_arn`**, not `kms_key`. The
guide had the wrong name too, and it is fixed in both. That is the argument
for building the reference workspaces rather than trusting the prose.

Not verified: never applied. Config is deliberately omitted here; in
org-managed accounts an SCP blocks `config:PutConfigurationRecorder`, and the
resulting Security Hub CRITICAL finding is itself the evidence that the gap
exists.
