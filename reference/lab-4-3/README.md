# Lab 4.3 reference: GRC evidence pipeline

Guide: [`docs/04_03_grc_evidence_pipeline.md`](../../docs/04_03_grc_evidence_pipeline.md)

```
oidc/                       Terraform: OIDC provider + scoped plan role
.github/workflows/          grc-gate.yml, 13 steps
policies/  scripts/         carried from Lab 3.4, the gate calls them
```

## Stand up the trust

```bash
cd oidc
terraform init
terraform apply \
  -var=github_org=YOUR_ORG \
  -var=github_repo=YOUR_REPO \
  -var=state_bucket=cgep-lab-tfstate-XXXXXXXX \
  -var=state_kms_arn=arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID

gh variable set AWS_ROLE_ARN --body "$(terraform output -raw role_arn)"
```

If the OIDC provider already exists in the account, import rather than
creating a second:

```bash
terraform import aws_iam_openid_connect_provider.github \
  arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com
```

## The three strings in the trust policy

`https://token.actions.githubusercontent.com` is GitHub's OIDC **issuer**,
where it publishes the keys AWS uses to verify a token's signature.

`sts.amazonaws.com` is the **audience**. A token minted for a different
audience cannot be replayed against AWS.

`repo:OWNER/REPO:*` is the **subject**, a string GitHub builds and varies by
trigger: `:ref:refs/heads/main` on push, `:pull_request` on a PR,
`:environment:production` in a deployment environment. `StringLike` with the
trailing `*` covers every trigger for one repository.

**Never write `repo:*:*`.** That trusts every repository on GitHub.

## Why the role needs write on the state bucket

`ReadOnlyAccess` alone fails at `terraform init`, and the error names S3
rather than the role. A plan writes a lock object and refreshes state, so the
role needs `s3:PutObject` and `s3:DeleteObject` on the state bucket plus
`kms:GenerateDataKey` on the state key. That is `aws_iam_role_policy.state_access`.

For the capstone, keep this role read-only and create a **second** role for
apply, bound to `repo:OWNER/REPO:environment:production` behind a GitHub
environment protection rule. Splitting plan credentials from apply
credentials is the single highest-value paragraph most write-ups can contain.

## Verified here

```
terraform fmt -check          clean
terraform validate            clean
grc-gate.yml                  parses; 13 steps
actions                       4 of 4 SHA-pinned, all four SHAs resolve upstream
scripts                       bash -n clean
```

**The action SHAs were checked against the GitHub API**, not just eyeballed
for length. A plausible-looking wrong SHA fails at runtime, in CI, on
somebody else's pull request.

What is **not** verified: the workflow has never executed. Running it needs a
GitHub repository with the role ARN set and a real AWS account. Everything
above is static analysis.

## Branch protection is what makes this a control

Without it a red check is a suggestion anyone can merge past.

```bash
gh api -X PUT "repos/OWNER/REPO/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["grc-gate"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
JSON
```

`enforce_admins: true` is the part that turns a habit into CM-3, and it is
the first thing an assessor checks.

## The inert-gate test

Before trusting any of this, prove it can fail for the right reason: open a
PR that deletes `policies/` and confirm the run goes **red** with
`policy-gate: FAIL (no policy results produced; gate did not run)`. If it
goes green, the gate reports success while evaluating nothing. Close that PR
unmerged and keep the run URL; it is the best single piece of evidence in a
portfolio that the gate is real.
