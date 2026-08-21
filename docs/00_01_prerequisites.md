# Lab 0.1: Prerequisites and Credential Setup

Do this once, before Lab 2.2. It takes about 90 minutes and it is the difference between labs that work and an afternoon of authentication errors.

Three things happen here: you build a sandbox where mistakes are cheap, you set up credentials that are short-lived by default, and you put a spending cap on it before you deploy anything that bills.

## Read this first: these labs cost money

This curriculum uses customer-managed KMS keys, which is where most of the cost comes from and is the point. Rough numbers for a single learner:

| If you | Expect |
|---|---|
| Destroy each lab the same day | Under **$5** for the whole curriculum |
| Leave the state backend up for a month (recommended) | **$1/month** for its CMK |
| Leave Security Hub + Config + a few keys running a month | **$10 to $15** |
| Forget to destroy Lab 5.2 for a quarter | **$30 to $45** |

Two specific traps:

- **KMS keys bill $1/month each, whether used or not**, and they keep billing through the 7-to-30 day deletion window after you schedule deletion. You cannot delete one immediately. Each lab tells you which keys it creates.
- **CloudTrail data events** bill per event. Lab 5.2 scopes them to one bucket for this reason. Point them at a busy bucket and the number changes character.

Set the budget alarm in Step 5 before you apply anything. It is not optional, and it is the only step here that has ever saved anyone real money.

## Learning objectives

- Stand up an AWS sandbox account isolated from anything you care about.
- Authenticate with short-lived credentials instead of long-lived access keys, and explain why that distinction is a control.
- Stand up a GCP project with the right APIs and both authentication modes.
- Install and verify the full toolchain.
- Cap your own spending before you can hurt yourself.

## Part 1: The AWS sandbox

### Step 1 Use a separate account

Not your production account. Not the account with your domain in it. A separate AWS account, because every lab ends with `terraform destroy` and the blast radius of a mistake should be a sandbox.

Two ways to get one:

| Approach | Do this if |
|---|---|
| **New member account in an Organization** (recommended) | You have or can create an AWS Organization. Gives you a clean account with consolidated billing and the option to attach an SCP later. |
| **A brand new standalone account** | You have no Organization and do not want one. Works fine. You manage its billing separately. |

Creating a member account in an existing Organization:

```bash
aws organizations create-account \
  --email you+cgep-lab@example.com \
  --account-name "CGE-P Lab Sandbox" \
  --profile YOUR_MGMT_PROFILE

# Poll until State is SUCCEEDED, then note the AccountId
aws organizations list-create-account-status \
  --states SUCCEEDED --profile YOUR_MGMT_PROFILE
```

The `you+cgep-lab@example.com` form matters: AWS requires a unique email per account, and most mail providers deliver plus-addressed mail to the same inbox.

> **A caution about Organizations.** A member account created this way has an `OrganizationAccountAccessRole` your management account can assume, and no root password until you reset it. That is convenient and it is also why Lab 5.2 may find Config blocked by a service control policy. Both are normal.

### Step 2 Harden the root user

Do this before anything else, in the console, signed in as root:

1. **Enable MFA on the root user.** A hardware key or an authenticator app.
2. **Delete any root access keys.** There should be none. If there are, delete them; nothing should ever use root programmatically.
3. **Set a strong unique password** in your password manager.
4. Then sign out of root and do not use it again. Everything below uses a role.

That is IA-2(1), AC-6(5), and IA-5 in three minutes, and it is the first thing any assessor checks.

### Step 3 Create a non-root IAM user

Do this before you touch credentials, because the credential step will
otherwise hand you root and not warn you.

In the console: **IAM → Users → Create user**.

- Name it `cgep-lab`.
- Tick **"Provide user access to the AWS Management Console"**.
- Set a password. Untick the force-reset box if you would rather not.
- Permissions: **Attach policies directly** → `AdministratorAccess`. This is a
  sandbox; scoping it properly is a week of policy authoring and teaches you
  nothing this curriculum is about.

Then **Security credentials → Assign MFA device** on that user. If you put a
hardware key on root in Step 2, register the same one here. A single key
enrols against multiple identities, and AWS allows eight devices per user.

**Do not create an access key.** A console password is all you need. Step 4
turns the resulting console session into short-lived credentials.

Now sign out of root and sign back in as `cgep-lab` at
`https://<ACCOUNT_ID>.signin.aws.amazon.com/console`.

### Step 4 Credentials: three ways, ranked

| | What it is | Secret on disk | Verdict |
|---|---|---|---|
| **`aws login`** | Converts your existing console session into temporary credentials that auto-refresh | None | **Use this** |
| **IAM Identity Center** | Federated sign-in with short-lived session credentials | None | Right for org-managed accounts, more setup |
| **IAM user access key** | A permanent `AKIA…` key and secret | Yes, forever | Last resort |

The third option is the credential type Labs 4.3 and 5.4 exist to eliminate.
Creating one to work through a curriculum about credential hygiene is a
choice you will have to defend to yourself.

#### The recommended path

```bash
aws login
```

It prompts for a region (`us-east-1`), opens a browser, and asks which
console session to use.

> **Read the session it offers.** `aws login` reuses whatever console session
> you are signed into, and it will happily offer you **root** without
> flagging that as dangerous. Root cannot be constrained by any IAM policy
> and cannot be scoped down afterwards. If the browser shows `root`, click
> **"Sign into new session"** and sign in as the `cgep-lab` user from Step 3.

Then confirm which identity you actually got:

```bash
aws sts get-caller-identity
```

You want an `Arn` ending in `:user/cgep-lab`. **If it ends in `:root`, stop
and redo the sign-in before applying anything.** Half of what this
curriculum builds is meaningless under root: Lab 4.3's OIDC role is scoped
so CI can plan but not apply, Lab 2.5's vault denies `s3:DeleteBucket` to
everyone except the account root, and Lab 2.2 grants the account root key
administration as a safety net. Run everything as root and all three become
decorative.

`aws login` writes no `~/.aws/credentials` file. It stores a session
reference and refreshes automatically while the refresh token is valid. When
it lapses, run `aws login` again.

#### The step everyone misses

**Terraform cannot read what `aws login` writes.** Nor what Identity Center
writes. Both store a session reference; the provider's Go SDK wants
materialized credentials. It will tell you this in the least helpful way
available:

```
Error: No valid credential sources found
Error: failed to refresh cached credentials, no EC2 IMDS role found,
       operation error ec2imds: GetMetadata, request canceled,
       context deadline exceeded
```

Nothing is wrong with EC2. That is simply where the credential chain gave
up. The bridge is a profile that resolves credentials by shelling out to the
AWS CLI. Add this to `~/.aws/config`:

```ini
[profile cgep]
region = us-east-1
credential_process = aws configure export-credentials --profile default --format process
```

Then, once per terminal:

```bash
export AWS_PROFILE=cgep
```

That is the whole setup. `credential_process` is part of the AWS SDK
contract, not a Terraform feature, so every tool in this course honours it.

One consequence to learn now rather than mid-lab: **re-login with
`aws login --profile default`.** With `AWS_PROFILE=cgep` exported, a bare
`aws login` targets `cgep` and the CLI stops you:

```
An error occurred (Configuration): Profile 'cgep' is already configured
with Credential Process credentials.
```

That is correct behaviour, not a broken profile. `aws login` writes
credentials into a profile, and it will not overwrite one that resolves them
through a process. The session lives in `default`, so that is what you refresh.
`cgep` reads through to it and needs no maintenance.

**Why a profile and not an environment variable.** The obvious-looking
alternative is `eval "$(aws configure export-credentials --format env)"`,
which copies the current credentials into the shell. It works for about
fifteen minutes and then becomes the problem. Those variables are a
*snapshot*: nothing updates them when the session lapses, and environment
variables outrank profiles in the credential chain, so a shell holding an
expired snapshot cannot be repaired by running `aws login` again. You get
`ExpiredToken` from a terminal where `aws login` just reported success, which
is a genuinely confusing place to be.

`credential_process` has no snapshot. Terraform re-runs the command whenever
it needs credentials, so refreshing the session with `aws login` is picked up
by the next Terraform command automatically. Nothing to re-export, nothing to
remember.

The rule generalizes: any credential source that is not a static key file
needs this bridge, which is every source you should be using.

> **If you already ran the `eval` line** in a terminal, that shell still has
> the snapshot and will keep failing. Clear it before setting the profile:
>
> ```bash
> unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
> export AWS_PROFILE=cgep
> ```

#### If you must use an access key

Only when Identity Center is unavailable and `aws login` is not an option.

```bash
aws configure --profile cgep-lab   # paste key and secret, region us-east-1
chmod 600 ~/.aws/credentials
```

Understand what you just made: a long-lived secret, in plaintext, valid
until you delete it. Rotate or remove it when the course ends:

```bash
aws iam list-access-keys --user-name cgep-lab
aws iam delete-access-key --user-name cgep-lab --access-key-id AKIA...
```

**Never commit it.** Install a guard before you can:

```bash
pip install detect-secrets && detect-secrets scan > .secrets.baseline
```

### Step 5 The budget alarm (do not skip)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

cat > /tmp/budget.json <<EOF
{
  "BudgetName": "cgep-lab-monthly",
  "BudgetLimit": { "Amount": "25", "Unit": "USD" },
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST"
}
EOF

cat > /tmp/notifications.json <<'EOF'
[
  {
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 50,
      "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [
      { "SubscriptionType": "EMAIL", "Address": "you@example.com" }
    ]
  },
  {
    "Notification": {
      "NotificationType": "FORECASTED",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 100,
      "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [
      { "SubscriptionType": "EMAIL", "Address": "you@example.com" }
    ]
  }
]
EOF

aws budgets create-budget \
  --account-id "$ACCOUNT_ID" \
  --budget file:///tmp/budget.json \
  --notifications-with-subscribers file:///tmp/notifications.json
```

Two alerts: one when you have actually spent half of $25, one when the forecast says you will exceed it. The forecast alert is the useful one, because it fires while you can still act.

Budgets are a billing API and may need to run against your management account in an Organization. If you get `AccessDeniedException`, set it there instead, scoped to the sandbox account.

### Step 6 Pick a region and stay in it

Every lab uses `us-east-1`. Use the same one everywhere: the state backend in Lab 2.2 and every workspace that reads it must agree, and a region mismatch produces `NoSuchBucket` errors that look like permissions errors.

If you use a different region, change it in Lab 2.2 first and carry it through consistently.

## Part 2: The GCP project

Labs 2.4, 3.3, and 5.4 are GCP. You can complete the AWS track and the capstone without them, but the cross-cloud lesson is most of the point of the curriculum.

### Step 7 Create the project and attach billing

```bash
gcloud auth login

PROJECT_ID="cgep-lab-$(date +%s | tail -c 6)"   # must be globally unique
gcloud projects create "$PROJECT_ID" --name="CGE-P Lab"

gcloud billing accounts list
gcloud billing projects link "$PROJECT_ID" --billing-account=XXXXXX-XXXXXX-XXXXXX
gcloud config set project "$PROJECT_ID"
```

Billing must be attached or API calls fail with errors that do not mention billing.

### Step 8 Enable the APIs

```bash
gcloud services enable \
  cloudkms.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com \
  orgpolicy.googleapis.com \
  storage.googleapis.com \
  logging.googleapis.com \
  sts.googleapis.com
```

`orgpolicy` and `sts` are needed for Lab 5.4 and are easy to forget. Enabling takes a minute or two to propagate.

### Step 9 The two authentications, which are not the same thing

This is the single most common GCP confusion, and it costs people an hour each time.

```bash
gcloud auth login                      # authenticates the gcloud CLI as you
gcloud auth application-default login  # writes Application Default Credentials
```

**You need both.** `gcloud auth login` authenticates the `gcloud` command. Terraform's google provider does not use that; it uses Application Default Credentials, a separate credential file written by the second command. Run only the first and every `gcloud` command works while every `terraform apply` fails with a confusing authentication error.

Verify both:

```bash
gcloud auth list                                   # your account, active
gcloud auth application-default print-access-token | head -c 20; echo "..."
```

ADC tokens expire and **Terraform will not refresh them**. When you see `reauth related error (invalid_rapt)`, run `gcloud auth application-default login` again. This is normal and will happen several times during the course.

> **Authenticating from a container.** Both commands try to open a browser, and
> a container does not have one. Add `--no-launch-browser` to each:
>
> ```bash
> gcloud auth login --no-launch-browser
> gcloud auth application-default login --no-launch-browser
> ```
>
> Each prints a URL to open on your own machine and waits for the code it gives
> you back. This is the GCP counterpart of `aws login --remote`, and you need it
> for both commands, not just the first.

### Step 10 Roles

If you created the project you are already Owner, which is sufficient. If someone else grants you access, you need:

```bash
for ROLE in roles/storage.admin roles/cloudkms.admin \
            roles/orgpolicy.policyAdmin roles/iam.workloadIdentityPoolAdmin \
            roles/logging.admin roles/iam.serviceAccountAdmin; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="user:you@example.com" --role="$ROLE"
done
```

`roles/orgpolicy.policyAdmin` and `roles/iam.workloadIdentityPoolAdmin` are **not** included in Owner in all configurations, and Lab 5.4 fails without them with a `PERMISSION_DENIED` that does not say which role is missing.

### Step 11 A GCP budget alert

```bash
gcloud billing budgets create \
  --billing-account=XXXXXX-XXXXXX-XXXXXX \
  --display-name="cgep-lab-monthly" \
  --budget-amount=25USD \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0,basis=forecasted-spend
```

Needs `roles/billing.admin` on the billing account. If you do not have it, set the budget in the console; do not skip it. Lab 5.4's Data Access logs are the line item that can surprise you, at $0.50/GB ingested.

## Part 3: The toolchain

Ten tools, each with its own installer. There are two ways to get them, and
the first one is strongly preferred unless you specifically want the practice.

### Step 12a The container (recommended)

The repository ships a devcontainer with the whole toolchain pinned to the
versions this course was written against. It builds natively on both `amd64`
and `arm64`, which matters: every Mac sold since 2020 is `arm64`, and the
manual instructions below are `amd64` only.

Two ways to run it, from the same definition:

- **In your browser.** On the repository page, press `.` or use
  **Code > Codespaces > Create codespace**. Nothing to install, and GitHub's
  free tier covers far more than this course needs. This is the answer if you
  are on Windows, on a locked-down laptop, or simply do not want ten new
  binaries on your machine.
- **Locally.** Install Docker and VS Code with the Dev Containers extension,
  open the repository, and choose **Reopen in Container**.

**The first start takes a few minutes.** It is building the image and pulling
roughly 3 GB of tooling. A long quiet pause is the build working, not a hang;
later starts reuse the image and open in seconds.

Either way you land in a shell with `terraform`, `aws`, `gcloud`, `opa`,
`conftest`, `trivy`, `cosign`, `trestle`, `jq` and `gh` already present and on
your `PATH`. Skip to Step 13 and verify. `AWS_PROFILE` is already set to
`cgep`; you still create the profile itself in Step 4 and still run
`aws login`, because the container deliberately contains no credentials.

> **Logging in from a container.** `aws login` opens a browser, and a
> container does not have one. Use `aws login --remote --profile default`,
> which prints a URL to open on your own machine and prompts for the code it
> shows you. Everything else behaves identically. Your `~/.aws` and gcloud
> config live on named volumes, so rebuilding the container does not cost you
> another login.

### Step 12b Installing by hand

Do this if you want to know exactly what lands on your machine, which is a
reasonable thing to want in a security course.

**This path is Ubuntu 24.04 on `amd64` only.** Every download below names
`linux_amd64` explicitly. On an Apple Silicon Mac or an ARM machine each one
is a different filename, and on Windows the shell itself differs; use the
container, or WSL2 with Ubuntu, rather than translating fourteen URLs by hand.

`~/.local/bin` must be on your `PATH`; every install below is sudo-free.

```bash
mkdir -p ~/.local/bin
case ":$PATH:" in *":$HOME/.local/bin:"*) : ;; *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && export PATH="$HOME/.local/bin:$PATH" ;; esac
```

**Terraform** (check the current version at `https://checkpoint-api.hashicorp.com/v1/check/terraform`):

```bash
TF_VERSION=1.10.5
cd /tmp
curl -fsSLO "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip"
curl -fsSLO "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_SHA256SUMS"
sha256sum --ignore-missing -c "terraform_${TF_VERSION}_SHA256SUMS"
unzip -o "terraform_${TF_VERSION}_linux_amd64.zip" terraform -d ~/.local/bin
```

Note `unzip ... terraform -d`, naming the one file you want. Unzipping the whole archive drops a `LICENSE.txt` into your bin directory.

Verify the signature too. You are taking a course about supply chain evidence:

```bash
curl -fsSL https://www.hashicorp.com/.well-known/pgp-key.txt | gpg --import
curl -fsSLO "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_SHA256SUMS.sig"
gpg --verify "terraform_${TF_VERSION}_SHA256SUMS.sig" "terraform_${TF_VERSION}_SHA256SUMS"
```

`Good signature from "HashiCorp Security..."` is what you want. The "key is not certified" warning is expected and only means you have not assigned local trust.

**AWS CLI v2.** Do not install this from `apt`; the packaged `awscli` is v1, and `aws configure export-credentials` is v2-only.

```bash
cd /tmp
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip -q awscliv2.zip
./aws/install --install-dir ~/.local/aws-cli --bin-dir ~/.local/bin
```

Add `--update` to that last command to upgrade later.

**gcloud.** The widely-cited `curl https://sdk.cloud.google.com | bash` is interactive and stops to ask questions. Use the tarball with explicit flags instead:

```bash
cd /tmp
curl -fsSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz -o gcloud.tar.gz
tar -xzf gcloud.tar.gz -C ~/
~/google-cloud-sdk/install.sh --quiet --path-update true --usage-reporting false --command-completion true
exec -l $SHELL
```

About 92MB. `--path-update true` appends to your shell profile, so start a new shell before `gcloud` resolves.

**OPA, Conftest, Trivy, Cosign, gh.** These versions were current as of this writing. Check for newer with the loop underneath before you install.

```bash
cd /tmp
curl -fsSL https://github.com/open-policy-agent/opa/releases/download/v1.19.1/opa_linux_amd64_static -o ~/.local/bin/opa
chmod +x ~/.local/bin/opa

curl -fsSL https://github.com/open-policy-agent/conftest/releases/download/v0.69.0/conftest_0.69.0_Linux_x86_64.tar.gz | tar -xz -C ~/.local/bin conftest

curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz | tar -xz -C ~/.local/bin trivy

curl -fsSL https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 -o ~/.local/bin/cosign
chmod +x ~/.local/bin/cosign

curl -fsSL https://github.com/cli/cli/releases/download/v2.98.0/gh_2.98.0_linux_amd64.tar.gz | tar -xz -C ~/.local/bin --strip-components=2 gh_2.98.0_linux_amd64/bin/gh
```

```bash
for r in open-policy-agent/opa open-policy-agent/conftest aquasecurity/trivy sigstore/cosign cli/cli; do
  printf '%-30s %s\n' "$r" "$(curl -sS "https://api.github.com/repos/$r/releases/latest" | jq -r .tag_name)"
done
```

Each of those tar extractions names the single binary to pull out. Extracting the whole archive scatters `LICENSE` and `README` files into your bin directory.

> **OPA 1.x.** OPA 1.0 made the `rego.v1` syntax the default. Every policy in this curriculum declares `import rego.v1` explicitly, which is valid in 1.x and required by 0.x, so the library runs on both. Inherited v0-syntax policies need `--v0-compatible` or a migration.

> **Cosign 3.x.** Cosign went 2.x to 3.x. The flags Lab 4.4 depends on (`sign-blob --bundle`, and `verify-blob --bundle --certificate-identity-regexp --certificate-oidc-issuer`) are all present in 3.1.3, so the lab is unaffected. Confirm with `cosign verify-blob --help` if you install a later major version.

**trestle.** Ubuntu 24.04 and other recent distributions enforce PEP 668, so plain `pip install --user` fails with `error: externally-managed-environment`. Use `pipx`:

```bash
sudo apt install -y pipx jq git unzip curl   # most are present already
pipx install compliance-trestle
```

`pipx` gives trestle its own virtualenv and links the binary into `~/.local/bin`. If you would rather not use pipx: `python3 -m venv ~/.venvs/trestle && ~/.venvs/trestle/bin/pip install compliance-trestle`, then link the binary onto your `PATH`.

> **Check which OSCAL version your trestle targets.** It decides what you write in Lab 6.1.
>
> ```bash
> trestle version
> # Trestle version v5.0.0 based on OSCAL version 1.2.1
> ```
>
> Your component definition, your profile, and the NIST catalog you import must all agree on that number. Lab 6.1 uses **1.2.1** to match trestle 5.x. If your trestle reports something different, use what it reports; a mismatch is the most common `trestle validate` failure.

`gh`, the GitHub CLI, per [cli.github.com](https://cli.github.com), then `gh auth login`.

### Step 13 Verify the whole toolchain

```bash
#!/usr/bin/env bash
# scripts/check-prereqs.sh
FAIL=0
check() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '  %-12s %s\n' "$1" "$($2 2>&1 | head -1)"
  else
    printf '  %-12s MISSING\n' "$1"; FAIL=1
  fi
}

echo "=== toolchain ==="
check terraform "terraform version"
check aws       "aws --version"
check gcloud    "gcloud version"
check opa       "opa version"
check conftest  "conftest --version"
check trivy     "trivy --version"
check cosign    "cosign version"
check trestle   "trestle version"
check jq        "jq --version"
check gh        "gh --version"

echo "=== AWS ==="
aws sts get-caller-identity --profile "${AWS_PROFILE:-cgep-lab}" 2>&1 | head -4 || FAIL=1

echo "=== GCP ==="
gcloud config get-value project 2>&1 | head -1
gcloud auth application-default print-access-token >/dev/null 2>&1 \
  && echo "  ADC: OK" || { echo "  ADC: MISSING (run: gcloud auth application-default login)"; FAIL=1; }

echo
[[ $FAIL -eq 0 ]] && echo "PREREQS OK" || { echo "PREREQS INCOMPLETE"; exit 1; }
```

```bash
chmod +x scripts/check-prereqs.sh && bash scripts/check-prereqs.sh
```

`PREREQS OK` means you are ready for Lab 2.2.

## Part 4: Habits that will save you

**Set `AWS_PROFILE` at the start of every session.** Terraform cannot read what
`aws login` or Identity Center store, so the `credential_process` profile from
Part 1 is a standing requirement and not an occasional fix. Put it in your
shell profile so every new terminal starts correct:

```bash
echo 'export AWS_PROFILE=cgep' >> ~/.bashrc
```

The `[profile cgep]` entry points at `--profile default`, because that is where
`aws login` writes. If you configured a named login profile instead, point it
there.

**Never export credentials into the shell.** The one habit that will cost you
an afternoon is `eval "$(aws configure export-credentials --format env)"`.
Environment variables outrank profiles, so the moment that snapshot expires
your shell is stuck: `aws login` succeeds and Terraform keeps failing, because
the provider never looks past the dead variables. If a shell is already in that
state, `unset` the four variables rather than trying to refresh them.

**Check which identity you are actually using**, especially after a re-login:

```bash
aws sts get-caller-identity --query Arn --output text
```

An `Arn` ending in `:root` means stop and re-authenticate as your IAM user.

**Never commit credentials.** Every lab's `.gitignore` excludes `*.tfvars` and `*.tfstate` for this reason. Add a scanner before you need one.

**Destroy what you finish**, except the Lab 2.2 state backend, which everything else depends on. Destroy that last, after Lab 6.1, and only after every other workspace is gone. Deleting the state bucket while resources still exist strands them: no state means Terraform can no longer destroy them, and you are deleting things by hand in the console.

**Check your bill weekly:**

```bash
aws ce get-cost-and-usage \
  --time-period Start=$(date -u -d '30 days ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) \
  --granularity MONTHLY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[].Groups[?Metrics.UnblendedCost.Amount>`0.01`].[Keys[0],Metrics.UnblendedCost.Amount]' \
  --output table
```

Cost Explorer must be enabled once in the console before this API returns data, and it can take 24 hours to populate.

## Troubleshooting

- **`Credentials were refreshed, but the refreshed credentials are still expired`.** Two different causes. If it appears seconds after `aws login`, it is a transient cache race: `aws login` returns your prompt as soon as it writes the profile, while the CLI's own cache still holds the previous entry. Re-run the command. If it persists, your shell is holding an expired snapshot from `export-credentials --format env`, which outranks the profile: `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION` and re-run.
- **`No valid credential sources found`** plus **`no EC2 IMDS role found`** from Terraform, while `aws sts get-caller-identity` works fine. Nothing is wrong with EC2; that is just where the credential chain gave up. Neither `aws login` nor Identity Center writes credentials the provider can read. Set up the `credential_process` profile from Part 1 and `export AWS_PROFILE=cgep`. **This is the most common error in the entire course.**
- **`failed to find SSO session section`** from Terraform. Same cause, different wording, same fix.
- **`ExpiredToken`** mid-lab. Your session lapsed. Re-run `aws login` (or `aws sso login` on the Identity Center path), then re-export. Short-lived credentials expiring is the feature, not a fault.
- **`aws: command not found`** after installing. `~/.local/bin` is not on `PATH`, or you need a new shell.
- **`aws configure export-credentials: Invalid choice`.** You have AWS CLI v1. Install v2; do not use `apt`.
- **`reauth related error (invalid_rapt)`** from Terraform on GCP. Re-run `gcloud auth application-default login`.
- **`PERMISSION_DENIED` on Org Policy or WIF** despite being Owner. Owner does not always include `roles/orgpolicy.policyAdmin` or `roles/iam.workloadIdentityPoolAdmin`. Grant them explicitly.
- **`billing account not found`.** The project has no billing attached. `gcloud billing projects link`.
- **Budget creation returns `AccessDeniedException`.** Budgets are a billing API. In an Organization, create it from the management account.

## Teardown, when you finish the course

In this order:

1. Destroy every lab workspace except the Lab 2.2 bootstrap.
2. Destroy the Lab 2.2 bootstrap last.
3. Check for orphans: `aws resourcegroupstaggingapi get-resources --tag-filters Key=ComplianceScope,Values=cge-p-lab`. This is what the `ComplianceScope` tag was for all along, and finding your own strays with it is a good final exercise.
4. Schedule KMS key deletion for anything left. Keys bill through their waiting period.
5. GCP: `gcloud projects delete "$PROJECT_ID"`. Deleting the project is the cleanest teardown, and it is 30-day recoverable.
6. If you created a dedicated AWS member account, close it. AWS retains it in `SUSPENDED` for 90 days.
7. Delete any IAM user access keys you created in Path B.

Leave the budget alarm in place until the account is closed. It is the last thing that will tell you about something you forgot.

## Revision history

**v2** (current)

- New document. Sandbox setup, credentials, toolchain and budget alarms were previously scattered across each lab's prerequisites.
- `aws login` is the recommended credential path, ahead of IAM Identity Center, with access keys demoted to last resort.
- Creating a non-root IAM user comes before the credential step, because `aws login` will otherwise offer the root session without flagging it.
- Terraform is bridged to `aws login` with a `credential_process` profile rather than by exporting credentials into the shell. The profile resolves credentials per command, so a re-login is picked up automatically; an exported snapshot goes stale after about fifteen minutes and then outranks every attempt to fix it.

**v1**

Did not exist. Prerequisites were listed per lab.
