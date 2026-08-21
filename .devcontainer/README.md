# The CGE-P lab container

The whole toolchain, pinned, on any operating system.

## Why this exists

The manual install in Lab 0.1 is ten separate tools and is written for Ubuntu
on `amd64`. Every Mac sold since 2020 is `arm64`, where each of those download
URLs is a different filename, and on Windows the shell itself differs. The
container removes the question: it builds natively on both architectures from
one definition, so the toolchain is identical whether the student is on a Mac,
a Windows laptop, a Chromebook, or a Linux desktop.

## Running it

**In a browser.** Nothing to install: from the repository page,
**Code > Codespaces > Create codespace**.

**Locally.** Docker plus VS Code with the Dev Containers extension, then
**Reopen in Container**.

**Either way, the first start takes a few minutes.** It builds the image and
pulls roughly 3 GB of tooling; a long quiet pause is the build working, not a
hang. Subsequent starts reuse the image and are quick.

Your first command should be the verification block from Lab 0.1 Step 13. It
prints a line per tool and ends in `PREREQS OK`. Do that before touching a
cloud account, so a missing tool surfaces as a failed check rather than as a
half-applied Terraform run.

There are no images to pull: the repository ships the Dockerfile, and your
machine or your Codespace builds from it. Nothing is published to a registry.

## What is in it

| Tool | Version | Used by |
|---|---|---|
| terraform | 1.10.5 | 2.2 onward |
| aws | v2, current | every AWS lab |
| gcloud | current | 2.4, 5.4 |
| opa | 1.19.1 | 3.3 |
| conftest | 0.69.0 | 3.4 |
| trivy | 0.74.0 | 3.4, 4.3 |
| cosign | 3.1.3 | 4.4 |
| trestle | current | 6.1 |
| gh | 2.98.0 | 4.3, 4.4 |
| jq, git | distro | throughout |

Versions are pinned as build arguments in the `Dockerfile` and must stay in
step with `docs/00_01_prerequisites.md`. CI's `pin-freshness` job fails if a
pin here is absent from the guide, and warns when one falls behind upstream;
it does not change them for you.

## Credentials

**The image contains no credentials, and it should stay that way.** You create
the profile and log in yourself, exactly as Lab 0.1 describes.

`~/.aws` and `~/.config/gcloud` are named volumes, so a container rebuild does
not throw your session away.

One difference from a laptop: `aws login` wants to open a browser, and a
container does not have one. Use

```bash
aws login --remote --profile default
```

which prints a URL to open on your own machine and then asks for the code it
displays. The `--profile default` matters because `AWS_PROFILE` is preset to
`cgep`, and `aws login` refuses to write into a profile that resolves
credentials through `credential_process`.

## Cost

The container is free. **The labs are not.** They create real resources in
your own cloud account, roughly $5 for the whole curriculum if you destroy
the same day. Lab 0.1 sets a budget alarm before anything bills, and that step
is not optional.
