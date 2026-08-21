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

**[Lab 0.1 Step 13a](../docs/00_01_prerequisites.md) is the walkthrough**, with
the exact menu paths, what each prompt should say, and what to do when one does
not appear. Two routes: a Codespace in the browser with nothing installed, or
Docker plus VS Code's Dev Containers extension locally.

The short version for anyone who has done this before: open the repository
folder on its own, not a parent directory and not a multi-root workspace, then
**Reopen in Container**. First start takes a few minutes while it builds.

There are no images to pull. The repository ships the Dockerfile and your
machine or your Codespace builds from it; nothing is published to a registry.

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
