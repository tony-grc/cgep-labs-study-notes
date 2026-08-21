# CGE-P lab study notes

Study notes from working through the **Certified GRC Engineer Practitioner
(CGE-P)** labs at the [GRC Engineering Club](https://grcengclub.com), written up
so they are useful to someone else.

**[`GRCEngClub/cgep-labs`](https://github.com/GRCEngClub/cgep-labs) is the
course. This is not.** It is one person's working through of it, shared in case
the reasoning is useful. Where the two differ, the official repo is the one that
counts.

## What's here

```
docs/           Twelve lab guides, a plain-English companion, and an index,
                as markdown and as PDFs, plus a 207-page bound edition.
reference/      Eleven companion workspaces (Terraform, Rego, shell, OSCAL).
.devcontainer/  The whole toolchain, pinned, for any operating system.
```

## Getting a toolchain

These labs need ten tools. Rather than installing them one at a time, open the
repository in a container.

From the repository page, **Code > Codespaces > Create codespace**. That is the
whole setup if you are on Windows, on a managed laptop, or simply would rather
not put ten new binaries on your machine. To run it on your own hardware
instead, install Docker and VS Code's Dev Containers extension, open the
repository, and choose **Reopen in Container**.

**The first start takes a few minutes and then never again.** It is building
the image and pulling roughly 3 GB of tooling. A long quiet pause is the build
working, not a hang. Later starts reuse the image and open in seconds.

When the shell appears, run the verification from
[Lab 0.1 Step 13](docs/00_01_prerequisites.md) as your first command. It prints
one line per tool and ends in `PREREQS OK`, which is how you know the
environment is sound before you spend money in a cloud account.

It builds natively on `amd64` and `arm64`, so it behaves the same on an Apple
Silicon Mac, a Windows laptop and a Linux desktop. See
[.devcontainer/README.md](.devcontainer/README.md). Lab 0.1 Step 12b still
documents the manual install for anyone who wants to see exactly what lands on
their machine; that path is Ubuntu `amd64` only.

The container holds **no credentials**. You still create your own cloud
accounts and log in yourself, which Lab 0.1 walks through.

**New reader? Start with [docs/00_00_plain_english_guide.md](docs/00_00_plain_english_guide.md).** The labs tell you what to type. That guide explains what it means, traces every magic string and constant to its source, and lays out which choices are genuinely yours to make. Nothing in this curriculum should be a value you paste because a guide said so.

Then [docs/README.md](docs/README.md) for the reading order.

The guides are complete and self-consistent. The companion `reference/` workspaces (Terraform, Rego, shell, OSCAL) are **not built yet**: the guides are written to be built from, and that is the next step.

## The governing rule

**Only cite a control the code actually implements.**

That was the rule I held myself to, and most of what follows came out of it.
Where a citation and the code did not line up, I either wrote the code or moved
the citation to the lab that earns it. Where a mapping is arguable, the lab says
so and defends it, because control mappings being arguments rather than lookups
is the most transferable idea in the course.

## What I changed, and why

Every one of these came from getting stuck, or from a citation I could not
defend when I looked at the code underneath it. Full reasoning in
[docs/README.md](docs/README.md).

| # | Change |
|---|---|
| 1 | **Added a state backend** (new Lab 2.2). With local state a fresh CI runner plans against nothing, so the capstone's "apply on merge to `main`" could not complete as I read it. |
| 2 | **Added TLS enforcement** (SC-8), via `aws:SecureTransport`. Encryption at rest was covered and encryption in transit was not, and the Chapter 4 `tfsec` gate flags the omission at HIGH. |
| 3 | **Versioned the log bucket.** The prose promised versioning on both buckets and the code versioned one, which left audit records less protected than the data. |
| 4 | **Moved AWS KMS ahead of the capstone.** CMEK is taught on GCP in 2.4, but the capstone grades you on AWS CMKs, so I met `aws_kms_key` for the first time in a graded deliverable. |
| 5 | **Dropped the AU-6 claim from Lab 2.3.** Shipping logs into a bucket is AU-3 and AU-11; AU-6 is review, so Lab 5.2 earns it with Athena queries instead. |
| 6 | **Stopped uploading raw Terraform state** into the Object Lock vault. State carries every sensitive attribute the provider stored, and immutable means a captured secret cannot be deleted. |
| 7 | **Constrained the cosign signer.** `--certificate-identity-regexp '.*'` accepts a signature from any repository on GitHub, so verification passes without proving anything. |
| 8 | **Compared retention as epoch seconds.** The string comparison works, but only because AWS returns UTC; a non-UTC offset breaks it in both directions. Robustness, not a live defect. |

6 and 7 are the two worth a second look: both pass every happy-path test, so nothing tells you they are there. 8 turned out on testing not to be a live defect at all, and is written up in Lab 4.4 as its own lesson about assuming.

## Two new practices the labs now teach

**Mutation testing.** A policy no test constrains cannot fail, and a gate full of those passes every check while enforcing nothing. Lab 3.3 breaks each policy on purpose and requires the tests to notice.

**Prove the control denies something.** Every lab that builds a control ends by watching it refuse an action, not by dumping its configuration. A control you have not seen fire is a control you are guessing about.

## Status

- [x] Twelve lab guides written
- [x] `reference/` workspaces built from the guides, 11 of 11, statically verified
- [ ] **Applied against a real cloud account: 2 of 11**
- [x] CI: 9 jobs (terraform, opa + mutation, trestle, shell, SHA-pinning, pin freshness, PDF freshness, pasteable-shell, container)
- [x] License: MIT, matching upstream

### Read this before you run anything

**Only Labs 2.2 and 2.3 have been applied against a real AWS account.** 2.2
created its backend and 2.3 created 18 resources, and every control in 2.3 was
watched denying something live: plain HTTP refused, an upload naming the wrong
key refused, the same upload with the right key accepted.

**The other nine workspaces have never touched a cloud.** They pass
`terraform validate`, `opa test`, `trestle validate` and the CI gates, and that
is genuinely not the same thing. Static checks cannot catch what an API rejects
at apply time: every lab I have applied so far has surfaced something the gates
did not. Expect the untested nine to do the same.

So treat this as reasoning to read, not code to trust. If you do apply any of
it, set the budget alarm in Lab 0.1 first, and destroy the same day.

## Licensing

MIT, matching [`GRCEngClub/cgep-labs`](https://github.com/GRCEngClub/cgep-labs)
upstream. This is a derivative work and retains their copyright notice
alongside its own, so there is no compatibility question if the club adopts
it, if it is upstreamed, or if the two are merged.

Fonts are the exception. The typefaces the PDF build kit uses are **not
committed** and carry their own SIL Open Font License 1.1 terms; see
[`LICENSE`](LICENSE) and
[`docs/CGE-P_PDF_Build_Kit/fonts/README.md`](docs/CGE-P_PDF_Build_Kit/fonts/README.md).

## Cost warning

v2 costs more than v1, because it uses customer-managed KMS keys. Roughly $5 for the whole curriculum destroyed same-day, $10 to $15 if Security Hub and a few keys run for a month. KMS keys bill $1/month each and keep billing through their deletion window.

[docs/00_01_prerequisites.md](docs/00_01_prerequisites.md) sets a budget alarm before anything bills. Do that first.
