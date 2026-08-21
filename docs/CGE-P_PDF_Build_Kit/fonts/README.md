# Fonts

The font binaries are **not committed**. Run the fetch script once before
your first build:

    ./fetch-fonts.sh

It downloads the exact upstream releases, verifies them, and drops six
files here. `../build.py` will not produce correct output without them:
`lab_style.css` references them by relative path, and WeasyPrint resolves
those against the kit directory.

To verify what is already on disk without downloading anything:

    ./fetch-fonts.sh --check

## What gets fetched

| File | Source | Release |
|---|---|---|
| `Inter-Regular.otf` | [rsms/inter](https://github.com/rsms/inter) `extras/otf/` | v4.1 |
| `Inter-Italic.otf` | same | v4.1 |
| `Inter-SemiBold.otf` | same | v4.1 |
| `Inter-Bold.otf` | same | v4.1 |
| `JetBrainsMonoNL-Regular.ttf` | [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono) `fonts/ttf/` | v2.304 |
| `JetBrainsMonoNL-Bold.ttf` | same | v2.304 |

About 2.8MB total, which is why they live behind a script rather than in
git history.

## Two layers of verification

The script checks each archive's SHA-256 before extracting, then checks
every extracted file's SHA-256 against the exact bytes that produced the
published PDF set.

That is the same distinction Lab 2.2 draws between a version constraint
and a lock file. The pinned release tag records what we intend; the
per-file hash records what we actually got. A re-tagged or re-uploaded
upstream release passes the first check and fails the second, which is
the point.

If a hash ever mismatches, the script refuses to continue rather than
building with fonts nobody has verified.

## NL is deliberate

`JetBrainsMonoNL` is the **no-ligature** variant. The standard variant
renders `>=` as a single glyph and `~>` as an arrow. In a curriculum
where `~>` is Terraform's pessimistic constraint operator and the subject
of an entire discussion in Lab 2.2, a ligature would silently teach the
wrong syntax. Do not "upgrade" to the standard variant.

## Licensing

Inter and JetBrains Mono are both under the SIL Open Font License 1.1.
The license texts are committed here as `LICENSE-Inter-OFL.txt` and
`LICENSE-JetBrainsMono-OFL.txt`, so the terms travel with the repository
whether or not the binaries have been fetched. Both are also included in
the upstream archives.
