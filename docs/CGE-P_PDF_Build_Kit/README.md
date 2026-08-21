# CGE-P PDF Build Kit

Regenerates the branded PDF set from the lab markdown.

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    ./fonts/fetch-fonts.sh            # once; binaries are not committed
    .venv/bin/python build.py [SRC_DIR] [OUT_DIR]

A virtualenv rather than a bare `pip install`: recent Debian and Ubuntu mark
the system interpreter externally-managed (PEP 668) and refuse to install into
it. pandoc is a system binary, not a pip package; install the pinned version
named at the top of `requirements.txt`, because the pins are part of the
reproducibility contract and CI asserts them.

With no arguments, the script locates the lab markdown by checking, in
order: ./docs beside the script, the script's own directory, the parent
directory (kit inside docs/), and ../docs (kit beside docs/). A directory
only qualifies if it contains 00_00_plain_english_guide.md, so the kit's
own README.md can never be mistaken for the Curriculum Overview source.
OUT_DIR defaults to ./out. If resolution fails, the error lists every
directory tried.

Builds the 15 standalone PDFs and then `CGE-P_Complete_Curriculum.pdf`, a
207-page bound edition. The bound edition is a **merge of the very files
that ship individually**, not a re-render, so a section cannot drift from
its standalone PDF: it is the same pages. CI verifies that every section
matches, page for page.

Its contents page carries absolute page numbers, computed from the real
page counts after the front matter's own length is known. Each merged part
keeps its own part-relative footer numbering; the contents is the absolute
index.

WeasyPrint needs OS-level libraries beyond pip (Debian/Ubuntu:
libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev); see
the WeasyPrint install docs for other platforms. Builds all 15 documents: the
Plain English Guide, the Curriculum Overview, 12 labs, and the capstone
brief. Fonts (Inter, JetBrains Mono NL - the no-ligature variant, so
`>=` and `~>` render literally) are vendored in ./fonts and referenced
relatively by lab_style.css. The binaries are not committed: run
./fonts/fetch-fonts.sh once to download and verify them, or
./fonts/fetch-fonts.sh --check to verify what is already there. See
fonts/README.md.

Repo targets live at the top of build.py: LINK_BASE / REPO point at the
repo readers should copy code from; UPSTREAM_ATTRIBUTION credits the
original curriculum and should stay pointed at GRCEngClub/cgep-labs.

## Font licensing

Inter and JetBrains Mono are vendored under the SIL Open Font License;
the license texts sit beside the font files in ./fonts as the OFL
requires. The NL (no-ligature) variant of JetBrains Mono is deliberate:
the standard variant renders `>=` as a single glyph and `~>` as an
arrow, which would misteach Terraform's constraint operators. Do not
"upgrade" it to the standard variant.

## Reproducibility

Rebuilds are functionally identical but not bit-identical by default:
the font subsetter stamps a modification time inside each embedded
font, so every build hashes differently even with unchanged sources.
For bit-reproducible output (e.g. if signing the PDFs the way Lab 4.4
signs evidence bundles), set SOURCE_DATE_EPOCH to any fixed Unix
timestamp before building:

    SOURCE_DATE_EPOCH=1755500000 python3 build.py

**1755500000 is this project's canonical epoch.** The committed PDF set was
built with it, so rebuilding with the same value reproduces those bytes
exactly and `git status` shows only the documents whose content actually
changed. Use a different value and all 15 appear modified.

Two builds with the same sources and the same SOURCE_DATE_EPOCH are
byte-identical (verified via sha256). Without it, sign the markdown
sources rather than the PDFs.
