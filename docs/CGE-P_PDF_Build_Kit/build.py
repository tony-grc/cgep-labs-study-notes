#!/usr/bin/env python3
"""Build the CGE-P Lab Curriculum v2 branded PDF set.

Usage:
    python3 build.py [SRC_DIR] [OUT_DIR]

SRC_DIR defaults to the first directory that contains the sentinel file
00_00_plain_english_guide.md, checked in this order: ./docs beside this
script, the script's own directory, the parent directory (kit inside
docs/), then ../docs (kit beside docs/). The sentinel check is what keeps
the kit's own README.md from being mistaken for the Curriculum Overview
source. OUT_DIR defaults to ./out beside this script. Requires pandoc
(built against 3.1.3) and the Python packages in requirements.txt.

Set SOURCE_DATE_EPOCH to a fixed Unix timestamp for bit-reproducible
output; without it the font subsetter stamps build time into each
embedded font, so every rebuild hashes differently. See README.md.

Reproducible means reproducible for a fixed toolchain. weasyprint 68.1
and 69.0 at the same epoch produce text-identical but byte-different
PDFs, so the pins in requirements.txt are part of the contract. CI
asserts them rather than letting the difference surface as an
unexplained diff.

Every document gets: dark branded cover, cover copy-from-repo caveat,
page-2 print notice, upstream attribution in the cover meta, and inline
relative-.md links rewritten to LINK_BASE. The Plain English Guide
additionally gets its Contents list styled with resolved page numbers
and an entry for its closing unnumbered section.
"""

import html as htmllib
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# A directory only counts as the source tree if it holds this lab file.
# Matching on README.md alone would let the kit's own README pass for
# the Curriculum Overview source.
SENTINEL = "00_00_plain_english_guide.md"


def resolve_src():
    if len(sys.argv) > 1:
        if not os.path.exists(os.path.join(sys.argv[1], SENTINEL)):
            raise SystemExit(
                f"{sys.argv[1]} does not contain {SENTINEL}; "
                "point SRC_DIR at the directory holding the lab markdown")
        return sys.argv[1]
    candidates = [
        os.path.join(SCRIPT_DIR, "docs"),      # kit at repo root, docs/ beside it
        SCRIPT_DIR,                            # kit dropped in with the sources
        os.path.dirname(SCRIPT_DIR),           # kit inside docs/
        os.path.join(os.path.dirname(SCRIPT_DIR), "docs"),  # kit beside docs/
    ]
    for c in candidates:
        if os.path.exists(os.path.join(c, SENTINEL)):
            return c
    raise SystemExit(
        "no source directory found; looked for " + SENTINEL + " in: "
        + ", ".join(candidates) + "\nusage: python3 build.py [SRC_DIR] [OUT_DIR]")


SRC = resolve_src()
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SCRIPT_DIR, "out")
os.makedirs(OUT, exist_ok=True)

STYLESHEET = os.path.join(SCRIPT_DIR, "lab_style.css")

# Where inline .md links and the copy-from instruction point.
# The cover attribution ("based on GRCEngClub/cgep-labs") credits upstream
# and is set separately below; it must NOT be changed to this repo.
REPO = "GRCEngClub/cgep-labs"
LINK_BASE = f"https://github.com/{REPO}/blob/main/docs/"
UPSTREAM_ATTRIBUTION = "grcengclub.com &middot; based on GRCEngClub/cgep-labs"

def print_note(src):
    """Point at the markdown beside this PDF rather than at a URL.

    Readers have already cloned the repository: the source is sitting next to
    the PDF they are holding, at the same version. Sending them to GitHub adds
    a network round trip and a chance of reading a different revision."""
    return ('<div class="print-note"><strong>This PDF is for reading.</strong> '
            'Long code lines wrap to fit the page, so copy commands and code from '
            f'<code>docs/{src}</code> in your clone, not from the PDF.</div>')

# The bound edition has no single source file, so it names the directory.
BOOK_CAVEAT = ('For reading. Code lines wrap to fit the page; '
               'copy code from the matching file in docs/, not the PDF.')


def cover_caveat(src):
    """Name the source file rather than linking to it.

    A relative <a href> is the obvious answer and the wrong one: WeasyPrint
    resolves it to an absolute file:// URL at build time, so every reader would
    receive a link into the build machine's filesystem. Broken for them, and it
    would put the builder's home directory into a published document."""
    return ('For reading. Code lines wrap to fit the page; '
            f'copy code from docs/{src}, not the PDF.')

# The bound edition is a MERGE of the very PDFs that ship individually, not a
# re-render. That makes drift impossible by construction: every section is
# literally the same bytes as the standalone file, and CI verifies it.
BOOK_NAME = "CGE-P_Complete_Curriculum"
BOOK_TITLE = "The Complete Curriculum"

# src filename -> (output name, cover meta line, is_guide)
FILES = {
    "00_00_plain_english_guide.md":
        ("CGE-P_Plain_English_Guide", "Companion to Labs 0.1 through 7.1", True),
    "README.md": ("CGE-P_Curriculum_Overview", None, False),
    "00_01_prerequisites.md": ("CGE-P_Lab_0.1_Prerequisites", None, False),
    "02_02_remote_state_backend.md": ("CGE-P_Lab_2.2_Remote_State_Backend", None, False),
    "02_03_first_compliant_resource.md": ("CGE-P_Lab_2.3_First_Compliant_Resource", None, False),
    "02_04_terraform_modules_for_compliance.md": ("CGE-P_Lab_2.4_Modules_for_Compliance", None, False),
    "02_05_iac_as_compliance_evidence.md": ("CGE-P_Lab_2.5_IaC_as_Compliance_Evidence", None, False),
    "03_03_writing_compliance_policies_rego.md": ("CGE-P_Lab_3.3_Writing_Rego", None, False),
    "03_04_integrating_pac_with_terraform.md": ("CGE-P_Lab_3.4_Conftest_and_Terraform", None, False),
    "04_03_grc_evidence_pipeline.md": ("CGE-P_Lab_4.3_GRC_Evidence_Pipeline", None, False),
    "04_04_evidence_chain_of_custody.md": ("CGE-P_Lab_4.4_Chain_of_Custody", None, False),
    "05_02_aws_security_services.md": ("CGE-P_Lab_5.2_AWS_Security_Services", None, False),
    "05_04_gcp_security_services.md": ("CGE-P_Lab_5.4_GCP_Security_Services", None, False),
    "06_01_introduction_to_oscal.md": ("CGE-P_Lab_6.1_Introduction_to_OSCAL", None, False),
    "07_01_capstone_brief.md": ("CGE-P_Capstone_Brief", None, False),
}


def two_tone(title):
    """'Lab N.N: rest' -> orange lab number; otherwise highlight last word."""
    m = re.match(r'^(Lab \d+\.\d+)(.*)$', title)
    if m:
        return (f'<span class="hl">{htmllib.escape(m.group(1))}</span>'
                f'{htmllib.escape(m.group(2))}')
    head, _, tail = title.rpartition(" ")
    if head:
        return f'{htmllib.escape(head)} <span class="hl">{htmllib.escape(tail)}</span>'
    return htmllib.escape(title)


def build(src, outname, meta_line, is_guide):
    path = os.path.join(SRC, src)
    md = open(path).read()

    # Inline links to sibling lab files -> repo blob URLs
    md = re.sub(r'\]\((\d\d_\d\d_[a-z0-9_]+\.md)\)',
                lambda m: f']({LINK_BASE}{m.group(1)})', md)

    # -tex_math_dollars: pandoc otherwise reads "$0.01 ... $1" as inline LaTeX
    # and renders the span between two dollar amounts as italic math, eating
    # the intervening markup. Cost sections are full of dollar figures, so
    # this is disabled at the reader rather than escaped in prose.
    body = subprocess.run(
        ["pandoc", "-f", "gfm-tex_math_dollars", "-t", "html", "--wrap=none"],
        input=md, capture_output=True, text=True, check=True).stdout

    hm = re.search(r'<h1 id="[^"]*">(.*?)</h1>\n', body, re.S)
    if not hm:
        raise SystemExit(f"{src}: no H1 found; every document needs a title")
    # Pandoc has already HTML-escaped the heading, so "&" arrives as "&amp;".
    # two_tone() and the <title> escape again, which renders the entity
    # literally. Unescape once here so exactly one escaping pass happens.
    title = htmllib.unescape(re.sub(r'<[^>]+>', '', hm.group(1)))
    rest = body[hm.end():]

    # Up to two leading paragraphs become the cover tagline
    taglines = []
    while len(taglines) < 2:
        pm = re.match(r'<p>(.*?)</p>\n', rest, re.S)
        if not pm:
            break
        taglines.append(pm.group(1))
        rest = rest[pm.end():]

    if is_guide:
        # Style the Contents list (resolved page numbers via CSS
        # target-counter) and add its unnumbered closing section.
        rest = rest.replace(
            '<h2 id="contents">Contents</h2>\n<ol type="1">',
            '<h2 id="contents">Contents</h2>\n<ol type="1" class="toc">')
        rest = rest.replace(
            '<li><a href="#7-how-to-find-the-answer-yourself">'
            'How to find the answer yourself</a></li>\n</ol>',
            '<li><a href="#7-how-to-find-the-answer-yourself">'
            'How to find the answer yourself</a></li>\n'
            '<li class="unnum"><a href="#the-three-habits">'
            'The three habits</a></li>\n</ol>')

    meta_html = f'{htmllib.escape(meta_line)}<br/>' if meta_line else ''
    tag_html = "\n".join(f'<p class="tagline">{t}</p>' for t in taglines)

    cover = f'''<div class="cover">
  <div class="kicker">CGE-P Lab Curriculum &middot; v2</div>
  <h1>{two_tone(title)}</h1>
  {tag_html}
  <div class="rule"></div>
  <div class="covernote">{cover_caveat(src)}</div>
  <div class="meta">
    <span class="brand">GRC Engineering Club</span><br/>
    {meta_html}{UPSTREAM_ATTRIBUTION}
    <div class="motto">From checkbox GRC to engineered systems</div>
  </div>
</div>
'''
    page = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<link rel="stylesheet" href="{STYLESHEET}">
<title>{htmllib.escape(title)} - CGE-P Lab Curriculum v2</title>
</head><body>
{cover}
{print_note(src)}
{rest}
</body></html>'''

    out_pdf = os.path.join(OUT, f"{outname}.pdf")
    from weasyprint import HTML
    HTML(string=page, base_url=SCRIPT_DIR).write_pdf(out_pdf)

    from pypdf import PdfReader
    pages = len(PdfReader(out_pdf).pages)
    print(f"OK  {outname}.pdf  {pages} pages")
    return out_pdf, pages


def check_fonts():
    """Fail loudly if the vendored fonts are absent.

    The binaries are fetched, not committed (see fonts/README.md). Without
    this check WeasyPrint silently falls back to system fonts: the build
    reports OK for all 15 documents and quietly produces an off-brand set.
    The required filenames are read out of the stylesheet's @font-face
    rules so this list cannot drift from the CSS.
    """
    css = open(STYLESHEET).read()
    needed = sorted(set(re.findall(r'url\("([^"]+)"\)', css)))
    missing = [f for f in needed
               if not os.path.exists(os.path.join(SCRIPT_DIR, f))]
    if missing:
        raise SystemExit(
            "missing fonts: " + ", ".join(missing)
            + "\nWeasyPrint would silently substitute system fonts and the "
              "output would not match the published set.\nRun: "
            + os.path.join(SCRIPT_DIR, "fonts", "fetch-fonts.sh"))


def front_matter(parts, out_path):
    """Render the bound edition's cover and contents.

    Page numbers are ABSOLUTE within the finished book. They are computed
    from the real page counts of the parts, after the front matter's own
    length is known, so they are correct rather than approximate. Each part
    keeps its own footer numbering, which reads as part-relative paging in a
    bound volume; the contents below is the absolute index.
    """
    rows = "\n".join(
        f'<li><span class="t">{htmllib.escape(t)}</span>'
        f'<span class="lead"></span>'
        f'<span class="p">{n}</span></li>'
        for t, n in parts)
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<link rel="stylesheet" href="{STYLESHEET}">
<title>{htmllib.escape(BOOK_TITLE)} - CGE-P Lab Curriculum v2</title>
</head><body class="book-front">
<div class="cover">
  <div class="kicker">CGE-P Lab Curriculum &middot; v2</div>
  <h1>{two_tone(BOOK_TITLE)}</h1>
  <p class="tagline">Every guide in one volume: the Plain English companion,
     the curriculum overview, twelve labs and the capstone brief.</p>
  <p class="tagline">Each section is identical to its standalone PDF.</p>
  <div class="rule"></div>
  <div class="covernote">{BOOK_CAVEAT}</div>
  <div class="meta">
    <span class="brand">GRC Engineering Club</span><br/>
    {UPSTREAM_ATTRIBUTION}
    <div class="motto">From checkbox GRC to engineered systems</div>
  </div>
</div>
<div class="toc-page">
<h2 id="contents">Contents</h2>
<ol class="toc booktoc">{rows}</ol>
</div>
</body></html>"""
    from weasyprint import HTML
    HTML(string=page, base_url=SCRIPT_DIR).write_pdf(out_path)
    from pypdf import PdfReader
    return len(PdfReader(out_path).pages)


def build_book(built):
    """Merge the standalone PDFs into one volume, preserving bookmarks.

    built is [(title, path, pages), ...] in reading order.
    """
    from pypdf import PdfReader, PdfWriter

    fm_path = os.path.join(OUT, "_front_matter.pdf")

    # Two passes: the contents needs absolute page numbers, which depend on
    # how many pages the contents itself occupies. Render once to measure,
    # then again with the offset applied.
    offset = front_matter([(t, 1) for t, _, _ in built], fm_path)
    while True:
        rows, n = [], offset + 1
        for title, _, pages in built:
            rows.append((title, n))
            n += pages
        actual = front_matter(rows, fm_path)
        if actual == offset:
            break
        offset = actual

    writer = PdfWriter()
    writer.append(fm_path)
    for title, path, _ in built:
        # outline_item= creates the part entry AND nests that document's own
        # bookmarks beneath it, shifted into book coordinates. Appending
        # without it imports the child bookmarks at top level, and adding a
        # parent separately then yields two entries per part.
        writer.append(PdfReader(path), outline_item=title)

    out_pdf = os.path.join(OUT, f"{BOOK_NAME}.pdf")
    with open(out_pdf, "wb") as fh:
        writer.write(fh)
    os.remove(fm_path)
    print(f"OK  {BOOK_NAME}.pdf  {len(writer.pages)} pages "
          f"({offset} front matter + {sum(p for _, _, p in built)} content)")


if __name__ == "__main__":
    check_fonts()
    missing = [s for s in FILES if not os.path.exists(os.path.join(SRC, s))]
    if missing:
        raise SystemExit(f"missing sources in {SRC}: {', '.join(missing)}")
    built = []
    for src, (outname, meta_line, is_guide) in FILES.items():
        path, pages = build(src, outname, meta_line, is_guide)
        built.append((outname.replace("CGE-P_", "").replace("_", " "), path, pages))
    build_book(built)
