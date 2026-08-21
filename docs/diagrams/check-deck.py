#!/usr/bin/env python3
"""Check a diagram deck against the limits in v5-design-prompt.md.

    python3 check-deck.py workspace-by-step-v5.pdf

Every rule in the brief is a number, so it is checkable rather than a matter of
taste. This exists because four rounds of judging decks by eye produced two
wrong diagnoses: crowding was blamed on a caption tier that turned out to cause
under half the collisions, and pages were called broken that were only showing
the ~3pt seam between two lines of one wrapped label.

Needs poppler-utils (pdftotext, pdftohtml, pdffonts).
"""
import collections
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# From the brief. Body budgets exclude header, title, summary and footer.
PAGES, PT_W, PT_H = 12, 792, 612
BODY_WORDS, BODY_OBJECTS, MAX_HOPS = 60, 30, 4
# A list of permitted sizes turned out to measure the wrong thing. The flat,
# undigestible draft and the readable one both used five body sizes inside a
# ~5pt band. What separated them was DISTRIBUTION: the flat one spread its body
# text across three sizes of similar weight (dominant size only 41%), so the eye
# had no default and the whole page had to be read. The readable one puts 69% at
# one size and uses the others as accents.
BODY_MAX_PT = 14.0             # above this is headings, not body
DOMINANT_MIN = 0.55            # share of body text the most-used size must carry
BODY_TOP, BODY_BOT = 0.20, 0.80   # fraction of page height
OK_FONTS = ("Inter", "JetBrainsMono")


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def load_sizes(pdf, tmp):
    """Font sizes in points. pdftohtml is the only tool that reports them, but
    it splits text per word, so it is used for sizes only."""
    subprocess.run(["pdftohtml", "-xml", "-i", "-q", pdf, f"{tmp}/d"], check=True)
    root = ET.parse(f"{tmp}/d.xml").getroot()
    scale = PT_W / float(next(root.iter("page")).get("width"))
    spec = {f.get("id"): float(f.get("size")) * scale for f in root.iter("fontspec")}
    used = collections.Counter()
    for pg in root.iter("page"):
        for t in pg.iter("text"):
            if "".join(t.itertext()).strip():
                used[round(spec[t.get("font")], 1)] += 1
    return used


def load_words(pdf, tmp):
    """One entry per WORD. Overlap has to be judged on glyph boxes: a line box
    around a 33pt numeral and a 23pt title extends well below the numeral, and
    reads as colliding with the next line when nothing visibly touches."""
    subprocess.run(["pdftotext", "-bbox", pdf, f"{tmp}/w.xml"], check=True)
    root = ET.parse(f"{tmp}/w.xml").getroot()
    tag = lambda e: e.tag.split("}")[-1]
    pages = []
    for pg in root.iter():
        if tag(pg) != "page":
            continue
        items = [{"box": (float(w.get("xMin")), float(w.get("yMin")),
                          float(w.get("xMax")), float(w.get("yMax"))),
                  "text": w.text.strip()}
                 for w in pg.iter() if tag(w) == "word" and (w.text or "").strip()]
        pages.append(items)
    return pages


def load_lines(pdf, tmp):
    """One entry per rendered LINE, for word counts and body/footer zoning."""
    subprocess.run(["pdftotext", "-bbox-layout", pdf, f"{tmp}/d.xml"], check=True)
    root = ET.parse(f"{tmp}/d.xml").getroot()
    tag = lambda e: e.tag.split("}")[-1]
    pages = []
    for pg in root.iter():
        if tag(pg) != "page":
            continue
        h = float(pg.get("height"))
        items = []
        for ln in pg.iter():
            if tag(ln) != "line":
                continue
            txt = " ".join(w.text or "" for w in ln if tag(w) == "word").strip()
            if not txt:
                continue
            y0 = float(ln.get("yMin"))
            items.append({"box": (float(ln.get("xMin")), y0,
                                  float(ln.get("xMax")), float(ln.get("yMax"))),
                          "text": txt, "rel_y": y0 / h})
        pages.append(items)
    return pages


# Word boxes of adjacent lines touch by a few points: descenders of one line
# against ascenders of the next. Measured across two decks, that seam is always
# <= 4pt, while genuine overprinting ran 5 to 15pt. 5pt is the boundary.
SEAM_PT = 5


def overlaps(a, b):
    """Genuine overprint between two WORD boxes, or None for a line seam."""
    ax0, ay0, ax1, ay1 = a["box"]
    bx0, by0, bx1, by1 = b["box"]
    ix, iy = min(ax1, bx1) - max(ax0, bx0), min(ay1, by1) - max(ay0, by0)
    if ix <= 1.5 or iy < SEAM_PT:
        return None
    smaller = min((ax1 - ax0) * (ay1 - ay0), (bx1 - bx0) * (by1 - by0)) or 1
    return (round(ix * iy / smaller * 100), round(ix), round(iy))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pdf = sys.argv[1]
    if not Path(pdf).exists():
        sys.exit(f"no such file: {pdf}")
    fails = []

    info = run("pdfinfo", pdf)
    n = int(re.search(r"Pages:\s+(\d+)", info).group(1))
    if n != PAGES:
        fails.append(f"page count {n}, expected {PAGES}")
    size = re.search(r"Page size:\s+([\d.]+) x ([\d.]+)", info)
    w, h = float(size.group(1)), float(size.group(2))
    if (round(w), round(h)) != (PT_W, PT_H):
        fails.append(f"page size {w:.0f}x{h:.0f}, expected {PT_W}x{PT_H} (landscape)")

    bad_fonts = sorted({ln.split()[0].split("+")[-1]
                        for ln in run("pdffonts", pdf).splitlines()[2:] if ln.strip()
                        if not any(k in ln for k in OK_FONTS)})
    if bad_fonts:
        fails.append(f"non-brand fonts embedded: {', '.join(bad_fonts)}")

    with tempfile.TemporaryDirectory() as tmp:
        pages = load_lines(pdf, tmp)
        word_pages = load_words(pdf, tmp)
        used = load_sizes(pdf, tmp)

    total_ov = 0
    print(f"  {'page':>5}  {'body words':>10}  {'objects':>7}  {'hops':>4}  {'overprints':>10}")
    for i, items in enumerate(pages, 1):
        body = [t for t in items if BODY_TOP <= t["rel_y"] < BODY_BOT]
        words = sum(len(t["text"].split()) for t in body)
        hops = len({m.group(1) for t in body
                    if (m := re.match(r"^([1-9])(?:\s|$)", t["text"]))})
        w = word_pages[i - 1] if i - 1 < len(word_pages) else []
        ovs = [o for j in range(len(w)) for k in range(j + 1, len(w))
               if (o := overlaps(w[j], w[k]))]
        total_ov += len(ovs)
        flag = ""
        if words > BODY_WORDS:      flag += " words"
        if len(body) > BODY_OBJECTS: flag += " objects"
        if hops > MAX_HOPS:          flag += " hops"
        if ovs:                      flag += " OVERPRINT"
        print(f"  {i:>5}  {words:>10}  {len(body):>7}  {hops:>4}  {len(ovs):>10}  {flag}")
        if words > BODY_WORDS:
            fails.append(f"p{i}: {words} body words, budget {BODY_WORDS}")
        if len(body) > BODY_OBJECTS:
            fails.append(f"p{i}: {len(body)} body objects, budget {BODY_OBJECTS}")
        if hops > MAX_HOPS:
            fails.append(f"p{i}: {hops} hops, max {MAX_HOPS}")
        for frac, ix, iy in ovs[:3]:
            fails.append(f"p{i}: text overprint {frac}% ({ix}x{iy}pt)")

    body = {pt: n for pt, n in used.items() if pt <= BODY_MAX_PT}
    total = sum(body.values()) or 1
    top_pt, top_n = max(body.items(), key=lambda kv: kv[1])
    share = top_n / total
    print(f"\n  type sizes used ({len(used)}):")
    for pt, c in sorted(used.items(), reverse=True):
        mark = "  <- dominant body size" if pt == top_pt else ""
        print(f"    {pt:5.1f}pt x{c:<5}{mark}")
    print(f"\n  body hierarchy: {top_pt}pt carries {share:.0%} of body text "
          f"(needs {DOMINANT_MIN:.0%})")
    if share < DOMINANT_MIN:
        fails.append(f"no dominant body size: largest share is {share:.0%} at "
                     f"{top_pt}pt, so the eye has no default and the page reads flat")

    print()
    if fails:
        print(f"  FAIL: {len(fails)} problem(s)")
        for f in fails[:25]:
            print(f"    - {f}")
        if len(fails) > 25:
            print(f"    ... and {len(fails) - 25} more")
        return 1
    print("  PASS: deck meets every limit in the brief.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
