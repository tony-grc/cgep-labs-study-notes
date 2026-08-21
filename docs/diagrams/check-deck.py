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
SIZES = {29.0, 20.0, 12.0, 10.0, 8.0}
TOL = 0.6                      # pt, for rounding in the PDF
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


def load_lines(pdf, tmp):
    """One entry per rendered LINE, which is the unit the brief means by a text
    element. pdftohtml would give one per word and inflate every count."""
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


def overlaps(a, b):
    """True 2-D overlap. Ignores the ~3pt seam between lines of one wrapped
    label, which is a rendering artefact and not a visible collision."""
    ax0, ay0, ax1, ay1 = a["box"]
    bx0, by0, bx1, by1 = b["box"]
    ix, iy = min(ax1, bx1) - max(ax0, bx0), min(ay1, by1) - max(ay0, by0)
    if ix <= 4 or iy <= 4:
        return None
    if abs(ax0 - bx0) < 12 and iy < 8:       # same wrapped block
        return None
    smaller = min((ax1 - ax0) * (ay1 - ay0), (bx1 - bx0) * (by1 - by0)) or 1
    frac = ix * iy / smaller
    return (round(frac * 100), round(ix), round(iy)) if frac > 0.20 and iy >= 10 else None


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
        used = load_sizes(pdf, tmp)

    total_ov = 0
    print(f"  {'page':>5}  {'body words':>10}  {'objects':>7}  {'hops':>4}  {'overprints':>10}")
    for i, items in enumerate(pages, 1):
        body = [t for t in items if BODY_TOP <= t["rel_y"] < BODY_BOT]
        words = sum(len(t["text"].split()) for t in body)
        hops = len({m.group(1) for t in body
                    if (m := re.match(r"^([1-9])(?:\s|$)", t["text"]))})
        ovs = [o for j in range(len(items)) for k in range(j + 1, len(items))
               if (o := overlaps(items[j], items[k]))]
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

    print(f"\n  type sizes used ({len(used)}):")
    for s, c in sorted(used.items(), reverse=True):
        ok = any(abs(s - a) <= TOL for a in SIZES)
        print(f"    {s:5.1f}pt x{c:<5} {'' if ok else '  <- not in the scale'}")
        if not ok:
            fails.append(f"type size {s}pt is not one of {sorted(SIZES, reverse=True)}")

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
