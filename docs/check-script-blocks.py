#!/usr/bin/env python3
"""Every guide block labelled `# scripts/x.sh` must equal the script that ships.

    python3 docs/check-script-blocks.py

A student copies the block out of the guide; CI runs the file in
reference/lab-X-Y/scripts/. When the two diverge the guide teaches one thing
and the repository contains another, and nothing complains. Lab 3.3 documented
a mutation-test.sh with a hardcoded policy directory while shipping a
parameterized one, and Lab 3.4 did the same with policy-gate.sh.

The label line itself is ignored on both sides: it tells the reader where to
save the block and has no business inside the file.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Two shapes of labelled block: a shell script under scripts/, and a workflow
# under .github/workflows/. Both are copied by the student out of the guide and
# run from the repository, so both can drift from what ships.
LABEL = re.compile(r"^#\s*(scripts/[a-z-]+\.sh|\.github/workflows/[a-z-]+\.yml)\s*$", re.M)


def strip_label(text, label):
    return "\n".join(l for l in text.strip().splitlines()
                     if l.strip() != f"# {label}").strip()


def main():
    fail = checked = 0
    for doc in sorted((ROOT / "docs").glob("*.md")):
        m = re.match(r"^(\d+)_(\d+)_", doc.name)
        if not m:
            continue
        lab = ROOT / f"reference/lab-{int(m.group(1))}-{int(m.group(2))}"
        for blk in re.findall(r"```(?:bash|yaml)\n(.*?)```", doc.read_text(), re.S):
            lm = LABEL.search(blk)
            if not lm:
                continue
            label = lm.group(1)
            path = lab / label
            checked += 1
            if not path.exists():
                print(f"::error file={doc.relative_to(ROOT)}::labels a block "
                      f"{label}, but {path.relative_to(ROOT)} does not exist")
                fail = 1
                continue
            if strip_label(path.read_text(), label) != strip_label(blk, label):
                print(f"::error file={path.relative_to(ROOT)}::differs from the "
                      f"block in {doc.name}. Sync one to the other.")
                fail = 1
    print(f"{checked} labelled block(s) match the files that ship.")
    return fail


if __name__ == "__main__":
    sys.exit(main())
