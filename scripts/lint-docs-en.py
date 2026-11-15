#!/usr/bin/env python3
"""Lint the English docs under docs/ for corrupted writes.

Allowed non-ASCII is limited to typographic punctuation and box drawing used
by the ASCII diagrams. Anything else (CJK ideographs, accented Latin letters,
mojibake) means a file was written badly. The language switcher line is the
only place a CJK string may appear.

Usage: python3 -I scripts/lint-docs-en.py
"""

import sys
import unicodedata
from pathlib import Path

ALLOWED = set("[]")
ALLOWED_EXTRA = (
    "\u2014\u2013\u00b7\u2192\u2190\u2264\u2265\u00a7\u00fc\ufe0f\u00b1"
    "\u00d7\u2194\u21d2"
    "\u201c\u201d\u2018\u2019\u00b0\u2026\u2016"
    "\u2713\u2717\u2714\u2718\u2705\u274c\u26a0\u23f3"
    "\u25cf\u25cb"
    "\u2191\u2193\u2304\u2315\u2328\u2318\u25b6\u25b2"
)
SWITCHER = "\u7b80\u4f53\u4e2d\u6587"
ROOT = Path(__file__).resolve().parent.parent / "docs"


def allowed(ch: str) -> bool:
    code = ord(ch)
    if code < 128:
        return True
    if ch in ALLOWED_EXTRA:
        return True
    return 0x2500 <= code <= 0x259F


def main() -> int:
    problems = 0
    targets = sorted(p for p in ROOT.glob("*.md") if p.is_file())
    for path in targets:
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            checked = line.replace(SWITCHER, "")
            for ch in checked:
                if allowed(ch):
                    continue
                print(f"{path.name}:{lineno}: {ch!r} {unicodedata.category(ch)}")
                problems += 1
                break
    print(f"checked {len(targets)} files, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
