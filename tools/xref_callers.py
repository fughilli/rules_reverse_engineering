#!/usr/bin/env python3
"""List functions in a blob that call given callees — fast objdump-based xref.

Immediate signal without waiting for full decompilation: relocation records
name the callee of every call, so we can find every function that calls a copy
sink (memcpy/memmove/strcpy/...) and flag the ones whose names match
input/parser-surface heuristics. Pair with safety_scan.py (which needs the decomp)
once Ghidra finishes.

Usage:
  tools/audit/xref_callers.py archive.a [--surface-only]
"""
import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

# Override via the OBJDUMP env var for cross-architecture targets, e.g.
#   OBJDUMP=llvm-objdump
OBJDUMP = os.environ.get("OBJDUMP", "objdump")
DEFAULT_CALLEES = ("memcpy,memmove,os_memcpy,os_memmove,strcpy,strncpy,strcat,"
                   "sprintf,ets_memcpy,bcopy")
# Input/parser-surface name heuristics.
SURFACE = re.compile(
    r'(recv|_rx|rx_|input|parse|decode|scan|_ie\b|ie_|ies|eapol|wpa|assoc|auth|'
    r'probe|beacon|action|deliver|process|mgmt|defrag|reassemb|fragment|hci|'
    r'l2cap|att_|gatt|smp|sdp)', re.I)

RE_FUNC = re.compile(r'^[0-9a-f]+ <([^>]+)>:')
# Relocation record naming the referenced symbol, e.g. "R_<ARCH>_CALL   memcpy".
RE_RELOC = re.compile(r'R_\S*\s+(\S+)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("--callees", default=DEFAULT_CALLEES)
    ap.add_argument("--surface-only", action="store_true")
    a = ap.parse_args()
    callees = set(a.callees.split(","))

    out = subprocess.check_output([OBJDUMP, "-dr", a.blob],
                                  stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    func = "?"
    counts = defaultdict(lambda: defaultdict(int))
    for line in out.splitlines():
        m = RE_FUNC.match(line)
        if m:
            if not m.group(1).startswith(".L"):
                func = m.group(1)
            continue
        m = RE_RELOC.search(line)
        if m:
            callee = m.group(1).split("+")[0]
            if callee in callees:
                counts[func][callee] += 1

    rows = [(sum(cc.values()), f, dict(cc)) for f, cc in counts.items()]
    rows.sort(key=lambda r: -r[0])
    shown = 0
    for total, f, cc in rows:
        surf = bool(SURFACE.search(f))
        if a.surface_only and not surf:
            continue
        shown += 1
        print("%3d %s %-44s %s" % (
            total, "*" if surf else " ", f,
            ", ".join("%s:%d" % (k, v) for k, v in sorted(cc.items()))))
    print("\n# %d functions call a copy sink%s (of %d total callers)"
          % (shown, " [surface-only]" if a.surface_only else "", len(rows)),
          file=sys.stderr)


if __name__ == "__main__":
    main()
