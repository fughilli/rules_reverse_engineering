#!/usr/bin/env python3
"""Extract observed MMIO register accesses from a static-library blob.

Fast first-pass evidence for a register map: disassembles every object member
with `objdump -d` and records each load/store whose effective address objdump
reconstructs (from a high-immediate + offset pair) into a peripheral MMIO
address window. objdump prints that reconstructed address in the line's `#`
comment, e.g.

    600a7124 <...>   lw   a4,292(a5)   # 600a7124 <...>

so we don't have to re-do the immediate arithmetic. This catches the common
high-immediate + load/store idiom; pointers built at runtime are missed
(Ghidra's data-flow pass in ExportMmio.py covers those). Read vs write comes
from the mnemonic.

Usage:
    tools/re/mmio_scan.py <blob.a> [--csv out.csv] [--lo 0x60000000] [--hi 0x60100000]

Prints a per-address summary (R/W counts + touching functions) and, with --csv,
writes one row per (function, address, access).
"""
import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

# Override via the OBJDUMP env var for cross-architecture targets, e.g. where
# the objdump has an architecture-specific name.
OBJDUMP = os.environ.get("OBJDUMP", "objdump")

LOADS = {"lw", "lh", "lhu", "lb", "lbu", "c.lw", "c.lwsp", "flw"}
STORES = {"sw", "sh", "sb", "c.sw", "c.swsp", "fsw"}

# member header:  "objfile.o:     file format elf32-little"
RE_MEMBER = re.compile(r"^(\S+\.o):\s+file format")
# function header: "00000000 <some_func>:"
RE_FUNC = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
# insn line: "  24:\t1247a703\tlw\ta4,292(a5) # 600a7124 <...>"
RE_INSN = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\t(\S+)\t?([^#]*)#\s*([0-9a-f]+)")


def scan(blob, lo, hi):
    out = subprocess.check_output(
        [OBJDUMP, "-d", "-M", "no-aliases", blob],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8", "replace")

    rows = []  # (func, addr, access, member)
    member = "?"
    func = "?"
    for line in out.splitlines():
        m = RE_MEMBER.match(line)
        if m:
            member = m.group(1)
            func = "?"
            continue
        m = RE_FUNC.match(line)
        if m:
            # Keep the last real function symbol; `.L*` are internal labels that
            # would otherwise shadow the function that contains the access.
            if not m.group(1).startswith(".L"):
                func = m.group(1)
            continue
        m = RE_INSN.match(line)
        if not m:
            continue
        mnem = m.group(1)
        addr = int(m.group(3), 16)
        if addr < lo or addr >= hi:
            continue
        if mnem in LOADS:
            access = "R"
        elif mnem in STORES:
            access = "W"
        else:
            continue  # e.g. `lui`/`auipc` comment lines that aren't a mem op
        rows.append((func, addr, access, member))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("--csv")
    ap.add_argument("--lo", default="0x60000000")
    ap.add_argument("--hi", default="0x60100000")
    args = ap.parse_args()
    lo, hi = int(args.lo, 16), int(args.hi, 16)

    rows = scan(args.blob, lo, hi)

    by_addr = defaultdict(lambda: {"R": 0, "W": 0, "funcs": set()})
    for func, addr, access, _member in rows:
        by_addr[addr][access] += 1
        by_addr[addr]["funcs"].add(func)

    print("# %d MMIO accesses, %d distinct registers in [%s,%s)"
          % (len(rows), len(by_addr), args.lo, args.hi))
    print("# addr        R    W   nfuncs  example_fn")
    for addr in sorted(by_addr):
        d = by_addr[addr]
        example = sorted(d["funcs"])[0]
        print("0x%08x  %4d %4d   %5d   %s"
              % (addr, d["R"], d["W"], len(d["funcs"]), example))

    if args.csv:
        with open(args.csv, "w") as fh:
            fh.write("function,address,access,member\n")
            for func, addr, access, member in sorted(rows, key=lambda r: (r[1], r[0])):
                fh.write("%s,0x%08x,%s,%s\n" % (func, addr, access, member))
        print("\nwrote %d rows to %s" % (len(rows), args.csv), file=sys.stderr)


if __name__ == "__main__":
    main()
