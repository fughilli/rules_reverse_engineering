# Ghidra headless post-script: export every observed MMIO register access.
#
# Emits CSV rows (function,insn_addr,access,target_addr,mnemonic,text) for each
# instruction that references a fixed address in the peripheral/MMIO window.
# This is the raw evidence for a register map: which registers the code actually
# touches, and read vs write.
#
# Run via analyzeHeadless:
#   ... -postScript ExportMmio.py <out.csv> [mmio_lo] [mmio_hi]
#
# @category ReverseEngineering
# @runtime Jython
import csv

args = getScriptArgs()
out_path = args[0] if args else "mmio_accesses.csv"

# The peripheral/MMIO address window to record; override via args. Broad on
# purpose — let the data show which banks are actually hit, rather than
# pre-judging the sub-ranges.
MMIO_LO = int(args[1], 16) if len(args) > 1 else 0x60000000
MMIO_HI = int(args[2], 16) if len(args) > 2 else 0x60100000

rt = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


def classify(ref_type):
    if ref_type.isWrite():
        return "W"
    if ref_type.isRead():
        return "R"
    return "?"


rows = []
seen = set()
insts = listing.getInstructions(True)
while insts.hasNext():
    inst = insts.next()
    addr = inst.getAddress()
    func = fm.getFunctionContaining(addr)
    fname = func.getName() if func is not None else "<none>"
    for ref in inst.getReferencesFrom():
        to = ref.getToAddress()
        if to is None:
            continue
        off = to.getOffset()
        if off < MMIO_LO or off >= MMIO_HI:
            continue
        key = (fname, addr.toString(), off, ref.getReferenceType().toString())
        if key in seen:
            continue
        seen.add(key)
        rows.append([
            fname,
            addr.toString(),
            classify(ref.getReferenceType()),
            "0x%08x" % off,
            inst.getMnemonicString(),
            inst.toString(),
        ])

rows.sort(key=lambda r: (r[3], r[0]))
# analyzeHeadless -recursive runs this post-script once PER imported object
# (each .o is its own program), so APPEND and write the header only when the
# file is new. analyze_lib.sh removes the CSV before the run for a clean start.
import os
new_file = not os.path.exists(out_path) or os.path.getsize(out_path) == 0
with open(out_path, "ab") as fh:
    w = csv.writer(fh)
    if new_file:
        w.writerow(["function", "insn_addr", "access", "target_addr", "mnemonic", "text"])
    w.writerows(rows)

print("[ExportMmio] appended %d MMIO accesses to %s" % (len(rows), out_path))
