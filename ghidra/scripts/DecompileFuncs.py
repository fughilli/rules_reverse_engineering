# Ghidra headless post-script: decompile functions whose name matches a regex,
# one .c file per function under an output directory. Useful for reading the
# actual code sequences behind a set of functions of interest.
#
# Run via analyzeHeadless:
#   ... -postScript DecompileFuncs.py <out_dir> "<name_regex>"
# e.g. name_regex = "(init|reset|config).*"
#
# @category ReverseEngineering
# @runtime Jython
import os
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_dir = args[0] if len(args) > 0 else "decomp"
pattern = args[1] if len(args) > 1 else ".*"
rx = re.compile(pattern)

if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()
count = 0
for func in fm.getFunctions(True):
    name = func.getName()
    if not rx.search(name):
        continue
    res = ifc.decompileFunction(func, 60, monitor)
    if res is None or not res.decompileCompleted():
        print("[DecompileFuncs] FAILED: %s" % name)
        continue
    # Prefix with entry address to keep names unique across objects.
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    fpath = os.path.join(out_dir, "%s@%s.c" % (safe, func.getEntryPoint()))
    with open(fpath, "w") as fh:
        fh.write(res.getDecompiledFunction().getC())
    count += 1

print("[DecompileFuncs] decompiled %d functions matching /%s/ into %s"
      % (count, pattern, out_dir))
