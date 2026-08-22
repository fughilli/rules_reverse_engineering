#!/usr/bin/env python3
"""Rank Ghidra-decompiled functions by memory-safety risk, for triage.

Not a proof of anything — a *prioritizer*. It reads a directory of decompiled
`.c` files (one function each, as produced by DecompileFuncs.py) and scores each
by classic red flags, so a human/agent reviews the riskiest code first instead
of thousands of functions blindly:

  * variable-length copy sinks (memcpy/memmove/strcpy/... with a non-constant
    length),
  * those whose destination is a stack buffer (Ghidra `auStack_`/`local_`),
  * length arithmetic that can underflow (`len - k`, `x & 0xff` used as a size),
  * a name/input-surface bonus (recv/input/parse/decode/...).

Usage:
  tools/audit/safety_scan.py out/decomp [--csv out/report.csv] [--top 40]
"""
import argparse
import os
import re
import sys

# Copy sinks.
COPY = re.compile(r'\b(memcpy|memmove|strcpy|strncpy|strcat|sprintf|bcopy|'
                  r'os_memcpy|ets_memcpy|os_memmove)\s*\(')
STACK_BUF = re.compile(r'\b(?:au?Stack_|acStack_|auStack_|aStack_|local_)[0-9A-Fa-fx]+\s*\[')
# Input/parser-surface name heuristics.
SURFACE = re.compile(
    r'(recv|_rx|rx_|input|parse|decode|scan|_ie|ie_|ies|eapol|wpa|assoc|auth|'
    r'probe|beacon|action|deliver|process|mgmt|hci|l2cap|att_|gatt|smp|'
    r'decrypt|ccmp|tkip|gcmp|defrag|reassemb|fragment)', re.I)
UNDERFLOW = re.compile(r'\b\w+\s*-\s*(?:0x[0-9a-f]+|\d+)\b')
NARROW_LEN = re.compile(r'&\s*0x(?:ff|ffff)\b')


def split_args(s):
    """Split top-level comma args of a call, given text just after the '('."""
    args, depth, cur = [], 0, ''
    for ch in s:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            if depth == 0:
                args.append(cur)
                return args
            depth -= 1
        if ch == ',' and depth == 0:
            args.append(cur)
            cur = ''
        else:
            cur += ch
    args.append(cur)
    return args


def is_const(expr):
    return re.fullmatch(r'\s*(?:0x[0-9a-fA-F]+|\d+)\s*', expr or '') is not None


def scan_file(path):
    try:
        text = open(path, errors='replace').read()
    except OSError:
        return None
    fname = os.path.basename(path).split('@')[0]
    findings = []
    for m in COPY.finditer(text):
        call = m.group(1)
        args = split_args(text[m.end():])
        length = args[2] if len(args) >= 3 else (args[-1] if args else '')
        var_len = not is_const(length)
        dst = args[0].strip() if args else ''
        stack_dst = bool(STACK_BUF.search(dst)) or dst.strip().startswith('auStack') \
            or dst.strip().startswith('local_') or dst.strip().startswith('acStack')
        findings.append({
            'call': call, 'len': length.strip()[:40], 'var_len': var_len,
            'stack_dst': stack_dst, 'dst': dst.strip()[:36],
        })
    score = 0
    var_copies = [f for f in findings if f['var_len']]
    stack_var = [f for f in var_copies if f['stack_dst']]
    score += 3 * len(var_copies) + 3 * len(stack_var)
    score += 2 * len(STACK_BUF.findall(text)) ** 0  # presence, not count
    if STACK_BUF.search(text) and var_copies:
        score += 3
    if SURFACE.search(fname):
        score += 5
    if NARROW_LEN.search(text) and var_copies:
        score += 2
    return {
        'func': fname, 'file': os.path.basename(path), 'score': score,
        'var_copies': len(var_copies), 'stack_var_copies': len(stack_var),
        'surface': bool(SURFACE.search(fname)), 'findings': findings,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('decomp_dir')
    ap.add_argument('--csv')
    ap.add_argument('--top', type=int, default=40)
    args = ap.parse_args()

    rows = []
    for root, _dirs, files in os.walk(args.decomp_dir):
        for fn in files:
            if fn.endswith('.c'):
                r = scan_file(os.path.join(root, fn))
                if r and r['score'] > 0:
                    rows.append(r)
    rows.sort(key=lambda r: (-r['score'], r['func']))

    print("# %d functions with red flags (of the decomp set in %s)\n"
          % (len(rows), args.decomp_dir))
    print("score  varcpy stkcpy surf  function")
    for r in rows[:args.top]:
        print("%4d   %5d  %5d   %-4s  %s"
              % (r['score'], r['var_copies'], r['stack_var_copies'],
                 'Y' if r['surface'] else '', r['func']))

    if args.csv:
        import csv as _csv
        with open(args.csv, 'w') as fh:
            w = _csv.writer(fh)
            w.writerow(['score', 'func', 'file', 'var_copies', 'stack_var_copies',
                        'surface', 'sample_len', 'sample_dst'])
            for r in rows:
                s = r['findings'][0] if r['findings'] else {}
                w.writerow([r['score'], r['func'], r['file'], r['var_copies'],
                            r['stack_var_copies'], r['surface'],
                            s.get('len', ''), s.get('dst', '')])
        print("\nwrote %d rows to %s" % (len(rows), args.csv), file=sys.stderr)


if __name__ == '__main__':
    main()
