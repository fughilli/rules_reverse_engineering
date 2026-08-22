# rules_reverse_engineering

A small, application-agnostic toolkit for reverse-engineering binary blobs, wired
for [Bazel](https://bazel.build) (bzlmod) with [Ghidra](https://ghidra-sre.org)
provisioned hermetically via [Nix](https://nixos.org).

Ghidra is a large JVM tool, not a Bazel library, so it comes from a pinned Nix
flake (`flake.nix`, `flake.lock`); Bazel provides a reproducible harness for
driving Ghidra's headless analyzer plus a few objdump-based scanners. The build
graph stays evaluable without Nix — only the run targets need the `nix` CLI.

## Layout

```
ghidra/
  analyze_headless.sh   # thin wrapper -> `nix run .#analyzeHeadless -- <args>`
  analyze_lib.sh        # one-shot: extract a .a, import, analyze, export MMIO + decompile
  shell.sh              # interactive Ghidra shell (nix develop)
  scripts/
    ExportMmio.py       # headless post-script: dump observed MMIO register accesses
    DecompileFuncs.py   # headless post-script: decompile functions matching a regex
tools/
  mmio_scan.py          # fast objdump pass: loads/stores into an MMIO address window
  xref_callers.py       # find functions that call given callees (e.g. copy sinks)
  safety_scan.py        # rank decompiled functions by memory-safety red flags (triage)
```

## Use

```sh
# Headless analysis of a static-library blob: extract members, import, auto-
# analyze, export MMIO accesses + decompile functions matching a name regex.
bazel run //ghidra:analyze_lib -- path/to/mylib.a out/mylib '(init|reset|config)'

# Or drive analyzeHeadless directly.
bazel run //ghidra:analyze_headless -- <analyzeHeadless args>

# objdump-based scanners (host objdump by default; set OBJDUMP for another target).
OBJDUMP=my-target-objdump bazel run //tools:mmio_scan -- path/to/firmware.a
bazel run //tools:xref_callers -- path/to/archive.a
bazel run //tools:safety_scan -- out/mylib/decomp
```

The scanners shell out to `$OBJDUMP` (default `objdump`); point it at a
cross-architecture objdump when analyzing non-host blobs. `ExportMmio.py` records
accesses into a peripheral/MMIO address window whose bounds are optional
arguments (broad defaults otherwise).

## Requirements

- Bazel (via [bazelisk](https://github.com/bazelbuild/bazelisk); see `.bazelversion`).
- The `nix` CLI with flakes enabled, for the run targets that invoke Ghidra.
