#!/usr/bin/env bash
#
# Bazel harness that drives Ghidra's headless analyzer (analyzeHeadless) through
# the pinned Nix flake at the repo root.
#
#   bazel run //tools/ghidra:analyze_headless -- <analyzeHeadless args>
#
# Example (create a throwaway project, import + auto-analyze a binary):
#   bazel run //:analyze_headless -- \
#       ./ghidra-projects MyProject -import /path/to/binary -overwrite
#
# Ghidra is provided entirely by Nix (see //flake.nix); the first run builds the
# Ghidra closure and can take a while.
set -euo pipefail

if ! command -v nix >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: `nix` is not on PATH.

Ghidra is provided via Nix (see flake.nix). Install/enable Nix, then retry.

In claude-container: the Nix installer lives in
.claude-container-overlay/Dockerfile. Relaunch the container so it takes effect,
then confirm as the runtime user:
    readlink -f /nix/var/nix/profiles/default   # must resolve into /nix/store/...
    nix --version
EOF
  exit 127
fi

# The flake lives at the workspace root. `bazel run` exports
# BUILD_WORKSPACE_DIRECTORY (absolute path to the real source tree); allow an
# explicit override, and fall back to the current directory when invoked
# outside `bazel run`.
FLAKE_DIR="${GHIDRA_FLAKE_DIR:-${BUILD_WORKSPACE_DIRECTORY:-$PWD}}"

exec nix run \
  --extra-experimental-features "nix-command flakes" \
  "${FLAKE_DIR}#analyzeHeadless" -- "$@"
