#!/usr/bin/env bash
#
# Drop into an interactive shell with the pinned Ghidra tools on PATH, via the
# repo-root Nix flake's devShell.
#
#   bazel run //:ghidra_shell
#   bazel run //tools/ghidra:shell
set -euo pipefail

if ! command -v nix >/dev/null 2>&1; then
  echo "error: \`nix\` is not on PATH — see tools/ghidra/analyze_headless.sh for setup." >&2
  exit 127
fi

FLAKE_DIR="${GHIDRA_FLAKE_DIR:-${BUILD_WORKSPACE_DIRECTORY:-$PWD}}"

exec nix develop \
  --extra-experimental-features "nix-command flakes" \
  "${FLAKE_DIR}"
