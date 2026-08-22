#!/usr/bin/env bash
#
# One-shot reverse-engineering pass over a static-library blob:
#   * extract the archive's object members,
#   * import them (architecture auto-detected) into a throwaway Ghidra project,
#   * run full auto-analysis,
#   * export observed MMIO register accesses (ExportMmio.py) and decompiled C
#     for the functions matching a name regex (DecompileFuncs.py).
#
# Usage:
#   tools/ghidra/analyze_lib.sh <blob.a> [out_dir] [name_regex]
#
# Example:
#   tools/ghidra/analyze_lib.sh mylib.a out/mylib '(init|reset|config)'
#
# Requires `nix` (Ghidra comes from //flake.nix). If nix is not yet live in the
# container, relaunch so .claude-container-overlay installs it.
set -euo pipefail

if ! command -v nix >/dev/null 2>&1; then
  echo "error: \`nix\` not on PATH — relaunch the container so the Nix overlay activates." >&2
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FLAKE_DIR="${GHIDRA_FLAKE_DIR:-${BUILD_WORKSPACE_DIRECTORY:-$REPO_ROOT}}"
SCRIPTS="${SCRIPT_DIR}/scripts"

BLOB="${1:?usage: analyze_lib.sh <blob.a> [out_dir] [name_regex]}"
OUT="${2:-out/$(basename "${BLOB%.a}")}"
REGEX="${3:-(init|reset|config)}"

BLOB="$(cd "$(dirname "$BLOB")" && pwd)/$(basename "$BLOB")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

members="$(mktemp -d)"
proj="$(mktemp -d)"
trap 'rm -rf "$members" "$proj"' EXIT

# ExportMmio.py appends (it runs once per imported object); start clean.
rm -f "${OUT}/mmio_accesses.csv"

echo ">> extracting $(basename "$BLOB") members..."
( cd "$members" && ar x "$BLOB" )
echo ">> $(ls "$members"/*.o 2>/dev/null | wc -l) objects; launching Ghidra headless (first run fetches Ghidra)..."

exec nix run \
  --extra-experimental-features "nix-command flakes" \
  "${FLAKE_DIR}#analyzeHeadless" -- \
  "$proj" re_$(basename "${BLOB%.a}") \
  -import "$members" -recursive \
  -scriptPath "$SCRIPTS" \
  -postScript ExportMmio.py "${OUT}/mmio_accesses.csv" \
  -postScript DecompileFuncs.py "${OUT}/decomp" "$REGEX" \
  -deleteProject
