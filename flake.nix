{
  description = "Reverse-engineering toolkit — Ghidra (pinned via Nix) driven from Bazel";

  # Pinned to a nixpkgs release; bump deliberately with `nix flake update` and
  # commit the resulting flake.lock. nixos-24.11 ships a recent Ghidra (11.x).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      # `nix build .#ghidra` / `nix run .#ghidra` — the full suite (GUI + tools).
      packages = forAllSystems (system:
        let pkgs = pkgsFor system; in
        {
          default = pkgs.ghidra;
          ghidra = pkgs.ghidra;
        });

      # `nix run .#analyzeHeadless -- <args>` — the headless analyzer, which is
      # what the Bazel harness invokes. A tiny wrapper locates the launcher
      # script that the ghidra package installs, whatever it is named.
      apps = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          headless = pkgs.writeShellApplication {
            name = "ghidra-headless";
            runtimeInputs = [ pkgs.ghidra ];
            text = ''
              # The nixpkgs ghidra package installs the headless launcher as
              # `ghidra-analyzeHeadless`; older/other layouts call it
              # `analyzeHeadless`. Try both so the harness is name-agnostic.
              for candidate in ghidra-analyzeHeadless analyzeHeadless; do
                if command -v "$candidate" >/dev/null 2>&1; then
                  exec "$candidate" "$@"
                fi
              done
              echo "error: could not find Ghidra's analyzeHeadless launcher on PATH" >&2
              exit 1
            '';
          };
        in
        {
          default = self.apps.${system}.analyzeHeadless;
          analyzeHeadless = {
            type = "app";
            program = "${headless}/bin/ghidra-headless";
          };
        });

      devShells = forAllSystems (system:
        let pkgs = pkgsFor system; in
        {
          # `nix develop` — RE shell with Ghidra + host binutils (objdump/nm/
          # readelf) on PATH. The objdump-based scanners in `tools/` shell out to
          # `$OBJDUMP` (default `objdump`); for a non-host target architecture,
          # point OBJDUMP at that target's binutils (e.g. a cross objdump).
          default = pkgs.mkShell {
            packages = [ pkgs.ghidra pkgs.binutils ];
          };
        });
    };
}
