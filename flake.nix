# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

{
  description = "slhdsa-c";

  inputs = {
    nixpkgs-2405.url = "github:NixOS/nixpkgs/nixos-24.05";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { config, pkgs, system, ... }:
        let
          pkgs-unstable = inputs.nixpkgs-unstable.legacyPackages.${system};
          pkgs-2405 = inputs.nixpkgs-2405.legacyPackages.${system};
          util = pkgs.callPackage ./nix/util.nix { };
          zigWrapCC = zig: pkgs.symlinkJoin {
            name = "zig-wrappers";
            paths = [
              (pkgs.writeShellScriptBin "cc"
                ''
                  exec ${zig}/bin/zig cc "$@"
                '')
              (pkgs.writeShellScriptBin "ar"
                ''
                  exec ${zig}/bin/zig ar "$@"
                '')
            ];
          };
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              (_:_: {
                gcc48 = pkgs-2405.gcc48;
                gcc49 = pkgs-2405.gcc49;
                gcc7 = pkgs-2405.gcc7;
              })
            ];
          };

          packages.linters = util.linters;
          packages.toolchains = util.toolchains;
          packages.toolchains_native = util.toolchains_native;

          devShells.default = util.mkShell {
            packages = builtins.attrValues
              {
                inherit (config.packages) linters toolchains_native;
                inherit (pkgs)
                  direnv
                  nix-direnv
                  zig_0_13;
              };
          };

          devShells.hol_light = util.mkShell {
            packages = builtins.attrValues {
              inherit (config.packages) hol_light s2n_bignum;
            };
          };
          devShells.ci = util.mkShell {
            packages = builtins.attrValues { inherit (config.packages) linters toolchains_native; };
          };
          devShells.ci_clang14 = util.mkShellWithCC' pkgs.clang_14;
          devShells.ci_clang15 = util.mkShellWithCC' pkgs.clang_15;
          devShells.ci_clang16 = util.mkShellWithCC' pkgs.clang_16;
          devShells.ci_clang17 = util.mkShellWithCC' pkgs.clang_17;
          devShells.ci_clang18 = util.mkShellWithCC' pkgs.clang_18;
          devShells.ci_clang19 = util.mkShellWithCC' pkgs.clang_19;
          devShells.ci_clang20 = util.mkShellWithCC' pkgs.clang_20;

          devShells.ci_zig0_12 = util.mkShellWithCC' (zigWrapCC pkgs.zig_0_12);
          devShells.ci_zig0_13 = util.mkShellWithCC' (zigWrapCC pkgs.zig_0_13);
          devShells.ci_zig0_14 = util.mkShellWithCC' (zigWrapCC pkgs.zig);

          devShells.ci_gcc48 = util.mkShellWithCC' pkgs.gcc48;
          devShells.ci_gcc49 = util.mkShellWithCC' pkgs.gcc49;
          devShells.ci_gcc7 = util.mkShellWithCC' pkgs.gcc7;
          devShells.ci_gcc11 = util.mkShellWithCC' pkgs.gcc11;
          devShells.ci_gcc12 = util.mkShellWithCC' pkgs.gcc12;
          devShells.ci_gcc13 = util.mkShellWithCC' pkgs.gcc13;
          devShells.ci_gcc14 = util.mkShellWithCC' pkgs.gcc14;
        };
      flake = {
        devShell.x86_64-linux =
          let
            pkgs = inputs.nixpkgs.legacyPackages.x86_64-linux;
            pkgs-unstable = inputs.nixpkgs-unstable.legacyPackages.x86_64-linux;
            util = pkgs.callPackage ./nix/util.nix { };
          in
          util.mkShell {
            packages =
              [
                util.linters
                util.toolchains_native
                pkgs.zig_0_13
              ];
          };
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.

      };
    };
}
