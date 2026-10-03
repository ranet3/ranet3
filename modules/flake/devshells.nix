# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ lib, ... }:

let
  dir = ../../pkgs;
  names = lib.filter (name: lib.pathExists (dir + "/${name}/shell.nix")) (
    lib.attrNames (lib.readDir dir)
  );
in
{
  perSystem =
    { config, pkgs, ... }:
    {
      devShells = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            deno
            git
            nixfmt-tree
            taplo
          ];
        };
      }
      // lib.genAttrs names (
        name: lib.callPackageWith (pkgs // { inherit (config) devShells; }) (dir + "/${name}/shell.nix") { }
      );
    };
}
