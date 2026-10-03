# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ lib, ... }:

{
  perSystem =
    { pkgs, ... }:
    {
      packages =
        # every directory under pkgs with a default.nix, under its own name,
        # which is what the layout page promises
        lib.genAttrs (lib.childDirsWithDefault ../../pkgs) (name: pkgs.${name}) // {
          default = pkgs.ranet3;
        };
    };
}
