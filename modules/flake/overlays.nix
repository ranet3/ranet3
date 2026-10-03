# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, lib, ... }:

{
  flake.overlays.default =
    pkgsFinal: pkgsPrev:
    lib.importPackagesTree {
      dir = ../../pkgs;

      currentFinal = pkgsFinal;
      currentPrev = pkgsPrev;

      inheritedArgs = {
        inherit
          inputs
          lib
          pkgsFinal
          pkgsPrev
          ;
      };
    };
}
