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
        # libcap, and through it qemu and the test VMs, build with the set's own go
        go = pkgsFinal.go_latest;
      };
    };
}
