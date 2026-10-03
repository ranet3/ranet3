# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, lib, ... }:

{
  perSystem =
    { pkgs, ... }:
    let
      tree = lib.importPackagesTree {
        dir = ../../checks;
        currentFinal = pkgs;
        currentPrev = { };
        inheritedArgs = {
          inherit inputs lib;
          pkgsFinal = pkgs;
          checksFinal = tree;
        };
      };
      found = lib.localPackagesFrom {
        dir = ../../checks;
        scope = tree;
      };
    in
    {
      checks = lib.filterAttrs (_: lib.meta.availableOn pkgs.stdenv.hostPlatform) (
        lib.flattenAttrs (removeAttrs found [ "profile" ])
      );
      legacyPackages.profile = found.profile;
    };
}
