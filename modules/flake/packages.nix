# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ lib, ... }:

{
  perSystem =
    { pkgs, ... }:
    {
      legacyPackages = lib.localPackagesFrom {
        dir = ../../pkgs;
        scope = pkgs;
      };
      packages.default = pkgs.ranet3;
    };
}
