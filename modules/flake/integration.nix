# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  perSystem =
    { pkgs, ... }:
    {
      # A nixos vm test of the harness in integration/, given the arguments it
      # is parameterized on. The checks and the profiling packages both build
      # these, so the helper is a module argument rather than a copy in each.
      _module.args.nixosTest =
        args:
        pkgs.testers.runNixOSTest (
          import ../../integration/nixos-test.nix (
            {
              inherit pkgs;
              ranet3 = pkgs.ranet3;
            }
            // args
          )
        );
    };
}
