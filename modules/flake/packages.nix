# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ lib, ... }:

{
  perSystem =
    {
      nixosTest,
      pkgs,
      system,
      ...
    }:
    {
      packages =
        # every directory under pkgs with a default.nix, under its own name,
        # which is what the layout page promises
        lib.genAttrs (lib.childDirsWithDefault ../../pkgs) (name: pkgs.${name})
        // {
          default = pkgs.ranet3;
        }
        # profiling variants are built on demand, never as part of a check
        // lib.optionalAttrs (lib.hasSuffix "linux" system) {
          integration-profile = nixosTest {
            cores = 4;
            profile = true;
          };
          namespace-profile = pkgs.testers.runNixOSTest (
            import ../../integration/nixos-performance.nix {
              inherit pkgs;
              ranet3 = pkgs.ranet3;
              benchmarkIperf = pkgs.iperf3-benchmark;
            }
          );
        };
    };
}
