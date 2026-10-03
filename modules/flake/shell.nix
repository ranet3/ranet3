# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  perSystem =
    {
      lib,
      pkgs,
      ...
    }:
    {
      devShells.default = pkgs.mkShell {
        packages =
          with pkgs;
          [
            deno
            go
            go-tools
            gomod2nix
            gopls
            pprof
            python3
          ]
          # the integration harness and the namespace benchmark are linux only
          ++ lib.optionals stdenv.hostPlatform.isLinux [
            bird3
            ethtool
            pkgs.iperf3-benchmark
            iproute2
            iputils
            strongswan
            util-linux
          ];
      };
    };
}
