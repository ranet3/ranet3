# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  stdenv,
  mkShell,
  devShells,
  ranet3,
  bird3,
  ethtool,
  go-tools,
  gomod2nix,
  gopls,
  iperf3-benchmark,
  iproute2,
  iputils,
  pprof,
  python3,
  strongswan,
  util-linux,
}:

mkShell {
  inputsFrom = [
    devShells.default
    ranet3
  ];

  packages = [
    go-tools
    gomod2nix
    gopls
    pprof
    python3
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    bird3
    ethtool
    iperf3-benchmark
    iproute2
    iputils
    strongswan
    util-linux
  ];
}
