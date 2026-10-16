# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  buildGoApplication,
}:

buildGoApplication {
  pname = "wireguard";
  version = "0-unstable-2026-10-06";

  src =
    with lib.fileset;
    toSource {
      root = ./.;
      fileset = unions [
        ./conn
        ./rwcancel
        ./tun
        ./go.mod
        ./go.sum
        ./LICENSE
      ];
    };

  modules = ./gomod2nix.toml;

  meta.license = lib.licenses.mit;

  # the tests run as flake checks, never inside the package build
  doCheck = false;
}
