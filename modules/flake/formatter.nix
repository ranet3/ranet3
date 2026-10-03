# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  perSystem =
    { lib, pkgs, ... }:
    {
      formatter = pkgs.writeShellScriptBin "formatter" ''
        set -eoux pipefail
        shopt -s globstar

        root="$(${lib.getExe pkgs.git} rev-parse --show-toplevel)"
        pushd "$root" > /dev/null

        ${lib.getExe pkgs.deno} fmt **/*.md pkgs/ranet3/examples/*.json
        ${lib.getExe pkgs.nixfmt-tree} .

        pushd pkgs/ranet3 > /dev/null
        ${lib.getExe pkgs.go} fmt ./...
        ${lib.getExe pkgs.go} vet ./...
        ${lib.getExe' pkgs.go-tools "staticcheck"} ./...
        ${lib.getExe' pkgs.gomod2nix "gomod2nix"}
        ${lib.getExe pkgs.go} run ./internal/cmd/notices
        popd > /dev/null

        ${lib.getExe pkgs.taplo} format **/*.toml

        popd
      '';
    };
}
