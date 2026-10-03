# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  perSystem =
    { lib, pkgs, ... }:
    {
      formatter = pkgs.writeShellScriptBin "formatter" ''
        set -eoux pipefail
        shopt -s globstar

        # in a linked worktree .git is a file, so walking up for .git/index escapes
        # the worktree and formats whatever checkout is above it
        root="$(${lib.getExe pkgs.git} rev-parse --show-toplevel)"
        pushd "$root" > /dev/null

        ${lib.getExe pkgs.deno} fmt **/*.md pkgs/ranet3/examples/*.json
        ${lib.getExe pkgs.nixfmt-tree} .

        pushd pkgs/ranet3 > /dev/null
        ${lib.getExe pkgs.go} fmt ./...
        ${lib.getExe pkgs.go} vet ./...
        ${lib.getExe' pkgs.go-tools "staticcheck"} ./...
        # before taplo, because gomod2nix rewrites gomod2nix.toml in its own layout
        # and formatting it first would leave the tree unformatted again
        ${lib.getExe' pkgs.gomod2nix "gomod2nix"}
        ${lib.getExe pkgs.go} run ./internal/cmd/notices
        popd > /dev/null
        ${lib.getExe pkgs.taplo} format **/*.toml

        popd
      '';
    };
}
