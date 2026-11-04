# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  outputs =
    inputs:
    inputs.autopilot.lib.mkFlake {
      inherit inputs;

      autopilot = {
        parts.path = ./modules/flake;

        lib = {
          path = ./lib;
          extender = inputs.nixpkgs.lib;
          extensions = with inputs; [
            autopilot.lib
            parts.lib
          ];
        };

        nixpkgs = {
          instances.pkgs = inputs.nixpkgs;
          config.allowUnfree = true;
          overlays = with inputs; [
            self.overlays.default
            gomod2nix.overlays.default
            # the tools that read the modules build with go_latest, and the
            # package set's go stays nixpkgs' default, which libcap and through
            # it qemu and the test machines build with
            (final: prev: {
              go-tools = prev.go-tools.override { buildGoModule = final.buildGoLatestModule; };
              gomod2nix = prev.gomod2nix.override { go = final.go_latest; };
              templ = prev.templ.override { buildGoModule = final.buildGoLatestModule; };
            })
          ];
        };
      };
    } { systems = import inputs.systems; };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable-small";
    systems.url = "github:nix-systems/triplet";
    parts.url = "github:hercules-ci/flake-parts";
    parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    autopilot.url = "github:stepbrobd/autopilot";
    autopilot.inputs.nixpkgs.follows = "nixpkgs";
    autopilot.inputs.parts.follows = "parts";
    autopilot.inputs.systems.follows = "systems";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.systems.follows = "systems";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix.inputs.flake-utils.follows = "utils";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.ysun.co" ];
    extra-trusted-public-keys = [ "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=" ];
  };
}
