# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

{
  description = "A mesh network with Babel routing over IKEv2 and userspace ESP";

  outputs =
    { self, ... }@inputs:
    inputs.autopilot.lib.mkFlake {
      inherit inputs;

      autopilot = {
        lib.path = ./lib;
        lib.extender = inputs.nixpkgs.lib;
        lib.extensions = with inputs; [
          autopilot.lib
          parts.lib
        ];

        nixpkgs.instances.pkgs = inputs.nixpkgs;
        nixpkgs.overlays = with inputs; [
          # buildGoApplication, which pkgs/ranet3 is written against
          gomod2nix.overlays.default
          self.overlays.default
        ];
        # FSL-1.1-ALv2 is unfree to nixpkgs. The flake's own instance allows
        # this project's derivations by name, so nix run and both modules work
        # with no configuration on the host.
        nixpkgs.config.allowUnfreePredicate =
          pkg: inputs.nixpkgs.lib.hasPrefix "ranet3" (inputs.nixpkgs.lib.getName pkg);

        parts.path = ./modules/flake;
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
