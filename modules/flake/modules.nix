# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, ... }:

{
  flake.nixosModules.default = import ../nixos/ranet3.nix { inherit inputs; };
  flake.darwinModules.default = import ../darwin/ranet3.nix { inherit inputs; };
}
