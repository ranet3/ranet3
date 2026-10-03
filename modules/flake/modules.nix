{ inputs, ... }:

{
  flake.nixosModules.default = import ../nixos/ranet3.nix { inherit (inputs) self; };
  flake.darwinModules.default = import ../darwin/ranet3.nix { inherit (inputs) self; };
}
