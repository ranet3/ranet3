# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, lib, ... }@args:

let
  modulesFor =
    name:
    lib.loadAll {
      dir = ../.. + "/${name}";
      importer = lib.importApplyWithArgs;
      args = { inherit inputs lib; };
    };
in
lib.deepMergeAttrsList (
  map (x: import x (args // { inherit modulesFor; })) (lib.filesList ./. [ "default.nix" ])
)
