# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT

# Adapted from stepbrobd/inc, MIT.
{ lib }:

{
  dir,
  scope,
}:

let
  inherit (lib)
    childDirsWithDefault
    concatMapAttrs
    isAttrs
    localPackagesFrom
    pathExists
    readDir
    ;
in
concatMapAttrs (
  name: type:
  let
    path = dir + "/${name}";
    hasDefaultNix = pathExists (path + "/default.nix");
  in
  if type != "directory" || !(scope ? ${name}) then
    { }
  else if hasDefaultNix then
    { ${name} = scope.${name}; }
  # nested scope, no default.nix of its own but child dirs with one
  else if childDirsWithDefault path != [ ] && isAttrs scope.${name} then
    {
      ${name} = localPackagesFrom {
        dir = path;
        scope = scope.${name};
      };
    }
  else
    { }
) (readDir dir)
