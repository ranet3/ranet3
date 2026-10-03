# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT

{ lib }:

let
  flatten =
    prefix:
    lib.concatMapAttrs (
      name: value:
      let
        path = if prefix == "" then name else "${prefix}-${name}";
      in
      if lib.isDerivation value then
        { ${path} = value; }
      else if lib.isFunction value then
        { }
      else if lib.isAttrs value then
        flatten path value
      else
        throw "flattenAttrs: ${path} is neither a derivation nor an attribute set"
    );
in
flatten ""
