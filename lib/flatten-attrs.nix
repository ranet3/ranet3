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
      else if lib.isAttrs value && !(value ? __functor) then
        flatten path value
      else
        { }
    );
in
flatten ""
