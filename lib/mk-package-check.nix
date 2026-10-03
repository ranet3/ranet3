# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT

{ ... }:

{
  package,
  name,
  command,
  tools ? [ ],
}:

package.overrideAttrs (prev: {
  pname = "${prev.pname}-${name}";
  nativeBuildInputs = prev.nativeBuildInputs ++ tools;
  buildPhase = command;
  installPhase = ''touch "$out"'';
  # some tests bind loopback, which the darwin sandbox forbids by default
  __darwinAllowLocalNetworking = true;
})
