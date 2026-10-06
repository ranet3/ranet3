# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2
{
  lib,
  stdenvNoCC,
}:

stdenvNoCC.mkDerivation {
  name = "ranet3.com";

  src =
    with lib.fileset;
    toSource {
      root = ./.;
      fileset = unions [
        ./favicon.svg
        ./index.html
      ];
    };

  installPhase = ''
    runHook preInstall
    install -Dm644 -t "$out" index.html favicon.svg
    runHook postInstall
  '';

  meta.license = lib.licenses.cc-by-40;
}
