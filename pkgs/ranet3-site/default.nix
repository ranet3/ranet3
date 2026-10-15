# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2
{
  lib,
  stdenvNoCC,
  minify,
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

  nativeBuildInputs = [ minify ];

  buildPhase = ''
    runHook preBuild
    mkdir dist
    minify --html-keep-document-tags --html-keep-quotes -o dist/index.html index.html
    minify -o dist/favicon.svg favicon.svg
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm644 -t "$out" dist/index.html dist/favicon.svg
    runHook postInstall
  '';

  meta.license = lib.licenses.cc-by-40;
}
