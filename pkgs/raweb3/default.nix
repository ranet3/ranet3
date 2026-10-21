# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  stdenv,
  buildGoApplication,
  go,
  runCommand,
  tailwindcss_4,
  templ,
}:

let
  generator = buildGoApplication {
    pname = "raweb3";
    version = "0-unstable-2026-10-21";

    src =
      with lib.fileset;
      toSource {
        root = ./.;
        fileset = unions [
          ./cmd
          (fileFilter (file: !lib.hasSuffix "_templ.go" file.name) ./internal)
          (fileFilter (file: !lib.hasSuffix "_templ.go" file.name) ./ui)
          ./go.mod
          ./go.sum
        ];
      };

    modules = ./gomod2nix.toml;
    inherit go;

    nativeBuildInputs = [ templ ];

    # the generated code calls into the templ module go.mod requires, so the
    # generator has to be the same release
    postConfigure = ''
      if ! grep -q "github.com/a-h/templ $(templ version)$" go.mod; then
        echo "go.mod requires another templ than the generator, $(templ version)" >&2
        exit 1
      fi
      templ generate
    '';

    subPackages = [ "cmd/raweb3" ];

    meta.license = lib.licenses.fsl11Asl20;

    # the tests run as a flake check, never inside the package build
    doCheck = false;
  };
in
runCommand "ranet3.com"
  {
    src =
      with lib.fileset;
      toSource {
        root = ./.;
        fileset = unions [
          ./pages
          ./static
          ./site.yaml
          ./ui/style.css
          # the class names tailwind compiles are read from the components
          (fileFilter (file: file.hasExt "templ") ./.)
        ];
      };

    nativeBuildInputs = [
      generator
      tailwindcss_4
    ];

    env = lib.optionalAttrs stdenv.hostPlatform.isDarwin {
      # bun compiled tailwindcss dies with SIGTRAP at startup in the darwin
      # sandbox unless the jsc jit is off
      BUN_JSC_useJIT = "0";
    };

    passthru = { inherit generator; };

    meta.license = with lib.licenses; [
      cc-by-40
      mit
    ];
  }
  ''
    raweb3 build --root "$src" --out "$out"
  ''
