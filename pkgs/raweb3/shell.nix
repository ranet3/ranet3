# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  mkShell,
  devShells,
  raweb3,
  go-tools,
  gomod2nix,
  gopls,
  tailwindcss_4,
}:

mkShell {
  inputsFrom = [
    devShells.default
    raweb3.generator
  ];

  packages = [
    go-tools
    gomod2nix
    gopls
    tailwindcss_4
  ];
}
