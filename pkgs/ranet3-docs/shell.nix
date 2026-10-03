# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  mkShell,
  devShells,
  ranet3-docs,
}:

mkShell {
  inputsFrom = [
    devShells.default
    ranet3-docs
  ];
}
