# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  ranet3,
  writableTmpDirAsHomeHook,
}:

lib.mkPackageCheck {
  package = ranet3;
  name = "test";
  tools = [ writableTmpDirAsHomeHook ];
  command = "go test -race ./...";
}
