# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# the generator's configure phase writes the templ components' go first
{
  lib,
  raweb3,
  writableTmpDirAsHomeHook,
}:

lib.mkPackageCheck {
  package = raweb3.generator;
  name = "test";
  tools = [ writableTmpDirAsHomeHook ];
  command = "go vet ./... && go test ./...";
}
