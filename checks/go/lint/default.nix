# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  ranet3,
  go-tools,
  writableTmpDirAsHomeHook,
}:

lib.mkPackageCheck {
  package = ranet3;
  name = "lint";
  tools = [
    go-tools
    writableTmpDirAsHomeHook
  ];
  # freebsd matches none of the configured systems, so its vet is the only
  # compile of platform_unsupported.go, tun_name_other.go and their test
  # files, and the one that fails when a property test leaves out the linux
  # and darwin constraint internal/pbt asks for
  command = "go vet ./... && GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go vet ./... && staticcheck ./...";
}
