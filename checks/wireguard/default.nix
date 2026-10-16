# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# the tun and conn tests that need root skip themselves here and run in checks/netlink
{
  lib,
  wireguard,
  writableTmpDirAsHomeHook,
}:

lib.mkPackageCheck {
  package = wireguard;
  name = "test";
  tools = [ writableTmpDirAsHomeHook ];
  command = "go vet ./... && go test -race ./...";
}
