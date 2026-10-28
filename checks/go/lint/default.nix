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
  # hegel, which the property tests import, needs cgo on android, so the check
  # builds the daemon alone there
  # the network in memory and internal/bubble are for tests, and the package
  # strips its binary, so a build that keeps its symbols shows the daemon links
  # neither, and no file but the network's own and the tests calls its
  # constructor
  # internal/bubble's calls inline into their caller, and the testing package
  # it imports stays linked by its init, so testing's symbols mark it too
  # each list is read whole first and must hold what it always holds, so a
  # failed or empty read fails the check rather than passing it
  command = ''
    go vet ./... && GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go vet ./... && staticcheck ./... \
      && GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null ./cmd/ranet3 \
      && go build -o "$TMPDIR/ranet3" ./cmd/ranet3 && go tool nm "$TMPDIR/ranet3" > "$TMPDIR/symbols" \
      && grep -q ' main\.main$' "$TMPDIR/symbols" && ! grep -E 'transport\.(\(\*)?[Mm]emory|internal/bubble\.| testing\.' "$TMPDIR/symbols" \
      && grep -rl --include='*.go' --exclude='*_test.go' NewMemoryNetwork . > "$TMPDIR/naming" \
      && grep -qx './transport/memory.go' "$TMPDIR/naming" && ! grep -vx './transport/memory.go' "$TMPDIR/naming"
  '';
}
