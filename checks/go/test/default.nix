# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  stdenv,
  ranet3,
  writableTmpDirAsHomeHook,
}:

let
  libhegel = "${ranet3.vendorEnv}/hegel.dev/go/hegel/internal/libhegel/libs/libhegel-${ranet3.GOOS}-${ranet3.GOARCH}${stdenv.hostPlatform.extensions.sharedLibrary}";
in
lib.mkPackageCheck {
  package = ranet3;
  name = "test";
  tools = [ writableTmpDirAsHomeHook ];
  command = ''
    HEGEL_LIBHEGEL_PATH=${libhegel} go test -race ./...
    for cache in "$HOME/Library/Caches/hegel-go" "$HOME/.cache/hegel-go"; do
      if [ -e "$cache" ]; then
        echo "a test wrote hegel's library cache at $cache" >&2
        exit 1
      fi
    done
  '';
}
