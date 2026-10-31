# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  deno,
  go,
  inputs,
  lib,
  nixfmt,
  reuse,
  runCommand,
  taplo,
  templ,
  writableTmpDirAsHomeHook,
}:

let
  prefix = "checks.aarch64-linux.";
  checks = inputs.self.checks.aarch64-linux;
  kvm = lib.filter (name: lib.elem "kvm" ((checks.${name}.out).requiredSystemFeatures or [ ])) (
    lib.attrNames checks
  );
  exclude = (lib.importTOML ../../atelier.toml).exclude;
  missing = lib.subtractLists exclude (map (name: prefix + name) kvm);
  stale = lib.filter (
    line: lib.hasPrefix prefix line && !(checks ? ${lib.removePrefix prefix line})
  ) exclude;
in
runCommand "ranet3-tree"
  {
    nativeBuildInputs = [
      deno
      go
      nixfmt
      reuse
      taplo
      templ
      writableTmpDirAsHomeHook
    ];
  }
  ''
    cp -r ${../..} tree
    chmod -R u+w tree
    cd tree

    # assigned first, so a file gofmt cannot parse fails the check as well
    unformatted="$(gofmt -l . | tee /dev/stderr)"
    test -z "$unformatted"
    deno fmt --check readme.md pkgs/ranet3/examples/config.json pkgs/raweb3
    templ fmt -fail pkgs/raweb3
    # found rather than globbed, so a new directory cannot quietly drop out of
    # the check. The count tells a narrowed walk from a tree that lost files
    files="$(find . -name '*.nix' -not -path './.*/*' | sort)"
    reached="$(printf '%s\n' "$files" | wc -l)"
    if [ "$reached" -lt 15 ]; then
      echo "the tree check reached $reached nix files, want at least 15" >&2
      exit 1
    fi
    nixfmt --check $files
    taplo format --check atelier.toml REUSE.toml pkgs/ranet3/REUSE.toml pkgs/ranet3/examples/*.toml pkgs/ranet3/gomod2nix.toml pkgs/wireguard/REUSE.toml pkgs/wireguard/gomod2nix.toml pkgs/raweb3/REUSE.toml pkgs/raweb3/gomod2nix.toml

    if [ ${toString (lib.length kvm)} -eq 0 ]; then
      echo "the tree check found no aarch64-linux check that needs kvm" >&2
      exit 1
    fi
    excluded=1
    for line in ${lib.escapeShellArgs missing}; do
      echo "atelier.toml does not exclude $line, which needs kvm" >&2
      excluded=0
    done
    for line in ${lib.escapeShellArgs stale}; do
      echo "atelier.toml excludes $line, which no check carries" >&2
      excluded=0
    done
    test "$excluded" = 1

    awk '
      $1 == "require" && $2 == "(" { block = 1; next }
      $1 == ")" { block = 0 }
      block { $0 = "require " $0 }
      $1 != "require" { next }
      FILENAME == ARGV[1] { ranet3[$2] = $3; next }
      $2 in ranet3 && ranet3[$2] != $3 {
        printf "%s: %s requires %s and %s requires %s\n", $2, ARGV[1], ranet3[$2], FILENAME, $3
        failed = 1
      }
      END { exit failed }
    ' pkgs/ranet3/go.mod pkgs/wireguard/go.mod pkgs/raweb3/go.mod >&2

    # reuse looks for the license texts in LICENSES alone. The rename goes
    # through a second name because a case-insensitive build directory reads
    # licenses and LICENSES as one file, and mv may refuse a rename that
    # changes only the case
    mv licenses licenses.moved
    mv licenses.moved LICENSES
    reuse lint
    touch "$out"
  ''
