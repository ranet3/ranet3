# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  deno,
  go,
  nixfmt,
  reuse,
  runCommand,
  taplo,
  writableTmpDirAsHomeHook,
}:

runCommand "ranet3-tree"
  {
    nativeBuildInputs = [
      deno
      go
      nixfmt
      # under structured attributes nixpkgs' sphinx hook runs only the first
      # of reuse's sphinx builders, and reuse fails for want of the man output
      # it declares. Plain reuse comes back once nixpkgs carries f77944fa, the
      # hook's fix
      (reuse.overridePythonAttrs { __structuredAttrs = false; })
      taplo
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
    deno fmt --check readme.md pkgs/ranet3-docs/pages pkgs/ranet3/examples/config.json pkgs/ranet3-site
    # found rather than globbed, so a new directory cannot quietly drop out of
    # the check. The count tells a narrowed walk from a tree that lost files
    files="$(find . -name '*.nix' -not -path './.*/*' | sort)"
    reached="$(printf '%s\n' "$files" | wc -l)"
    if [ "$reached" -lt 15 ]; then
      echo "the tree check reached $reached nix files, want at least 15" >&2
      exit 1
    fi
    nixfmt --check $files
    taplo format --check atelier.toml REUSE.toml pkgs/ranet3/REUSE.toml pkgs/ranet3/examples/*.toml pkgs/ranet3/gomod2nix.toml pkgs/wireguard/REUSE.toml pkgs/wireguard/gomod2nix.toml

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
    ' pkgs/ranet3/go.mod pkgs/wireguard/go.mod >&2

    # reuse looks for the license texts in LICENSES alone. The rename goes
    # through a second name because a case-insensitive build directory reads
    # licenses and LICENSES as one file, and mv may refuse a rename that
    # changes only the case
    mv licenses licenses.moved
    mv licenses.moved LICENSES
    reuse lint
    touch "$out"
  ''
