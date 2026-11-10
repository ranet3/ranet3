# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# the generator's configure phase writes the templ components' go first
{
  lib,
  raweb3,
  writableTmpDirAsHomeHook,
}:

let
  behavior = ../../pkgs/ranet3/internal/egress/kernel/behavior_linux_test.go;
  deviations = ../../pkgs/raweb3/pages/docs/design/protocol-deviations.md;
in
lib.mkPackageCheck {
  package = raweb3.generator;
  name = "test";
  tools = [ writableTmpDirAsHomeHook ];
  command = ''
    # each row the kernel exit's behavior suite declares a limit under is the
    # first cell of one row of the deviations page
    rows="$(grep -o '\<Row: *"[^"]*"' ${behavior} | cut -d '"' -f 2 | sort -u)"
    if [ -z "$rows" ]; then
      echo "the kernel exit's behavior suite declares no row" >&2
      exit 1
    fi
    cells="$(awk -F '|' '/^\|/ { cell = $2; gsub(/^ +| +$/, "", cell); print cell }' ${deviations})"
    while IFS= read -r row; do
      count="$(printf '%s\n' "$cells" | grep -c -x -F -e "$row" || true)"
      if [ "$count" != 1 ]; then
        echo "the kernel exit declares a limit under '$row', the first cell of $count rows of protocol-deviations.md, want 1" >&2
        exit 1
      fi
    done <<< "$rows"
    go vet ./... && go test ./...
  '';
}
