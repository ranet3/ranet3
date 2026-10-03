# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2
{
  lib,
  runCommand,
  jq,
  yq-go,
}:

# the pages as written, plus a stub that answers the go command until an
# engine renders them. Choosing an engine replaces this file and nothing else.
runCommand "ranet3-docs"
  {
    src =
      with lib.fileset;
      toSource {
        root = ../..;
        fileset = unions [
          ./pages
          ./site.yaml
          ../../licenses/CC-BY-4.0.txt
          ../../licenses/MIT.txt
        ];
      };
    nativeBuildInputs = [
      jq
      yq-go
    ];
    meta.license = with lib.licenses; [
      cc-by-40
      mit
    ];
  }
  ''
    dest="$out/share/ranet3-docs"
    mkdir -p "$dest/licenses"
    cp -r "$src/pkgs/ranet3-docs/pages" "$src/pkgs/ranet3-docs/site.yaml" "$dest/"
    cp "$src/licenses/CC-BY-4.0.txt" "$src/licenses/MIT.txt" "$dest/licenses/"
    # each value taken from site.yaml is escaped for html, and a missing one
    # fails the build rather than printing null
    metas="$(yq -e -o=json '.metas' "$src/pkgs/ranet3-docs/site.yaml" | jq -r 'to_entries[] | @html "<meta name=\"\(.key)\" content=\"\(.value)\">"')"
    repository="$(yq -e -o=json '.repository' "$src/pkgs/ranet3-docs/site.yaml" | jq -r '@html')"
    title="$(yq -e -o=json '.title' "$src/pkgs/ranet3-docs/site.yaml" | jq -r '@html')"
    for page in index 404; do
      {
        echo '<!doctype html>'
        echo '<html lang="en">'
        echo '<head>'
        echo '<meta charset="utf-8">'
        echo "<title>$title</title>"
        echo "$metas"
        echo '</head>'
        echo '<body>'
        echo "<p><a href=\"$repository\">$repository</a></p>"
        echo '</body>'
        echo '</html>'
      } > "$dest/$page.html"
    done
  ''
