# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Hold every page to its frontmatter and its links, and the site to a go-import the go command can read."""
import datetime, pathlib, re, sys
import yaml

root = pathlib.Path(sys.argv[1])
failures = []
# each field, the type yaml reads it as, and that type in words
FIELDS = {
    "title": (str, "a string"),
    "description": (str, "a string"),
    "created": (datetime.date, "a date"),
    "updated": (datetime.date, "a date"),
    "order": (int, "an integer"),
}

pages = sorted((root / "pages").rglob("*.md"))
if not pages:
    failures.append(f"{root / 'pages'}: no page found")
for page in pages:
    text = page.read_text()
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not match:
        failures.append(f"{page}: no frontmatter")
        continue
    front = match.group(1)
    # the patterns below spell out the tags they look for, which reuse would
    # otherwise read as this file's own
    # REUSE-IgnoreStart
    if not re.search(r"^# SPDX-FileCopyrightText: \d{4} .+$", front, re.M):
        failures.append(f"{page}: no SPDX-FileCopyrightText line in the frontmatter")
    if len(re.findall(r"^# SPDX-License-Identifier: .+$", front, re.M)) != 1:
        failures.append(f"{page}: want exactly one SPDX-License-Identifier line in the frontmatter")
    # REUSE-IgnoreEnd
    fields = yaml.safe_load(front) or {}
    for key, (kind, words) in FIELDS.items():
        if not isinstance(fields.get(key), kind):
            failures.append(f"{page}: {key} missing or not {words}")
    for target in re.findall(r"\]\(([^)#:\s]+\.md)(?:#[^)]*)?\)", text):
        if not (page.parent / target).resolve().is_file():
            failures.append(f"{page}: link to {target} does not resolve")

site = yaml.safe_load((root / "site.yaml").read_text())
metas = site.get("metas") if isinstance(site, dict) else None
if not isinstance(metas, dict):
    failures.append("site.yaml: metas missing or not a mapping")
    metas = {}
go_import = metas.get("go-import")
if not isinstance(go_import, str):
    failures.append("site.yaml: go-import missing or not a string")
else:
    parts = go_import.split()
    if len(parts) != 3 or parts[0] != "ranet3.com" or parts[1] != "git" or not parts[2].startswith("https://"):
        failures.append(f"site.yaml: go-import {parts} is not prefix, vcs and an https repository")
go_source = metas.get("go-source")
if not isinstance(go_source, str):
    failures.append("site.yaml: go-source missing or not a string")
elif len(go_source.split()) != 4:
    failures.append("site.yaml: go-source wants four fields")

for f in failures:
    print(f, file=sys.stderr)
sys.exit(1 if failures else 0)
