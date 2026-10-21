// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPagePathServesEveryPageAsADirectory(t *testing.T) {
	for src, want := range map[string]string{
		"index.md":              "/",
		"about.md":              "/about/",
		"about/index.md":        "/about/",
		"docs/index.md":         "/docs/",
		"docs/design/limits.md": "/docs/design/limits/",
	} {
		if got := pagePath(src); got != want {
			t.Errorf("pagePath(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestUnvettedUntilVettedOnOrAfterTheLastUpdate(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC) }
	for _, tc := range []struct {
		vetted time.Time
		want   bool
	}{
		{time.Time{}, true},
		{day(1), true},
		{day(2), false},
		{day(3), false},
	} {
		f := frontmatter{Updated: day(2), Vetted: tc.vetted}
		if got := f.unvetted(); got != tc.want {
			t.Errorf("unvetted with vetted %v and updated %v = %v, want %v", tc.vetted, f.Updated, got, tc.want)
		}
	}
}

// front is a frontmatter with every field a docs page needs.
const front = "---\ntitle: T\ndescription: D\ncreated: 2026-10-01\nupdated: 2026-10-02\norder: 10\n---\n"

const landing = "---\ntitle: T\ndescription: D\ncreated: 2026-10-01\nupdated: 2026-10-02\nlayout: landing\n---\n"

func writePages(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadPagesPointsLinksAtServedPaths(t *testing.T) {
	dir := writePages(t, map[string]string{
		"index.md":         landing,
		"docs/index.md":    front + "[a](design/x.md#heading-one) [b](#local) [c](https://example.com/x.md)\n\n## Local\n",
		"docs/design/x.md": front + "## Heading one\n\n[back](../index.md)\n",
	})
	ps, err := loadPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	html := map[string]string{}
	for _, p := range ps {
		html[p.src] = p.html
	}
	for src, want := range map[string][]string{
		"docs/index.md":    {`href="/docs/design/x/#heading-one"`, `href="#local"`, `href="https://example.com/x.md"`},
		"docs/design/x.md": {`href="/docs/"`},
	} {
		for _, w := range want {
			if !strings.Contains(html[src], w) {
				t.Errorf("%s renders without %s:\n%s", src, w, html[src])
			}
		}
	}
}

func TestLoadPagesRefusesBrokenSources(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"link to a missing page": {
			map[string]string{"index.md": landing, "docs/a.md": front + "[x](b.md)\n"},
			`link "b.md" names no page`,
		},
		"link to a missing heading": {
			map[string]string{"index.md": landing, "docs/a.md": front + "[x](b.md#nope)\n", "docs/b.md": front + "## Yes\n"},
			"names no heading of docs/b.md",
		},
		"relative link to a file that is no page": {
			map[string]string{"index.md": landing, "docs/a.md": front + "[x](../../license.txt)\n"},
			"only .md files are served",
		},
		"page and directory index on one path": {
			map[string]string{"index.md": landing, "about.md": front, "about/index.md": front},
			"both serve /about/",
		},
		"docs page without an order": {
			map[string]string{"index.md": landing, "docs/a.md": strings.Replace(front, "order: 10\n", "", 1)},
			"order missing",
		},
		"landing page with a body": {
			map[string]string{"index.md": landing + "lost\n"},
			"renders no markdown",
		},
		"unknown frontmatter field": {
			map[string]string{"index.md": landing, "a.md": strings.Replace(front, "order", "weight", 1)},
			"field weight not found",
		},
		"no front page": {
			map[string]string{"a.md": front},
			"no index.md for the front page",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadPages(writePages(t, tc.files))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadPages error %v, want one containing %q", err, tc.want)
			}
		})
	}
}
