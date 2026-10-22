// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/chroma/v2"
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

const landing = "---\ntitle: T\ndescription: D\ncreated: 2026-10-01\nupdated: 2026-10-02\nlayout: bare\n---\n"

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

func TestLoadPagesHighlightsCodeBlocks(t *testing.T) {
	dir := writePages(t, map[string]string{
		"index.md": landing + "```sh\n# a comment\ncd \"$HOME\" && go vet ./...\nsudo nix run . -- --config x.toml \\\n  --dry\n```\n\n" +
			"```nix\n{\n  networking.ranet3.enable = true;\n  imports = [ inputs.x ];\n}\n```\n\n" +
			"```\n<plain> & \"text\"\n```\n",
	})
	ps, err := loadPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<code class="language-sh"><span class="c"># a comment</span>`,
		`<span class="nf">cd</span>`,
		`<span class="k">&amp;&amp;</span> <span class="nf">go</span> vet ./...` + "\n",
		`<span class="nf">sudo</span> <span class="nf">nix</span> run . <span class="k">--</span> <span class="k">--config</span> x.toml <span class="se">`,
		"<span class=\"se\">\\\n</span>  <span class=\"k\">--dry</span>\n</code></pre>",
		`<span class="na">networking</span><span class="k">.</span><span class="na">ranet3</span><span class="k">.</span><span class="na">enable</span> <span class="k">=</span> <span class="k">true;</span>`,
		`<span class="na">imports</span> <span class="k">=</span> <span class="p">[</span> inputs<span class="k">.</span>x <span class="p">]</span>`,
		"<code>&lt;plain&gt; &amp; &quot;text&quot;\n</code></pre>",
	} {
		if !strings.Contains(ps[0].html, want) {
			t.Errorf("renders without %s:\n%s", want, ps[0].html)
		}
	}
}

func TestLoadPagesPlacesComponentsNamedByEmptyElements(t *testing.T) {
	dir := writePages(t, map[string]string{
		"index.md": landing + "<div class=\"text-[13px]\">\n<ui-ascii-mark></ui-ascii-mark>\n</div>\n",
	})
	ps, err := loadPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ps[0].html, `<div class="text-[13px]">`+"\n"+`<pre class="m-0`) || !strings.Contains(ps[0].html, "..::----::..") {
		t.Errorf("renders without the ascii mark in place:\n%s", ps[0].html)
	}
	if strings.Contains(ps[0].html, "<ui-") {
		t.Errorf("renders the component's element:\n%s", ps[0].html)
	}
}

func TestTokenClassFollowsNordsSyntaxGuide(t *testing.T) {
	for _, tc := range []struct {
		kind  chroma.TokenType
		value string
		want  string
	}{
		{chroma.Text, "go", ""},
		{chroma.Text, " \n", ""},
		{chroma.Error, "\n", ""},
		{chroma.Punctuation, "{", "p"},
		{chroma.Punctuation, ",", "k"},
		{chroma.KeywordDeclaration, "let", "k"},
		{chroma.KeywordType, "int", "kt"},
		{chroma.NameBuiltin, "cd", "nf"},
		{chroma.NameBuiltinPseudo, "self", "k"},
		{chroma.CommentSingle, "# x", "c"},
		{chroma.CommentPreproc, "#include", "cp"},
		{chroma.GenericPrompt, "$", "c"},
		{chroma.GenericOutput, "Node example/laptop", ""},
		{chroma.LiteralStringDouble, `"x"`, "s"},
		{chroma.LiteralStringEscape, `\n`, "se"},
		{chroma.LiteralNumberInteger, "1", "m"},
		{chroma.NameVariable, "$HOME", ""},
		{chroma.NameConstant, "true", "k"},
		{chroma.NameOther, "port", "na"},
		{chroma.NameTag, `"nodes"`, "na"},
		{chroma.Error, "?", "err"},
	} {
		if got := tokenClass(chroma.Token{Type: tc.kind, Value: tc.value}); got != tc.want {
			t.Errorf("tokenClass(%v %q) = %q, want %q", tc.kind, tc.value, got, tc.want)
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
		"unknown frontmatter field": {
			map[string]string{"index.md": landing, "a.md": strings.Replace(front, "order", "weight", 1)},
			"field weight not found",
		},
		"code block in a language chroma has no lexer for": {
			map[string]string{"index.md": landing, "docs/a.md": front + "```tmol\nx = 1\n```\n"},
			`code block language "tmol" has no lexer`,
		},
		"element that names no component": {
			map[string]string{"index.md": landing + "<ui-nope></ui-nope>\n"},
			"<ui-nope></ui-nope> names no component",
		},
		"component element with content": {
			map[string]string{"index.md": landing + "<ui-ascii-mark>x</ui-ascii-mark>\n"},
			"a component takes none",
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
