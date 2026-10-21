// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/raweb3/internal/pages"
)

// frontmatter is the YAML between a page's fences.
type frontmatter struct {
	Title       string    `yaml:"title"`
	Description string    `yaml:"description"`
	Created     time.Time `yaml:"created"`
	Updated     time.Time `yaml:"updated"`
	// Order sorts a docs page among the others in its directory
	Order *int `yaml:"order"`
	// Layout is the template the page renders through. A page under docsDir
	// takes the docs layout and any other the page layout, unless this names
	// another
	Layout string `yaml:"layout"`
	// Vetted is the day a person last read the page in full, set by hand
	// only and never shown. A page without it, or changed since, carries a
	// notice that it may contain unreviewed machine generated text
	Vetted time.Time `yaml:"vetted"`
}

// unvetted says whether the page carries the notice.
func (f frontmatter) unvetted() bool {
	return f.Vetted.IsZero() || f.Vetted.Before(f.Updated)
}

// page is one page of the pages directory.
type page struct {
	// src is the page's file under the pages directory, slash separated
	src    string
	path   string
	layout string
	front  frontmatter
	html   string

	body []byte
	root ast.Node
	// ids are the fragments the page's headings answer to
	ids map[string]bool
}

var markdown = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

// loadPages reads and renders every page under dir. Every page is parsed
// before any is rendered, since a link is checked against the headings of the
// page it names.
func loadPages(dir string) ([]*page, error) {
	var ps []*page
	var errs []error
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		pg, err := parsePage(filepath.ToSlash(rel), p)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		ps = append(ps, pg)
		return nil
	})
	if err != nil {
		return nil, err
	}
	byPath := map[string]*page{}
	bySrc := map[string]*page{}
	for _, pg := range ps {
		if other, ok := byPath[pg.path]; ok {
			errs = append(errs, fmt.Errorf("%s and %s both serve %s", other.src, pg.src, pg.path))
		}
		byPath[pg.path] = pg
		bySrc[pg.src] = pg
	}
	if byPath["/"] == nil {
		errs = append(errs, fmt.Errorf("%s: no %s%s for the front page", dir, pageIndex, pageSuffix))
	}
	for _, pg := range ps {
		errs = append(errs, pg.render(bySrc)...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	slices.SortFunc(ps, func(a, b *page) int {
		return cmp.Or(
			cmp.Compare(path.Dir(a.src), path.Dir(b.src)),
			cmp.Compare(order(a), order(b)),
			cmp.Compare(a.src, b.src),
		)
	})
	return ps, nil
}

// order is a page's place in its directory, before every page that has none.
func order(p *page) int {
	if p.front.Order == nil {
		return 0
	}
	return *p.front.Order
}

// parsePage reads one page and parses its frontmatter and markdown.
func parsePage(src, file string) (*page, error) {
	if !strings.HasSuffix(src, pageSuffix) {
		return nil, fmt.Errorf("%s: not a %s page", src, pageSuffix)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	front, body, ok := splitFrontmatter(b)
	if !ok {
		return nil, fmt.Errorf("%s: no frontmatter between %q lines at the top", src, strings.TrimSpace(fence))
	}
	p := &page{src: src, path: pagePath(src), body: body}
	dec := yaml.NewDecoder(bytes.NewReader(front))
	dec.KnownFields(true)
	if err := dec.Decode(&p.front); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	if p.layout, err = layoutOf(src, p.front.Layout); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	if err := p.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	p.root = markdown.Parser().Parse(text.NewReader(body), parser.WithContext(parser.NewContext()))
	p.ids = map[string]bool{}
	ast.Walk(p.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if h, ok := n.(*ast.Heading); ok && entering {
			if id, ok := h.AttributeString("id"); ok {
				p.ids[string(id.([]byte))] = true
			}
		}
		return ast.WalkContinue, nil
	})
	return p, nil
}

// layoutOf is the layout the page in src renders through, given the one its
// frontmatter names.
func layoutOf(src, named string) (string, error) {
	inDocs := strings.HasPrefix(src, docsDir+"/")
	switch named {
	case "":
		if inDocs {
			return layoutDocs, nil
		}
		return layoutPage, nil
	case layoutDocs:
		if !inDocs {
			return "", fmt.Errorf("layout %s outside %s/", named, docsDir)
		}
		return named, nil
	case layoutBare, layoutPage:
		return named, nil
	}
	return "", fmt.Errorf("layout %q is none of %s, %s and %s", named, layoutBare, layoutPage, layoutDocs)
}

func (p *page) check() error {
	var errs []error
	if p.front.Title == "" {
		errs = append(errs, errors.New("title missing"))
	}
	if p.front.Description == "" {
		errs = append(errs, errors.New("description missing"))
	}
	if p.front.Created.IsZero() {
		errs = append(errs, errors.New("created missing"))
	}
	if p.front.Updated.IsZero() {
		errs = append(errs, errors.New("updated missing"))
	}
	if p.front.Updated.Before(p.front.Created) {
		errs = append(errs, fmt.Errorf("updated %s before created %s", p.front.Updated.Format(time.DateOnly), p.front.Created.Format(time.DateOnly)))
	}
	if p.layout == layoutDocs && p.front.Order == nil {
		errs = append(errs, errors.New("order missing, which places a docs page in the navigation"))
	}
	return errors.Join(errs...)
}

// render points every link of the page at where its target is served and
// renders the page. A relative link must name another page by its file, and a
// fragment one of that page's headings.
func (p *page) render(bySrc map[string]*page) []error {
	var errs []error
	ast.Walk(p.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		var dest *[]byte
		switch n := n.(type) {
		case *ast.Link:
			dest = &n.Destination
		case *ast.Image:
			dest = &n.Destination
		}
		if !entering || dest == nil {
			return ast.WalkContinue, nil
		}
		resolved, err := p.resolve(string(*dest), bySrc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.src, err))
			return ast.WalkContinue, nil
		}
		*dest = []byte(resolved)
		return ast.WalkContinue, nil
	})
	var b bytes.Buffer
	if err := markdown.Renderer().Render(&b, p.body, p.root); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", p.src, err))
	}
	p.html = b.String()
	return errs
}

func (p *page) resolve(dest string, bySrc map[string]*page) (string, error) {
	u, err := url.Parse(dest)
	if err != nil {
		return "", fmt.Errorf("link %q: %w", dest, err)
	}
	if u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/") {
		return dest, nil
	}
	target := p
	if u.Path != "" {
		if !strings.HasSuffix(u.Path, pageSuffix) {
			return "", fmt.Errorf("link %q names no page, only %s files are served", dest, pageSuffix)
		}
		var ok bool
		if target, ok = bySrc[path.Join(path.Dir(p.src), u.Path)]; !ok {
			return "", fmt.Errorf("link %q names no page", dest)
		}
	}
	if u.Fragment == "" {
		return target.path, nil
	}
	if !target.ids[u.Fragment] {
		return "", fmt.Errorf("link %q names no heading of %s", dest, target.src)
	}
	if target == p && u.Path == "" {
		return "#" + u.EscapedFragment(), nil
	}
	return target.path + "#" + u.EscapedFragment(), nil
}

// splitFrontmatter cuts the frontmatter from the top of a page.
func splitFrontmatter(b []byte) (front, body []byte, ok bool) {
	rest, ok := bytes.CutPrefix(b, []byte(fence))
	if !ok {
		return nil, nil, false
	}
	i := bytes.Index(rest, []byte("\n"+fence))
	if i < 0 {
		return nil, nil, false
	}
	return rest[:i+1], rest[i+1+len(fence):], true
}

// pagePath is where the page in src is served. Every page is served as a
// directory, so a.md and a/index.md both serve /a/.
func pagePath(src string) string {
	stem := strings.TrimSuffix(src, pageSuffix)
	if stem == pageIndex {
		return "/"
	}
	return "/" + strings.TrimSuffix(stem, "/"+pageIndex) + "/"
}

// docsNav is the docs navigation as current sees it, the pages under docsDir
// in their order with the top level first.
func docsNav(ps []*page, current *page) []pages.Section {
	var docs []*page
	for _, p := range ps {
		if p.layout == layoutDocs {
			docs = append(docs, p)
		}
	}
	section := func(p *page) string {
		if dir := path.Dir(p.src); dir != docsDir {
			return strings.TrimPrefix(dir, docsDir+"/")
		}
		return ""
	}
	slices.SortStableFunc(docs, func(a, b *page) int {
		return cmp.Compare(section(a), section(b))
	})
	var out []pages.Section
	for i, p := range docs {
		if i == 0 || section(p) != section(docs[i-1]) {
			out = append(out, pages.Section{Title: sectionTitle(section(p))})
		}
		s := &out[len(out)-1]
		s.Links = append(s.Links, pages.Link{Title: p.front.Title, Path: p.path, Current: p == current})
	}
	return out
}

// sectionTitle names a docs directory in the navigation after its last element.
func sectionTitle(dir string) string {
	if dir == "" {
		return ""
	}
	name := strings.ReplaceAll(path.Base(dir), "-", " ")
	return strings.ToUpper(name[:1]) + name[1:]
}
