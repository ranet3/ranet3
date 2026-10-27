// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	img "image"
	_ "image/jpeg"
	_ "image/png"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/raweb3/internal/pages"
	"ranet3.com/pkgs/raweb3/ui"
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
	// Authors wrote a news post, which names at least one
	Authors []string `yaml:"authors"`
	// Vetted is the day a person last read the page in full, set by hand
	// only and never shown. A page without it, or changed since, carries a
	// notice that it may contain unreviewed machine generated text
	Vetted time.Time `yaml:"vetted"`
	// OG overrides the text of the page's Open Graph image, a field left
	// empty taking what the page derives
	OG struct {
		Label string `yaml:"label"`
		Title string `yaml:"title"`
		Meta  string `yaml:"meta"`
		// Image names a file beside the page, 1200 by 630, used in place of
		// the drawn one
		Image string `yaml:"image"`
	} `yaml:"og"`
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
	// card is the text drawn on the page's Open Graph image, and image the
	// path of the file used in its place, if any
	card  ui.Card
	image string
	// minutes is how long the page takes to read
	minutes int

	body []byte
	root ast.Node
	// ids are the fragments the page's headings answer to
	ids map[string]bool
}

var markdown = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(
		html.WithUnsafe(),
		// ahead of goldmark's own renderer at 1000
		renderer.WithNodeRenderers(util.Prioritized(highlighter{}, 100)),
	),
)

// components are the ui components a page places with an empty element of
// their name, such as <ui-ascii-mark></ui-ascii-mark>
var components = map[string]templ.Component{
	"ascii-mark": ui.ASCIIMark(),
}

var componentTag = regexp.MustCompile(`<ui-([a-z0-9-]+)></ui-([a-z0-9-]+)>`)

// loadPages reads and renders every page under dir. Every page is parsed
// before any is rendered, since a link is checked against the headings of the
// page it names. A file under dir that is no page is served as it is.
func loadPages(dir string) ([]*page, error) {
	var ps []*page
	var errs []error
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, pageSuffix) {
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
	files := os.DirFS(dir)
	for _, pg := range ps {
		errs = append(errs, pg.render(bySrc, files)...)
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
	if strings.HasPrefix(src, newsDir+"/") {
		switch {
		case named != "":
			return "", fmt.Errorf("layout %s under %s/, where the place of a page decides it", named, newsDir)
		case src == newsDir+"/"+pageIndex+pageSuffix:
			return layoutNews, nil
		}
		return layoutPost, nil
	}
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
	if p.layout == layoutPost && len(p.front.Authors) == 0 {
		errs = append(errs, errors.New("authors missing"))
	}
	if p.layout == layoutDocs && p.front.Order == nil {
		errs = append(errs, errors.New("order missing, which places a docs page in the navigation"))
	}
	return errors.Join(errs...)
}

// render points every link of the page at where its target is served, makes
// every table focusable, since a table wider than the page scrolls and a
// keyboard has to reach it, and renders the page. A relative link must name
// another page by its file, and a fragment one of that page's headings, or
// one of the files beside the pages.
func (p *page) render(bySrc map[string]*page, files fs.FS) []error {
	var errs []error
	ast.Walk(p.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		var dest *[]byte
		switch n := n.(type) {
		case *ast.Link:
			dest = &n.Destination
		case *ast.Image:
			dest = &n.Destination
		case *extast.Table:
			if entering {
				n.SetAttributeString("tabindex", []byte("0"))
			}
		}
		if !entering || dest == nil {
			return ast.WalkContinue, nil
		}
		resolved, err := p.resolve(string(*dest), bySrc, files)
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
	out, err := place(b.String())
	if err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", p.src, err))
	}
	p.html = out
	// at 200 words a minute of the rendered text
	p.minutes = max(1, (len(strings.Fields(htmlTag.ReplaceAllString(p.html, "")))+100)/200)
	if p.front.OG.Image != "" {
		err = p.imageOf(files)
	} else {
		err = p.newCard()
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", p.src, err))
	}
	return errs
}

// htmlTag is an HTML tag, dropped to count the words a page shows
var htmlTag = regexp.MustCompile(`<[^>]*>`)

// newCard sets the text of the page's Open Graph image. A page of prose and a
// docs page carry the day they last changed at the bottom, a news post its
// day and reading time.
func (p *page) newCard() error {
	label, meta := p.front.OG.Label, ""
	switch p.layout {
	case layoutDocs:
		label = cmp.Or(label, "Docs")
		meta = "Updated " + p.front.Updated.Format(pages.DateFormat)
	case layoutPage:
		meta = "Updated " + p.front.Updated.Format(pages.DateFormat)
	case layoutPost:
		label = cmp.Or(label, "News")
		meta = fmt.Sprintf("%s \u00b7 %d min read", p.front.Created.Format(pages.DateFormat), p.minutes)
	}
	var err error
	p.card, err = ui.NewCard(label, cmp.Or(p.front.OG.Title, p.front.Title), p.front.Description, cmp.Or(p.front.OG.Meta, meta))
	return err
}

// imageOf checks the file beside the page its frontmatter names as its Open
// Graph image, in place of the drawn one.
func (p *page) imageOf(files fs.FS) error {
	file := path.Join(path.Dir(p.src), p.front.OG.Image)
	if !fs.ValidPath(file) || hidden(file) {
		return fmt.Errorf("og.image %q names no file beside the pages", p.front.OG.Image)
	}
	f, err := files.Open(file)
	if err != nil {
		return fmt.Errorf("og.image: %w", err)
	}
	defer f.Close()
	if c, _, err := img.DecodeConfig(f); err != nil || c.Width != 1200 || c.Height != 630 {
		return fmt.Errorf("og.image %s is no PNG or JPEG of 1200 by 630", file)
	}
	p.image = "/" + file
	return nil
}

// place renders each component the page's HTML names in place of its
// element. Rendered markdown carries a raw < only in markup, so a <ui- left
// over is an element that is not empty.
func place(rendered string) (string, error) {
	var errs []error
	out := componentTag.ReplaceAllStringFunc(rendered, func(tag string) string {
		m := componentTag.FindStringSubmatch(tag)
		if m[1] != m[2] {
			errs = append(errs, fmt.Errorf("<ui-%s> closes as </ui-%s>", m[1], m[2]))
			return ""
		}
		c, ok := components[m[1]]
		if !ok {
			errs = append(errs, fmt.Errorf("%s names no component", tag))
			return ""
		}
		var b strings.Builder
		if err := c.Render(context.Background(), &b); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", tag, err))
		}
		return b.String()
	})
	if len(errs) == 0 && strings.Contains(out, "<ui-") {
		errs = append(errs, errors.New("a <ui-> element holds content, and a component takes none"))
	}
	return out, errors.Join(errs...)
}

func (p *page) resolve(dest string, bySrc map[string]*page, files fs.FS) (string, error) {
	u, err := url.Parse(dest)
	if err != nil {
		return "", fmt.Errorf("link %q: %w", dest, err)
	}
	if u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/") {
		return dest, nil
	}
	target := p
	if u.Path != "" {
		file := path.Join(path.Dir(p.src), u.Path)
		if !strings.HasSuffix(file, pageSuffix) {
			if !fs.ValidPath(file) || !isFile(files, file) {
				return "", fmt.Errorf("link %q names no file beside the pages", dest)
			}
			u.Path, u.RawPath = "/"+file, ""
			return u.String(), nil
		}
		var ok bool
		if target, ok = bySrc[file]; !ok {
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
