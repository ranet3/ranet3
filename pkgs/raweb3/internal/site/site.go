// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package site loads the sources of ranet3.com and renders every page of it,
// to files for a deploy or on each request while writing.
package site

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/a-h/templ"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/raweb3/internal/pages"
	"ranet3.com/pkgs/raweb3/ui"
)

// config is site.yaml. The ui types take their keys from their field names,
// lowercased.
type config struct {
	Title     string            `yaml:"title"`
	URL       string            `yaml:"url"`
	Metas     map[string]string `yaml:"metas"`
	Analytics ui.Analytics      `yaml:"analytics"`
	Nav       []ui.Link         `yaml:"nav"`
	CTA       ui.Link           `yaml:"cta"`
	Footer    ui.Footer         `yaml:"footer"`
}

// Site is every source of the site, loaded and checked.
type Site struct {
	ui    ui.Site
	pages []*page
	// static holds the files served as they are
	static fs.FS
}

// Load reads site.yaml under root and every page under dir, a path relative
// to root. It reports every source that does not hold up rather than the
// first.
func Load(root, dir string) (*Site, error) {
	c, cerr := loadConfig(filepath.Join(root, configFile))
	ps, perr := loadPages(filepath.Join(root, dir))
	if err := errors.Join(cerr, perr); err != nil {
		return nil, err
	}
	s := &Site{static: os.DirFS(filepath.Join(root, staticDir)), pages: ps, ui: ui.Site{
		Name:      c.Title,
		URL:       c.URL,
		Analytics: c.Analytics,
		Nav:       c.Nav,
		CTA:       c.CTA,
		Footer:    c.Footer,
	}}
	for _, name := range slices.Sorted(maps.Keys(c.Metas)) {
		s.ui.Metas = append(s.ui.Metas, ui.Meta{Name: name, Content: c.Metas[name]})
	}
	return s, nil
}

func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	for _, f := range []struct{ name, value string }{
		{"title", c.Title},
		{"url", c.URL},
		{"analytics.src", c.Analytics.Src},
		{"analytics.domain", c.Analytics.Domain},
		{"cta.title", c.CTA.Title},
		{"cta.href", c.CTA.Href},
		{"footer.title", c.Footer.Title},
	} {
		if f.value == "" {
			errs = append(errs, fmt.Errorf("%s: %s missing", path, f.name))
		}
	}
	// the go command reads the module's repository from these on every page
	host := strings.TrimPrefix(c.URL, "https://")
	if f := strings.Fields(c.Metas["go-import"]); len(f) != 3 || f[0] != host || f[1] != "git" || !strings.HasPrefix(f[2], "https://") {
		errs = append(errs, fmt.Errorf("%s: metas.go-import %q wants %s, git and an https repository", path, c.Metas["go-import"], host))
	}
	if len(strings.Fields(c.Metas["go-source"])) != 4 {
		errs = append(errs, fmt.Errorf("%s: metas.go-source %q wants 4 fields", path, c.Metas["go-source"]))
	}
	for i, l := range c.Nav {
		if l.Title == "" || l.Href == "" {
			errs = append(errs, fmt.Errorf("%s: nav entry %d wants a title and an href", path, i+1))
		}
	}
	for _, g := range []struct {
		name  string
		facts []ui.Fact
	}{{"stack", c.Footer.Stack}, {"project", c.Footer.Project}} {
		for i, f := range g.facts {
			if f.Label == "" || len(f.Parts) == 0 {
				errs = append(errs, fmt.Errorf("%s: footer.%s entry %d wants a label and parts", path, g.name, i+1))
			}
			for j, p := range f.Parts {
				if p.Text == "" || p.Cite && p.Href == "" {
					errs = append(errs, fmt.Errorf("%s: footer.%s entry %d part %d wants a text, and an href when it cites", path, g.name, i+1, j+1))
				}
			}
		}
	}
	if strings.HasSuffix(c.URL, "/") {
		errs = append(errs, fmt.Errorf("%s: url %q ends in a slash, which every page path begins with", path, c.URL))
	}
	return c, errors.Join(errs...)
}

// Pages maps each file of the site, relative to its root, to the page it holds.
func (s *Site) Pages() map[string]templ.Component {
	out := map[string]templ.Component{notFoundFile: pages.NotFound(s.ui)}
	for _, p := range s.pages {
		c := pages.Content{
			Title:       p.front.Title,
			Description: p.front.Description,
			Path:        p.path,
			Image:       p.path + ogFile,
			Updated:     p.front.Updated,
			Unvetted:    p.front.unvetted(),
			Body:        p.html,
		}
		var page templ.Component
		switch p.layout {
		case layoutBare:
			page = pages.Bare(s.ui, c)
		case layoutDocs:
			c.Nav = docsNav(s.pages, p)
			page = pages.Docs(s.ui, c)
		default:
			page = pages.Page(s.ui, c)
		}
		out[strings.TrimPrefix(p.path, "/")+indexFile] = page
	}
	return out
}

// Images maps the Open Graph image of each page, relative to the site's root,
// to the SVG it is drawn from.
func (s *Site) Images() map[string]templ.Component {
	out := map[string]templ.Component{}
	for _, p := range s.pages {
		out[strings.TrimPrefix(p.path, "/")+ogFile] = ui.OG(s.ui, p.card)
	}
	return out
}

// siteLink is an href or src that leads to a path on the site.
var siteLink = regexp.MustCompile(`\s(?:href|src)="(/|/[^/"][^"]*)"`)

// Render renders every page of the site, the sitemap and robots.txt to the
// file each is served from. It fails where a link leads to a path the site
// serves nothing at. Loading checks the links of the markdown, and only this
// checks those of the layouts, of site.yaml and of the HTML in a page.
func (s *Site) Render(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	for file, page := range s.Pages() {
		var b bytes.Buffer
		if err := page.Render(ctx, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		out[file] = b.Bytes()
	}
	sitemap, err := s.sitemap()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sitemapFile, err)
	}
	out[sitemapFile] = sitemap
	out[robotsFile] = s.robots()
	var errs []error
	for _, file := range slices.Sorted(maps.Keys(out)) {
		for _, m := range siteLink.FindAllSubmatch(out[file], -1) {
			if !s.serves(out, string(m[1])) {
				errs = append(errs, fmt.Errorf("%s: link %q leads to nothing the site serves", file, m[1]))
			}
		}
	}
	return out, errors.Join(errs...)
}

// serves says whether the site serves anything at the path link leads to,
// given its rendered pages.
func (s *Site) serves(rendered map[string][]byte, link string) bool {
	p, _, _ := strings.Cut(link, "#")
	p, _, _ = strings.Cut(p, "?")
	file := strings.TrimPrefix(p, "/")
	if file == "" || strings.HasSuffix(file, "/") {
		file += indexFile
	}
	if _, ok := rendered[file]; ok || file == styleOutput {
		return true
	}
	return fs.ValidPath(file) && isFile(s.static, file)
}

// mediaType is the type of a file the site renders.
func mediaType(file string) (string, error) {
	kind, ok := mediaTypes[path.Ext(file)]
	if !ok {
		return "", fmt.Errorf("%s: the site renders no %q files", file, path.Ext(file))
	}
	return kind, nil
}
