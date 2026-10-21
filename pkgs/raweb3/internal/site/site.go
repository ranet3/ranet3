// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package site loads the sources of ranet3.com and renders every page of it,
// to files for a deploy or on each request while writing.
package site

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/a-h/templ"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/raweb3/internal/pages"
	"ranet3.com/pkgs/raweb3/ui"
)

// config is site.yaml.
type config struct {
	Title      string            `yaml:"title"`
	URL        string            `yaml:"url"`
	Repository string            `yaml:"repository"`
	Metas      map[string]string `yaml:"metas"`
	Analytics  struct {
		Src    string `yaml:"src"`
		Domain string `yaml:"domain"`
	} `yaml:"analytics"`
}

// Site is every source of the site, loaded and checked.
type Site struct {
	ui    ui.Site
	pages []*page
}

// Load reads site.yaml under root and every page under dir, a path relative
// to root. It reports every source that does not hold up rather than the
// first.
func Load(root, dir string) (*Site, error) {
	c, err := loadConfig(filepath.Join(root, configFile))
	if err != nil {
		return nil, err
	}
	s := &Site{ui: ui.Site{
		Name:       c.Title,
		URL:        c.URL,
		Repository: c.Repository,
		Analytics:  ui.Analytics{Src: c.Analytics.Src, Domain: c.Analytics.Domain},
	}}
	for _, name := range slices.Sorted(maps.Keys(c.Metas)) {
		s.ui.Metas = append(s.ui.Metas, ui.Meta{Name: name, Content: c.Metas[name]})
	}
	s.pages, err = loadPages(filepath.Join(root, dir))
	if err != nil {
		return nil, err
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
	for field, v := range map[string]string{
		"title":            c.Title,
		"url":              c.URL,
		"repository":       c.Repository,
		"analytics.src":    c.Analytics.Src,
		"analytics.domain": c.Analytics.Domain,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s: %s missing", path, field))
		}
	}
	// the go command reads the module's repository from these on every page
	for _, name := range []string{"go-import", "go-source"} {
		if c.Metas[name] == "" {
			errs = append(errs, fmt.Errorf("%s: metas.%s missing", path, name))
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
			Updated:     p.front.Updated,
			Unvetted:    p.front.unvetted(),
			Body:        p.html,
		}
		var page templ.Component
		switch p.layout {
		case layoutLanding:
			page = pages.Landing(s.ui, c)
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
