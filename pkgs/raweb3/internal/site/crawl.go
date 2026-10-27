// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"encoding/xml"
	"fmt"
	"time"
)

// urlset is a sitemap, https://www.sitemaps.org/protocol.html
type urlset struct {
	XMLName xml.Name     `xml:"urlset"`
	NS      string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod"`
}

// sitemap lists every page of the site with the day it last changed. The 404
// page has no address of its own and is left out.
func (s *Site) sitemap() ([]byte, error) {
	set := urlset{NS: "http://www.sitemaps.org/schemas/sitemap/0.9"}
	for _, p := range s.pages {
		set.URLs = append(set.URLs, sitemapURL{Loc: s.ui.URL + p.path, LastMod: p.front.Updated.Format(time.DateOnly)})
	}
	return marshal(set)
}

// feed is an Atom feed, https://www.rfc-editor.org/rfc/rfc4287
type feed struct {
	XMLName xml.Name `xml:"feed"`
	NS      string   `xml:"xmlns,attr"`
	ID      string   `xml:"id"`
	Title   string   `xml:"title"`
	Updated string   `xml:"updated"`
	Links   []link   `xml:"link"`
	Entries []entry  `xml:"entry"`
}

type entry struct {
	ID        string   `xml:"id"`
	Title     string   `xml:"title"`
	Published string   `xml:"published"`
	Updated   string   `xml:"updated"`
	Link      link     `xml:"link"`
	Authors   []author `xml:"author"`
	Summary   string   `xml:"summary"`
}

type link struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
}

type author struct {
	Name string `xml:"name"`
}

// feed is the Atom feed of every news post, newest first, under the title of
// the page that lists them, updated when that page or a post last was.
func (s *Site) feed(news *page) ([]byte, error) {
	f := feed{
		NS:    "http://www.w3.org/2005/Atom",
		ID:    s.ui.URL + news.path,
		Title: s.ui.Name + " " + news.front.Title,
		Links: []link{{"self", s.ui.URL + "/" + feedFile}, {"alternate", s.ui.URL + news.path}},
	}
	updated := news.front.Updated
	for _, p := range s.posts() {
		e := entry{
			ID:        s.ui.URL + p.path,
			Title:     p.front.Title,
			Published: p.front.Created.Format(time.RFC3339),
			Updated:   p.front.Updated.Format(time.RFC3339),
			Link:      link{"alternate", s.ui.URL + p.path},
			Summary:   p.front.Description,
		}
		for _, name := range p.front.Authors {
			e.Authors = append(e.Authors, author{name})
		}
		f.Entries = append(f.Entries, e)
		if p.front.Updated.After(updated) {
			updated = p.front.Updated
		}
	}
	f.Updated = updated.Format(time.RFC3339)
	return marshal(f)
}

// marshal writes v as an XML document.
func marshal(v any) ([]byte, error) {
	b, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(b, '\n')...), nil
}

// robots lets every crawler read every path and names the sitemap.
func (s *Site) robots() []byte {
	return fmt.Appendf(nil, "User-agent: *\nAllow: /\n\nSitemap: %s/%s\n", s.ui.URL, sitemapFile)
}
