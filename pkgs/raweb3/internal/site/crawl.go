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
	b, err := xml.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(b, '\n')...), nil
}

// robots lets every crawler read every path and names the sitemap.
func (s *Site) robots() []byte {
	return fmt.Appendf(nil, "User-agent: *\nAllow: /\n\nSitemap: %s/%s\n", s.ui.URL, sitemapFile)
}
