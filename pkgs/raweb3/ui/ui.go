// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package ui holds the components and the stylesheet every ranet3 web page
// shares, whichever site or service renders it.
package ui

import _ "embed"

// logo is the ASCII logo's markup, kept out of templ, which would collapse its
// whitespace
//
//go:embed logo.html
var logo string

// Site holds what every page says about the site it belongs to.
type Site struct {
	Name       string
	URL        string
	Repository string
	// Metas go on every page in this order, the 404 page included
	Metas     []Meta
	Analytics Analytics
}

// Meta is one name and content pair of a meta element.
type Meta struct {
	Name    string
	Content string
}

// Analytics names the script that counts visits and the domain it counts them under.
type Analytics struct {
	Src    string
	Domain string
}

// Page holds what the head of one page says about it.
type Page struct {
	Title       string
	Description string
	// Path is the page's absolute path on the site, empty for a page that has
	// no address of its own and must not be indexed, such as the 404 page
	Path string
}
