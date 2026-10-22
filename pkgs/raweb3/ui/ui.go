// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package ui holds the components and the stylesheet every ranet3 web page
// shares, whichever site or service renders it.
package ui

// Site holds what every page says about the site it belongs to.
type Site struct {
	Name       string
	URL        string
	Repository string
	// Metas go on every page in this order, the 404 page included
	Metas     []Meta
	Analytics Analytics
	// Nav are the links of every page's header
	Nav []Link
	// Footer ends every page, with CTA's button beside its title
	CTA    Link
	Footer Footer
}

// Footer is a title beside the button, above the facts of the protocol stack
// and those of the project.
type Footer struct {
	Title   string
	Stack   []Fact
	Project []Fact
}

// Fact is a label and its text, in parts joined by spaces.
type Fact struct {
	Label string
	Parts []Part
}

// Part is a run of text, a link when Href is set. A cited part links the
// standard the text before it follows, set in parentheses.
type Part struct {
	Text string
	Href string
	Cite bool
}

// Link is a title and the address it leads to.
type Link struct {
	Title string
	Href  string
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
