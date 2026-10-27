// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package pages holds the pages of ranet3.com.
package pages

import "time"

// Content holds what a page of the pages directory renders from.
type Content struct {
	Title       string
	Description string
	// Path is the page's absolute path on the site
	Path string
	// Image is the absolute path of the page's Open Graph image
	Image   string
	Updated time.Time
	// Unvetted puts the notice that the page may contain unreviewed machine
	// generated text on it
	Unvetted bool
	// Body is the page's markdown rendered to HTML
	Body string
	// Nav is the docs navigation, for a docs page only
	Nav []Section
}

// Section is one group of the docs navigation, the top level when Title is empty.
type Section struct {
	Title string
	Links []Link
}

// Link is one entry of the docs navigation.
type Link struct {
	Title   string
	Path    string
	Current bool
}
