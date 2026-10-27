// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

const (
	// configFile names the site's settings, relative to the root
	configFile = "site.yaml"
	// staticDir holds the files served as they are, relative to the root
	staticDir = "static"
	// styleInput is the stylesheet tailwind compiles, relative to the root
	styleInput = "ui/style.css"
	// styleOutput is where the compiled stylesheet is served
	styleOutput = "style.css"
	// docsDir is the directory of the pages directory whose pages take the
	// docs layout and make up its navigation
	docsDir = "docs"
	// indexFile is the file a directory path serves
	indexFile = "index.html"
	// notFoundFile is the page GitHub Pages serves for a path it has no file for
	notFoundFile = "404.html"
	// sitemapFile and robotsFile are served at the root, where crawlers look
	sitemapFile = "sitemap.xml"
	robotsFile  = "robots.txt"
	// pageSuffix marks a page's source file
	pageSuffix = ".md"
	// pageIndex is the stem of the page a directory serves at its own path
	pageIndex = "index"
	// fence opens and closes a page's frontmatter on a line of its own
	fence = "---\n"
	// dirMode and fileMode are the modes of what a build writes
	dirMode  = 0o755
	fileMode = 0o644
)

// mediaTypes are the types of the files the site renders, by extension. A
// file of another extension is a bug of the generator.
var mediaTypes = map[string]string{
	".html": "text/html",
	".xml":  "application/xml",
	".txt":  "text/plain",
}

// layouts a page's frontmatter may name
const (
	layoutBare = "bare"
	layoutPage = "page"
	layoutDocs = "docs"
)
