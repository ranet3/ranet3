// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ui

const (
	// OGWidth and OGHeight are the size of the Open Graph image ui draws and
	// the page head declares, which a page's own image matches
	OGWidth, OGHeight = 1200, 630
	// cardWidth is the width of the title and the lead, from the 72px margin
	// on the left
	cardWidth = 900
	// titleLines and leadLines are the most lines each takes
	titleLines, leadLines = 3, 3
	// Noto Sans Mono's width of every Latin glyph, and its ascent and
	// height, in em
	advance, ascent, height = 0.6, 1.069, 1.362
	titleTop, titleLeading  = 232, 1.12
	leadSize, leadLeading   = 28, 1.4
	// leadGap is the space between the title and the lead, and leadBottom
	// where the lead ends, above the meta line
	leadGap, leadBottom = 20, 540
)

// cardSizes are the title's font sizes in pixels, the largest that fits taken
var cardSizes = []int{64, 52, 44}
