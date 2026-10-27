// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ui

import (
	"errors"
	"strings"
)

// Card is the text of a page's Open Graph image: an optional label, the title
// broken into lines at a size that fits, and an optional line below.
type Card struct {
	Label string
	Lines []string
	Size  int
	Meta  string
}

const (
	// cardWidth is the title's box, inside the 72px margin on either side
	cardWidth = 900
	// cardLines is the most lines a title takes
	cardLines = 3
	// advance is Noto Sans Mono's width of every Latin glyph, in em
	advance = 0.6
)

// cardSizes are the title's font sizes in pixels, the largest that fits taken
var cardSizes = []int{64, 52, 44}

// NewCard breaks title into the fewest lines at the largest size that fits,
// as even in length as the line count allows, as text-wrap: balance does.
func NewCard(label, title, meta string) (Card, error) {
	words := strings.Fields(title)
	for _, size := range cardSizes {
		limit := int(cardWidth / (advance * float64(size)))
		lines := wrap(words, limit)
		if lines == nil || len(lines) > cardLines {
			continue
		}
		for width := 1; width < limit; width++ {
			if l := wrap(words, width); l != nil && len(l) == len(lines) {
				lines = l
				break
			}
		}
		return Card{Label: strings.ToUpper(label), Lines: lines, Size: size, Meta: meta}, nil
	}
	return Card{}, errors.New("title takes more than 3 lines of the Open Graph image at its smallest size")
}

// wrap breaks words into lines of at most width characters, nil when a word
// is wider.
func wrap(words []string, width int) []string {
	var lines []string
	for _, w := range words {
		n := len([]rune(w))
		if n > width {
			return nil
		}
		if last := len(lines) - 1; last >= 0 && len([]rune(lines[last]))+1+n <= width {
			lines[last] += " " + w
		} else {
			lines = append(lines, w)
		}
	}
	return lines
}
