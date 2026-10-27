// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ui

import (
	"errors"
	"fmt"
	"strings"
)

// Card is the text of a page's Open Graph image: an optional label, the title
// broken into lines at a size that fits, a lead in the room the title leaves,
// and an optional line at the bottom.
type Card struct {
	Label string
	Lines []string
	Size  int
	Lead  []string
	Meta  string
}

const (
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

// NewCard breaks title into the fewest lines at the largest size that fits,
// as even in length as the line count allows, as text-wrap: balance does. The
// lead takes as many lines below it as fit, up to 3, cut at a word with an
// ellipsis where it runs longer.
func NewCard(label, title, lead, meta string) (Card, error) {
	words := strings.Fields(title)
	for _, size := range cardSizes {
		limit := chars(size)
		lines := wrap(words, limit)
		if lines == nil || len(lines) > titleLines {
			continue
		}
		for width := 1; width < limit; width++ {
			if l := wrap(words, width); l != nil && len(l) == len(lines) {
				lines = l
				break
			}
		}
		c := Card{Label: strings.ToUpper(label), Lines: lines, Size: size, Meta: meta}
		width := chars(leadSize)
		if c.Lead = wrap(strings.Fields(lead), width); c.Lead == nil && lead != "" {
			return Card{}, errors.New("lead has a word wider than a line of the Open Graph image")
		}
		// at least 1, as 3 title lines at 64px end above leadBottom
		room := min(int((leadBottom-c.leadTop())/(leadLeading*leadSize)), leadLines)
		if len(c.Lead) > room {
			c.Lead = c.Lead[:room]
			c.Lead[room-1] = ellipsize(c.Lead[room-1], width)
		}
		return c, nil
	}
	return Card{}, fmt.Errorf("title takes more than %d lines of the Open Graph image at its smallest size", titleLines)
}

// chars is how many characters a line of the card holds at size pixels.
func chars(size int) int {
	return int(cardWidth / (advance * float64(size)))
}

// TitleY is the baseline of the title's line i.
func (c Card) TitleY(i int) string {
	return baseline(titleTop, float64(c.Size), titleLeading, i)
}

// LeadY is the baseline of the lead's line i.
func (c Card) LeadY(i int) string {
	return baseline(c.leadTop(), leadSize, leadLeading, i)
}

func (c Card) leadTop() float64 {
	return titleTop + titleLeading*float64(c.Size*len(c.Lines)) + leadGap
}

// baseline is the baseline of line i of a box at top, which sits the font's
// ascent below the top of the line, less half of what the leading takes from
// the font's height.
func baseline(top, size, leading float64, i int) string {
	return fmt.Sprintf("%.1f", top+size*(ascent-(height-leading)/2+leading*float64(i)))
}

// ellipsize drops words from the end of line until an ellipsis fits after
// it, and cuts a single word that fills the line.
func ellipsize(line string, width int) string {
	for len([]rune(line))+1 > width {
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			line = string([]rune(line)[:width-1])
			break
		}
		line = line[:i]
	}
	return strings.TrimRight(line, ",;:") + "\u2026"
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
