// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ui

import (
	"slices"
	"strings"
	"testing"
)

func TestNewCardTakesTheLargestSizeThatFitsAndBalancesTheLines(t *testing.T) {
	for _, tc := range []struct {
		title string
		size  int
		lines []string
	}{
		{"Configuration reference", 64, []string{"Configuration reference"}},
		// 23 characters a line at 64px, so greedy would leave "machines" alone
		{"How ranet3 picks the fastest path between two machines", 64, []string{"How ranet3 picks the", "fastest path between", "two machines"}},
		{"One fast, private network for every server, GPU and laptop you run.", 52, []string{"One fast, private network", "for every server, GPU and", "laptop you run."}},
	} {
		c, err := NewCard("", tc.title, "")
		if err != nil {
			t.Fatal(err)
		}
		if c.Size != tc.size || !slices.Equal(c.Lines, tc.lines) {
			t.Errorf("NewCard(%q) = %dpx %q, want %dpx %q", tc.title, c.Size, c.Lines, tc.size, tc.lines)
		}
	}
	if _, err := NewCard("", strings.Repeat("word ", 30), ""); err == nil {
		t.Error("NewCard fits a title of 150 characters")
	}
}
