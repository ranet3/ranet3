// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"log/slog"
	"slices"
	"strings"
	"sync"
)

// eventLog keeps each event a hub or a bind records as its kind and attributes on one line
type eventLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *eventLog) record(kind string, attrs ...slog.Attr) {
	line := []string{kind}
	for _, attr := range attrs {
		line = append(line, attr.String())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, strings.Join(line, " "))
}

func (l *eventLog) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}
