// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

// logHandler is the daemon's handler on stderr. Where journal, the JOURNAL_STREAM systemd hands a unit, names stderr, each
// line starts with sd-daemon's prefix for its priority, which journald reads as the line's priority.
func logHandler(stderr *os.File, journal string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if !journalStream(journal, stderr) {
		return slog.NewTextHandler(stderr, opts)
	}
	line := &bytes.Buffer{}
	return journalHandler{slog.NewTextHandler(line, opts), line, new(sync.Mutex), stderr}
}

// journalHandler writes each line behind its prefix in one write, so no other writer of the file splits the two
type journalHandler struct {
	slog.Handler
	line *bytes.Buffer
	mu   *sync.Mutex
	w    io.Writer
}

func (h journalHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.line.Reset()
	h.line.WriteString(priority(r.Level))
	if err := h.Handler.Handle(ctx, r); err != nil {
		return err
	}
	_, err := h.w.Write(h.line.Bytes())
	return err
}

func (h journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(attrs)
	return h
}

func (h journalHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(name)
	return h
}

// priority is sd-daemon's prefix for level
func priority(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "<3>"
	case level >= slog.LevelWarn:
		return "<4>"
	case level >= slog.LevelInfo:
		return "<6>"
	}
	return "<7>"
}

// printError writes a command's error to stderr as its last line, behind the error's prefix where journal names stderr
func printError(stderr *os.File, journal string, err error) {
	line := err.Error() + "\n"
	if journalStream(journal, stderr) {
		line = priority(slog.LevelError) + line
	}
	_, _ = stderr.WriteString(line)
}
