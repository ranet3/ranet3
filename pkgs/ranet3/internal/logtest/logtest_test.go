// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package logtest

import (
	"io"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// a later test's log.Printf reaches the writer the log package had before the swap, with its flags
func TestLogPackageGetsItsWriterAndFlagsBack(t *testing.T) {
	var before strings.Builder
	writer, flags := log.Writer(), log.Flags()
	log.SetOutput(&before)
	log.SetFlags(log.Lmicroseconds)
	t.Cleanup(func() {
		log.SetOutput(writer)
		log.SetFlags(flags)
	})

	t.Run("swap", func(t *testing.T) {
		SetDefault(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
		log.Print("swallowed")
	})
	log.Print("after the swap")

	if got := before.String(); strings.Contains(got, "swallowed") || !strings.Contains(got, "after the swap") {
		t.Errorf("the log package wrote %q, want only the line printed after the swap", got)
	}
	if got := log.Flags(); got != log.Lmicroseconds {
		t.Errorf("the log package's flags are %d after the swap, want %d", got, log.Lmicroseconds)
	}
}
