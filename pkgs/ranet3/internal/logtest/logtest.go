// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package logtest swaps the default logger for the length of one test. Test
// files import it and nothing else does.
package logtest

import (
	"log"
	"log/slog"
	"testing"
)

// SetDefault makes logger the slog default until tb ends.
//
// slog.SetDefault with a handler other than its own also points the log
// package at that handler and clears its flags, and setting the previous
// default back undoes neither, so the cleanup puts all three back.
func SetDefault(tb testing.TB, logger *slog.Logger) {
	tb.Helper()
	previous, writer, flags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(logger)
	tb.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
}
