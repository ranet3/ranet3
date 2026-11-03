// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// openStream is a file of the test's own in place of stderr, and the JOURNAL_STREAM value naming it
func openStream(t *testing.T, name string) (*os.File, string) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return f, fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

// JOURNAL_STREAM names stderr only by its own device and inode
func TestJournalStreamNamesStderrByDeviceAndInode(t *testing.T) {
	stderr, named := openStream(t, "stderr")
	_, other := openStream(t, "other")
	device, _, _ := strings.Cut(named, ":")
	for name, arm := range map[string]struct {
		value   string
		journal bool
	}{
		"stderr's":                 {named, true},
		"another file's":           {other, false},
		"stderr's inode elsewhere": {"1" + named, false},
		"unset":                    {"", false},
		"the device alone":         {device, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := journalStream(arm.value, stderr); got != arm.journal {
				t.Errorf("JOURNAL_STREAM=%q names stderr %v, want %v", arm.value, got, arm.journal)
			}
		})
	}
}

// Where JOURNAL_STREAM names stderr, each line starts with sd-daemon's prefix for its level, a derived handler's lines
// among them, and elsewhere the lines are slog's text as it writes them
func TestDaemonLogLinesCarryTheirPriorityOnTheJournal(t *testing.T) {
	logged := func(stderr *os.File, journal string) []string {
		t.Helper()
		logger := slog.New(logHandler(stderr, journal, slog.LevelDebug))
		logger.Debug("at debug")
		logger.Info("at info")
		logger.Warn("at warn")
		logger.Error("at error")
		logger.Log(t.Context(), slog.LevelWarn+1, "past warn")
		logger.With("peer", "example/gateway").WithGroup("session").Warn("derived", "spi", 1)
		raw, err := os.ReadFile(stderr.Name())
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	want := []struct{ prefix, msg string }{
		{"<7>", "msg=\"at debug\""},
		{"<6>", "msg=\"at info\""},
		{"<4>", "msg=\"at warn\""},
		{"<3>", "msg=\"at error\""},
		{"<4>", "msg=\"past warn\""},
		{"<4>", "msg=derived peer=example/gateway session.spi=1"},
	}

	stderr, named := openStream(t, "journal")
	lines := logged(stderr, named)
	if len(lines) != len(want) {
		t.Fatalf("the journal's stream got %d lines, want %d:\n%s", len(lines), len(want), strings.Join(lines, "\n"))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, want[i].prefix+"time=") || !strings.Contains(line, want[i].msg) {
			t.Errorf("line %d on the journal's stream is %q, want %s ahead of slog's line holding %s", i, line, want[i].prefix, want[i].msg)
		}
	}

	for name, journal := range map[string]string{"unset": "", "naming another file": named} {
		t.Run(name, func(t *testing.T) {
			stderr, _ := openStream(t, "file")
			lines := logged(stderr, journal)
			if len(lines) != len(want) {
				t.Fatalf("stderr got %d lines, want %d:\n%s", len(lines), len(want), strings.Join(lines, "\n"))
			}
			for i, line := range lines {
				if !strings.HasPrefix(line, "time=") || !strings.Contains(line, want[i].msg) {
					t.Errorf("line %d with JOURNAL_STREAM %s is %q, want slog's line alone holding %s", i, name, line, want[i].msg)
				}
			}
		})
	}
}

// A command's error, the refusal ranet3 reload prints under ExecReload among them, is its own line on stderr, behind the
// error's prefix where JOURNAL_STREAM names stderr
func TestCommandErrorTakesTheErrorPriorityOnTheJournal(t *testing.T) {
	refused := errors.New("control: /v0/reload: 400 Bad Request: refused for the test")
	for name, journal := range map[string]bool{"naming stderr": true, "naming another file": false} {
		t.Run(name, func(t *testing.T) {
			stderr, named := openStream(t, "stderr")
			want := refused.Error() + "\n"
			if journal {
				want = "<3>" + want
			} else {
				_, named = openStream(t, "other")
			}
			printError(stderr, named, refused)
			raw, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != want {
				t.Errorf("stderr with JOURNAL_STREAM %s holds %q, want %q", name, raw, want)
			}
		})
	}
}

// writes keeps each Write it is handed
type writes struct{ each []string }

func (w *writes) Write(p []byte) (int, error) {
	w.each = append(w.each, string(p))
	return len(p), nil
}

// Each line on the journal's stream, a derived handler's among them, reaches the file in one write holding its prefix and
// the whole line, so no other writer of the file comes between the two
func TestDaemonLogLinesReachTheJournalInOneWriteEach(t *testing.T) {
	stderr, named := openStream(t, "journal")
	handler := logHandler(stderr, named, slog.LevelDebug)
	h, ok := handler.(journalHandler)
	if !ok {
		t.Fatalf("the handler on the journal's stream is %T, want the journal's", handler)
	}
	recorded := &writes{}
	h.w = recorded
	logger := slog.New(h)
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	loggers := []*slog.Logger{logger, logger.With("from", "derived")}
	for _, l := range loggers {
		for _, level := range levels {
			l.Log(t.Context(), level, "in one write")
		}
	}
	if want := len(loggers) * len(levels); len(recorded.each) != want {
		t.Errorf("the journal's stream got %d writes, want one for each of the %d lines:\n%q", len(recorded.each), want, recorded.each)
	}
	whole := regexp.MustCompile(`^<[3467]>time=[^\n]+ msg="in one write"( from=derived)?\n$`)
	for _, write := range recorded.each {
		if !whole.MatchString(write) {
			t.Errorf("a write to the journal's stream holds %q, want one prefix ahead of one whole line of slog's", write)
		}
	}
}

// Lines of every priority written to the journal's stream at once, a derived handler's among them, each stay whole behind
// their own prefix, and so does a line another writer of the file writes meanwhile
func TestDaemonLogLinesOfEveryPriorityStayWholeAtOnce(t *testing.T) {
	stderr, named := openStream(t, "journal")
	logger := slog.New(logHandler(stderr, named, slog.LevelDebug))
	levels := map[slog.Level]string{slog.LevelDebug: "<7>", slog.LevelInfo: "<6>", slog.LevelWarn: "<4>", slog.LevelError: "<3>"}
	const each = 500
	var writers sync.WaitGroup
	for level := range levels {
		for _, l := range []*slog.Logger{logger, logger.With("from", "derived")} {
			writers.Go(func() {
				for i := range each {
					l.Log(t.Context(), level, "at once", "line", i)
				}
			})
		}
	}
	writers.Go(func() {
		for range each {
			_, _ = stderr.WriteString("outside\n")
		}
	})
	writers.Wait()
	raw, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if want := len(levels)*2*each + each; len(lines) != want {
		t.Fatalf("the journal's stream got %d lines, want %d", len(lines), want)
	}
	whole := regexp.MustCompile(`^(<[3467]>time=\S+ level=(DEBUG|INFO|WARN|ERROR) msg="at once"( from=derived)? line=\d+|outside)$`)
	broken := 0
	for _, line := range lines {
		if !whole.MatchString(line) {
			if broken++; broken <= 5 {
				t.Errorf("a line on the journal's stream is %q, want one prefix ahead of one whole line of slog's", line)
			}
		}
	}
	for level, prefix := range levels {
		if got := strings.Count(string(raw), prefix+"time="); got != 2*each {
			t.Errorf("the journal's stream holds %d lines behind %s, want the %d at %s", got, prefix, 2*each, level)
		}
	}
}
