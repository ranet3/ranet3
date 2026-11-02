// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// lines hands each line a log writes to the test that reads it
type lines chan string

func (l lines) Write(p []byte) (int, error) {
	l <- string(p)
	return len(p), nil
}

// a pprof or metrics handler's panic, which the server recovers, is logged at warn, which a log at warn keeps
func TestServedHTTPLogsARecoveredPanicAtWarn(t *testing.T) {
	logged := make(lines, 4)
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serveHTTP(listener, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("a handler's panic") }))
	if response, err := http.Get("http://" + listener.Addr().String() + "/metrics"); err == nil {
		response.Body.Close()
	}
	select {
	case line := <-logged:
		if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "a handler's panic") {
			t.Errorf("a recovered panic left %q in a log at warn", line)
		}
	case <-time.After(stopWithin):
		t.Error("a recovered panic left nothing in a log at warn")
	}
}
