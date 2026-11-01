// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// The first signal starts the shutdown and the second gives up on it. An
// earlier shape registered the second channel only after the first signal had
// canceled the context, which left a window where a signal reached nobody:
// two with no gap lost the second and the process sat through the whole
// shutdown. Registering up front instead delivered the first signal to both
// readers, so the first Ctrl-C forced an exit rather than shutting down. One
// channel read in order has neither, and a burst is held by the buffer.
func TestFirstSignalShutsDownAndTheSecondGivesUp(t *testing.T) {
	for name, gap := range map[string]bool{"a burst of two": false, "one then another": true} {
		t.Run(name, func(t *testing.T) {
			signals := make(chan os.Signal, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			forced := make(chan struct{})
			go watchSignals(signals, cancel, func() { close(forced) })

			signals <- os.Interrupt
			if gap {
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("the first signal did not start the shutdown")
				}
				select {
				case <-forced:
					t.Fatal("the first signal gave up on the shutdown instead of starting it")
				case <-time.After(50 * time.Millisecond):
				}
			}
			signals <- os.Interrupt
			select {
			case <-forced:
			case <-time.After(5 * time.Second):
				t.Fatal("the second signal was lost, so the shutdown runs to completion with nothing to interrupt it")
			}
			if ctx.Err() == nil {
				t.Error("the shutdown was never started")
			}
		})
	}
}

// The border withdraws only once the reconciler and the translator have
// withdrawn, which they start on the cancel, so no route into the tun outlives
// the filter. The two owners are a recording fake around the WaitGroup main
// waits on.
func TestShutdownWithdrawsTheBorderLast(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, step)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var owners sync.WaitGroup
	for _, owner := range []string{"reconciler", "translator"} {
		owners.Go(func() {
			<-ctx.Done()
			record(owner + " withdrew")
		})
	}
	wait := func() {
		owners.Wait()
		record("both waited for")
	}
	stopInOrder(cancel, wait, func() { record("the antispoof filter withdrew") })
	if len(order) != 4 || order[2] != "both waited for" || order[3] != "the antispoof filter withdrew" {
		t.Errorf("the shutdown ran %v, want the antispoof filter to withdraw after the reconciler and the translator", order)
	}
}

// The mesh's failure cancels for kernel.ErrMeshFailed, which the reconciler
// reads to leave the kill switch's table, and fails the exit status. A stop
// that ends ctx with the mesh still up, a signal's, returns with neither.
func TestMeshFailureCancelsForItsCause(t *testing.T) {
	for name, failure := range map[string]bool{"the failure": true, "a signal": false} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			meshFailed := make(chan struct{})
			want := error(kernel.ErrMeshFailed)
			if failure {
				close(meshFailed)
			} else {
				cancel(nil)
				want = context.Canceled
			}
			var failed atomic.Bool
			returned := make(chan struct{})
			go func() {
				cancelOnMeshFailure(ctx, meshFailed, &failed, cancel)
				close(returned)
			}()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("cancelOnMeshFailure did not return")
			}
			if cause := context.Cause(ctx); cause != want || failed.Load() != failure {
				t.Errorf("the stop's cause is %v with the exit status failed %v, want %v and %v", cause, failed.Load(), want, failure)
			}
		})
	}
}

// `ranet3 daemon config.yaml`, one missing dash, otherwise starts against
// the default path and reports nothing: the node comes up with a
// configuration nobody asked for. An unreadable --log-level is the same shape.
func TestDaemonRefusesWhatItCannotActOn(t *testing.T) {
	for name, args := range map[string][]string{
		"a positional argument": {"daemon", "config.yaml"},
		"one after a flag":      {"daemon", "--config", "/etc/x.yaml", "extra"},
		"an unreadable level":   {"daemon", "--log-level", "chatty"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := execute(t, args...); err == nil {
				t.Errorf("%q was accepted", args)
			}
		})
	}

	// --help is a request cobra answers by writing the usage. Reported as a
	// failure it exits nonzero on a question that was answered.
	usage, err := execute(t, "daemon", "--help")
	if err != nil {
		t.Errorf("asking for help failed: %v", err)
	}
	for _, want := range []string{"--config", "--log-level", "--metrics", "--state-dir"} {
		if !strings.Contains(usage, want) {
			t.Errorf("the usage does not name %s: %q", want, usage)
		}
	}
}

// no flag of the command tree decides who may use the debug paths, so the daemon refuses --debug-access as unknown
// the empty --state-dir refuses the start before the node runs, should the flag ever be taken
func TestDebugAccessIsAnUnknownFlag(t *testing.T) {
	if _, err := execute(t, "daemon", "--debug-access", "root", "--state-dir", ""); err == nil || !strings.Contains(err.Error(), "unknown flag: --debug-access") {
		t.Errorf("daemon --debug-access root ended with %v", err)
	}
}

// log.Fatal is os.Exit, which a test cannot observe, so this reads the source.
// The helper existing is not the fix: a call site that still reports through
// the standard logger exits 1 saying nothing at a production level.
func TestStartupRefusalsAvoidTheStandardLogger(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("log.Fatal")) {
		t.Error("main.go still exits through log.Fatal, which writes at INFO and vanishes at --log-level warn")
	}
}

// The same rule from the other side: a refusal at --log-level error is written.
// See refuseToStart.
func TestStartupRefusalsSurviveAProductionLogLevel(t *testing.T) {
	var written strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&written, &slog.HandlerOptions{Level: slog.LevelError})))

	if code := refuseToStart(errors.New("config: read /nonexistent.yaml")); code == 0 {
		t.Error("a refusal reported success")
	}
	if !strings.Contains(written.String(), "/nonexistent.yaml") {
		t.Errorf("a refusal at --log-level error wrote %q", written.String())
	}
}

// the socket the daemon serves answers the node's debug paths
func TestServeControlAnswersTheDebugPaths(t *testing.T) {
	var parsed options
	daemon := daemonCommand(func(o options) int {
		parsed = o
		return 0
	})
	socket := socketPath(t)
	daemon.SetArgs([]string{"--control", socket})
	if err := daemon.Execute(); err != nil {
		t.Fatal(err)
	}
	var failed atomic.Bool
	listener, err := serveControl(parsed, &client.Client{}, &failed)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	response, err := control.Dial(socket).Raw(t.Context(), http.MethodGet, control.PathDebugRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("the daemon's socket answered a debug read with %s", response.Status)
	}
}
