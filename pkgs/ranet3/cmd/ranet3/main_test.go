// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// stopWithin bounds a wait on a part of the daemon's start or stop, long past one that ends
const stopWithin = 5 * time.Second

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
			go watchSignals(make(chan struct{}), signals, cancel, func() { close(forced) })

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
// reads to leave the kill switch, and fails the exit status. A stop
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

// The node refuses up, reload and redial before the run's context ends for the stop, so none starts as the stop withdraws,
// and the cause reaches the context
func TestStopRefusesTheVerbsBeforeTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var refused, endedFirst bool
	stopFor(func() { refused, endedFirst = true, ctx.Err() != nil }, cancel)(kernel.ErrMeshFailed)
	if !refused || endedFirst {
		t.Errorf("the node refused the verbs %v, after the run's context ended %v, want before", refused, endedFirst)
	}
	if cause := context.Cause(ctx); cause != kernel.ErrMeshFailed {
		t.Errorf("the stop ended the context for %v, want %v", cause, kernel.ErrMeshFailed)
	}
}

// The stop begins on the node, a verb running ended and the rest refused, before daemon.stopping reaches the stream, and the
// stream ends after it
func TestStopBeginsBeforeItIsAnnounced(t *testing.T) {
	bus := events.New()
	announced := func() int {
		return len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "daemon.stopping" }, 0))
	}
	begun := -1
	announceStop(func() { begun = announced() }, bus)
	if begun != 0 {
		t.Errorf("the stop began with daemon.stopping recorded %d times, want none yet", begun)
	}
	if got := announced(); got != 1 {
		t.Errorf("daemon.stopping was recorded %d times, want once", got)
	}
}

// The start dials once the first pass it waits for has ended, at once where it waits for none, and never once its stop has
// begun, whether the stop came during the wait or before it
func TestFirstPassWaitDialsOnlyWhileTheStartRuns(t *testing.T) {
	ended := make(chan struct{})
	close(ended)
	for name, arm := range map[string]struct {
		firstPass <-chan struct{}
		stopped   bool
		dials     bool
	}{
		"the pass ended":                 {ended, false, true},
		"no pass waited for":             {nil, false, true},
		"a stop in the wait":             {make(chan struct{}), true, false},
		"a stop with no pass waited for": {nil, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if arm.stopped {
				cancel()
			}
			answered := make(chan bool, 1)
			go func() { answered <- awaitFirstPass(ctx, arm.firstPass, firstPassWait) }()
			select {
			case dials := <-answered:
				if dials != arm.dials {
					t.Errorf("the start dials %v, want %v", dials, arm.dials)
				}
			case <-time.After(stopWithin):
				t.Fatal("the wait did not end")
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

// notDaemon is the directories of the module no daemon is built from: the generator under internal/cmd,
// and the packages only tests import
var notDaemon = []string{"internal/cmd", "internal/dnstest", "internal/egress/egresstest", "internal/goldentest", "internal/logtest", "internal/netnstest"}

// daemonSources parses, as far as mode asks, every non-test file of the module but those of notDaemon and of testdata
func daemonSources(tb testing.TB, mode parser.Mode) (*token.FileSet, []*ast.File) {
	tb.Helper()
	root := filepath.Join("..", "..")
	files := token.NewFileSet()
	var parsed []*ast.File
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		dir, _ := filepath.Rel(root, path)
		switch {
		case err != nil:
			return err
		case entry.IsDir() && (slices.Contains(notDaemon, filepath.ToSlash(dir)) || entry.Name() == "testdata"):
			return filepath.SkipDir
		case entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		file, err := parser.ParseFile(files, path, nil, mode|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		parsed = append(parsed, file)
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	if len(parsed) == 0 {
		tb.Fatal("the walk read no source")
	}
	return files, parsed
}

// the standard logger writes through slog at INFO, which --log-level warn drops, so a failure or a warning sent there goes unwritten
// an import of log in any of the daemon's sources fails
func TestDaemonPackagesAvoidTheStandardLogger(t *testing.T) {
	files, parsed := daemonSources(t, parser.ImportsOnly)
	for _, file := range parsed {
		for _, spec := range file.Imports {
			if spec.Path.Value == `"log"` {
				t.Errorf("%s imports log, whose standard logger writes at INFO", files.Position(spec.Pos()))
			}
		}
	}
}

// a message tells no one to add cap.egress, cap.exit or cap.table, each of which some platform refuses, and
// builds no instruction to add a block from parts
func TestNoMessageSaysToAddABlockAPlatformRefuses(t *testing.T) {
	files, parsed := daemonSources(t, 0)
	instruction := regexp.MustCompile(`\badd cap\.(egress|exit|table)\b|\badd $|\badd %`)
	for _, file := range parsed {
		ast.Inspect(file, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				if text, err := strconv.Unquote(literal.Value); err == nil && instruction.MatchString(text) {
					t.Errorf("%s: %q says to add a block", files.Position(literal.Pos()), text)
				}
			}
			return true
		})
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
	// and so is the failure to undo a start, which exits 1 as well
	if !logged("kernel", errors.New("kernel: delete rule 1000: operation not permitted")) {
		t.Error("a close that failed was reported as one that did not")
	}
	if !strings.Contains(written.String(), "delete rule 1000") {
		t.Errorf("a close that failed at --log-level error wrote %q", written.String())
	}
	// and so is a second signal, which gives up on the shutdown with 1
	signals := make(chan os.Signal, 2)
	signals <- os.Interrupt
	signals <- os.Interrupt
	watchSignals(make(chan struct{}), signals, func() {}, func() {})
	if !strings.Contains(written.String(), "second signal") {
		t.Errorf("a second signal at --log-level error wrote %q", written.String())
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
	listener, err := bindControl(parsed.controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go control.Serve(listener, &client.Client{})
	response, err := control.Dial(socket).Raw(t.Context(), http.MethodGet, control.PathDebugRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("the daemon's socket answered a debug read with %s", response.Status)
	}
}
