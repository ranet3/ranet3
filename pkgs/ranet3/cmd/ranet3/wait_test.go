// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// daemonSettle bounds a wait for what the daemon does once asked, and for the goroutines of a start to end
const daemonSettle = 10 * time.Second

// waitHeld is how long a test keeps a file from a start that waits for it, two of the wait's looks
const waitHeld = 2 * authPoll

// pendingTries is how many connections a test leaves at the handover as a turn ends, since a select that may take one picks
// it at even odds, and pendingHeld how long it leaves each before the turn ends
const (
	pendingTries = 200
	pendingHeld  = 5 * time.Millisecond
)

// acceptWithin is the connection listener's Accept takes, failing t where it takes none within daemonSettle
func acceptWithin(t *testing.T, what string, listener net.Listener) net.Conn {
	t.Helper()
	took := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		took <- accepted{conn, err}
	}()
	select {
	case a := <-took:
		if a.err != nil {
			t.Fatalf("%s took no connection: %v", what, a.err)
		}
		return a.conn
	case <-time.After(daemonSettle):
		t.Fatalf("%s took no connection within %s", what, daemonSettle)
		return nil
	}
}

// goroutines is the stack of each goroutine, behind its status line
func goroutines() []string {
	stacks := make([]byte, 1<<20)
	return strings.Split(string(stacks[:runtime.Stack(stacks, true)]), "\n\n")
}

// stackName is the name a goroutine's stack gives the function fn, behind its package's import path
func stackName(fn any) string {
	return runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
}

// running reports whether a goroutine runs the function fn or was started by it
func running(fn any) bool {
	return slices.ContainsFunc(goroutines(), func(g string) bool { return strings.Contains(g, stackName(fn)) })
}

// offering reports whether a handover's goroutine is blocked in its offer of a connection it accepted, the select between a
// turn's receive and the socket's close
func offering() bool {
	return slices.ContainsFunc(goroutines(), func(g string) bool {
		status, _, _ := strings.Cut(g, "\n")
		return strings.Contains(status, " [select") && strings.Contains(g, "created by "+stackName(newHandover)+" ")
	})
}

// shortDir is a directory of the test's own directly under the temporary directory, whose path leaves a socket in it short
// enough for control.Listen, which t.TempDir's, named after the test, can pass
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ranet3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// signalSelf sends sig to this process and returns once os/signal has handed it to a channel of the test's own, which it hands
// the daemon's in the same delivery
func signalSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	seen := make(chan os.Signal, 1)
	signal.Notify(seen, sig)
	defer signal.Stop(seen)
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(daemonSettle):
		t.Fatalf("%s was not delivered", sig)
	}
}

// lockedLog keeps what a log writes from any goroutine
type lockedLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

// waitTill polls done until it holds, failing t after daemonSettle
func waitTill(t *testing.T, what string, done func() bool) {
	t.Helper()
	waitWithin(t, what, daemonSettle, done)
}

// waitWithin polls done until it holds, failing t after within
func waitWithin(t *testing.T, what string, within time.Duration, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// logTo has the default logger write into a log of the test's own until the test ends
func logTo(t *testing.T) *lockedLog {
	logged := &lockedLog{}
	was := slog.Default()
	t.Cleanup(func() { slog.SetDefault(was) })
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, nil)))
	return logged
}

// waitingStart is a node's file naming a key and a trust document in a directory of the test's own, the one field names
// missing, the path it names, and the stages of a start whose node, the first part to read the two files, hands reached
// the config it was built from and refuses. None of it needs root.
func waitingStart(t *testing.T, field string) (opts options, missing string, s stages, reached <-chan *config.Config) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"auth.key": filepath.Join(dir, "key.pem"), "auth.trust": filepath.Join(dir, "trust.json")}
	for name, path := range files {
		if name == field {
			continue
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := fmt.Sprintf(`node: example/start
auth:
  key: %s
  trust: %s
link:
  port: 14000
  listen: true
  endpoints:
    - serial: "0"
      family: ip4
`, files["auth.key"], files["auth.trust"])
	opts = options{configPath: filepath.Join(dir, "config.yaml"), stateDir: filepath.Join(dir, "state")}
	if err := os.WriteFile(opts.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	built := make(chan *config.Config, 1)
	s = production
	s.node = func(cfg *config.Config, _ *events.Bus) (*client.Client, error) {
		built <- cfg
		return nil, errors.New("refused once built for the test")
	}
	s.force = func() {}
	return opts, files[field], s, built
}

// rewrite replaces each old of pairs with the new after it in the file at path
func rewrite(t *testing.T, path string, pairs ...string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.NewReplacer(pairs...).Replace(string(body))), 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitLines counts the lines the wait logged for field, as it began and once the file was there
func waitLines(logged *lockedLog, field string) (began, ended int) {
	text := logged.String()
	return strings.Count(text, `msg="waiting for a file the config names to exist" field=`+field+" "),
		strings.Count(text, `msg="a file the start waited for exists" field=`+field+" ")
}

// built is the config the start built the node from, failing t where it builds none within daemonSettle
func built(t *testing.T, reached <-chan *config.Config, what string) *config.Config {
	t.Helper()
	select {
	case cfg := <-reached:
		return cfg
	case <-time.After(daemonSettle):
		t.Fatalf("the start did not build the node once %s", what)
		return nil
	}
}

// notBuilt fails t where the start built the node by now
func notBuilt(t *testing.T, reached <-chan *config.Config, what string) {
	t.Helper()
	select {
	case <-reached:
		t.Fatalf("the start built the node with %s", what)
	default:
	}
}

// A start whose key or trust document is missing waits for it across its looks, building no node, logs the wait once as it
// begins, and goes on to build the node once the file is there, logging that once
func TestDaemonWaitsForAMissingKeyOrTrustDocument(t *testing.T) {
	for _, field := range []string{"auth.key", "auth.trust"} {
		t.Run(field, func(t *testing.T) {
			logged := logTo(t)
			opts, missing, s, reached := waitingStart(t, field)
			code := make(chan int, 1)
			go func() { code <- startDaemon(opts, s) }()
			waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, field); return began != 0 })
			time.Sleep(waitHeld)
			notBuilt(t, reached, field+" missing")
			if err := os.WriteFile(missing, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			built(t, reached, field+" was there")
			if got := <-code; got != 1 {
				t.Errorf("the start whose node refused exited %d", got)
			}
			if began, ended := waitLines(logged, field); began != 1 || ended != 1 {
				t.Errorf("the wait for %s logged its start %d times and its end %d times, want once each:\n%s", field, began, ended, logged.String())
			}
		})
	}
}

// A file rewritten while the start waits is the one the build takes: the wait goes on for the key the new file names rather
// than the one the file named as it began, and the node is built from the new file
func TestDaemonBuildsFromTheConfigAsTheWaitLastReadIt(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, "auth.key"); return began != 0 })
	moved := filepath.Join(filepath.Dir(missing), "moved.pem")
	rewrite(t, opts.configPath, "port: 14000", "port: 14001", missing, moved)
	waitTill(t, "the wait for the key the new file names", func() bool { began, _ := waitLines(logged, "auth.key"); return began == 2 })
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(waitHeld)
	notBuilt(t, reached, "the key the file names no longer and the one it names now missing")
	if err := os.WriteFile(moved, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := built(t, reached, "the key the new file names was there")
	<-code
	if cfg.Link.Port != 14001 || cfg.Auth.Key != moved {
		t.Errorf("the node was built from link.port %d and auth.key %s, want the new file's 14001 and %s", cfg.Link.Port, cfg.Auth.Key, moved)
	}
}

// A file the loader refuses as the wait ends refuses the start, as it refuses a start that reads it first, and the wait for
// the key it names goes on while it is refused
func TestDaemonRefusedByTheFileTheWaitLastRead(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, "auth.key"); return began != 0 })
	rewrite(t, opts.configPath, "  listen: true\n", "  listen: true\n  refused: true\n")
	time.Sleep(waitHeld)
	select {
	case got := <-code:
		t.Fatalf("the start ended with %d at a refused file while the key was missing:\n%s", got, logged.String())
	default:
	}
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-code:
		if got != 1 {
			t.Errorf("the start the file refused exited %d", got)
		}
	case <-time.After(daemonSettle):
		signalSelf(t, syscall.SIGTERM)
		<-code
		t.Fatal("the start did not end once the key was there")
	}
	notBuilt(t, reached, "a file the loader refuses")
	if !strings.Contains(logged.String(), "field refused not found") {
		t.Errorf("the start logged\n%s\nwant the loader's refusal", logged.String())
	}
}

// The control socket is bound through the wait. A reload there reads the file again and answers as the node's does, a
// success naming the file or the loader's refusal, which the wait goes on past, and the node is built from the file the last
// look read. Every other request is refused with the file the start waits for.
func TestDaemonAnswersOnlyAReloadWhileItWaits(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	opts.controlPath = filepath.Join(shortDir(t), "control.sock")
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, "auth.key"); return began != 0 })
	socket := control.Dial(opts.controlPath)

	rewrite(t, opts.configPath, "port: 14000", "port: 14001")
	result, err := socket.Reload()
	if err != nil {
		t.Fatalf("a reload of a file the loader takes during the wait: %v", err)
	}
	if len(result.Acted) != 1 || result.Acted[0] != opts.configPath || !strings.HasPrefix(result.Detail, "Re-read "+opts.configPath) {
		t.Errorf("a reload during the wait answered %+v, want the file re-read", result)
	}

	rewrite(t, opts.configPath, "  listen: true\n", "  listen: true\n  refused: true\n")
	_, refused := config.Load(opts.configPath)
	if refused == nil {
		t.Fatal("the loader takes the file the test means it to refuse")
	}
	// the client keeps the first line of a refusal
	want, _, _ := strings.Cut(refused.Error(), "\n")
	if _, err := socket.Reload(); err == nil || !strings.Contains(err.Error(), "400 Bad Request: "+want) {
		t.Errorf("a reload of a file the loader refuses during the wait answered %v, want the refusal %q", err, want)
	}
	rewrite(t, opts.configPath, "  refused: true\n", "")

	if _, err := socket.Status(); err == nil || !strings.Contains(err.Error(), "auth.key "+missing) {
		t.Errorf("a read during the wait answered %v, want a refusal naming auth.key %s", err, missing)
	}
	if _, err := socket.Redial("", true); err == nil || !strings.Contains(err.Error(), "auth.key "+missing) {
		t.Errorf("a redial during the wait answered %v, want a refusal naming auth.key %s", err, missing)
	}

	notBuilt(t, reached, "auth.key missing")
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := built(t, reached, "auth.key was there")
	if got := <-code; got != 1 {
		t.Errorf("the start whose node refused exited %d", got)
	}
	if cfg.Link.Port != 14001 {
		t.Errorf("the node was built from link.port %d, want the 14001 of the file the wait last read", cfg.Link.Port)
	}
}

// The wait's server and the node's take the control socket's connections in turn: once the wait's has stopped, the socket is
// still bound, and a connection made then waits at the handover, open, until the node's turn takes it
func TestControlSocketGoesFromTheWaitToTheNodeStillBound(t *testing.T) {
	path := filepath.Join(shortDir(t), "control.sock")
	socket, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	h := newHandover(socket)
	defer h.Close()
	w := &wait{path: "config.yaml", load: config.Load, files: map[configured]bool{{"auth.key", "key.pem"}: true}}
	stop := serveWait(h, w)
	if _, err := control.Dial(path).Status(); err == nil || !strings.Contains(err.Error(), "auth.key key.pem") {
		t.Errorf("a read the wait's server answers: %v, want its refusal", err)
	}
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(daemonSettle):
		t.Fatalf("the wait's server did not stop within %s", daemonSettle)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("a dial once the wait's server stopped: %v", err)
	}
	defer conn.Close()
	waitTill(t, "the handover's offer of the connection made between the two servers", offering)
	c := acceptWithin(t, "the node's turn", h)
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("the node's turn wrote to the connection made between the two servers: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(daemonSettle))
	got := make([]byte, 2)
	if n, err := conn.Read(got); string(got[:n]) != "x" {
		t.Errorf("the connection made between the two servers read %q and %v, want the node's byte alone", got[:n], err)
	}
}

// Once the wait ends, the listener the node serves takes each connection made to the control socket, and its close ends the
// handover's goroutine and the wait's server
func TestControlSocketReachesTheNodeOnceTheWaitEnds(t *testing.T) {
	logTo(t)
	opts, missing, s, _ := waitingStart(t, "auth.key")
	opts.controlPath = filepath.Join(shortDir(t), "control.sock")
	d := &daemon{opts: opts}
	var err error
	if d.cfg, err = s.load(opts.configPath); err != nil {
		t.Fatal(err)
	}
	if d.control, err = bindControl(opts.controlPath); err != nil {
		t.Fatal(err)
	}
	asked := make(chan struct{})
	t.Cleanup(func() { close(asked) })
	waited := make(chan error, 1)
	go func() {
		if ended, err := d.await(s.load, asked); !ended || err != nil {
			waited <- fmt.Errorf("the wait reported %v and %v, want its end and no error", ended, err)
			return
		}
		waited <- nil
	}()
	waitTill(t, "the wait's answer on the socket", func() bool {
		_, err := control.Dial(opts.controlPath).Status()
		return err != nil && strings.Contains(err.Error(), "auth.key "+missing)
	})
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(daemonSettle):
		t.Fatalf("the wait did not end within %s of the key", daemonSettle)
	}
	t.Cleanup(d.closeListeners)
	for i := range 3 {
		conn, err := net.Dial("unix", opts.controlPath)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = acceptWithin(t, fmt.Sprintf("the node's listener, at connection %d once the wait ended,", i), d.control).Close()
	}
	d.closeListeners()
	waitTill(t, "the end of the handover's goroutine and the wait's server", func() bool {
		return !running(newHandover) && !running(serveWait)
	})
}

// A turn whose close has returned takes no connection, though one waits at the handover, and the next turn takes it
func TestHandoverTurnTakesNothingPastItsEnd(t *testing.T) {
	path := filepath.Join(shortDir(t), "control.sock")
	socket, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	h := newHandover(socket)
	defer h.Close()
	took := 0
	for range pendingTries {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(pendingHeld)
		ended := &turn{handover: h, ended: make(chan struct{})}
		_ = ended.Close()
		if c, err := ended.Accept(); err == nil {
			took++
			_ = c.Close()
		} else {
			_ = acceptWithin(t, "the turn after an ended one", h).Close()
		}
		_ = conn.Close()
	}
	if took != 0 {
		t.Errorf("a turn whose close had returned took the connection waiting at the handover %d of %d times", took, pendingTries)
	}
}

// A reload the wait's server reads once the wait has ended is refused, though the loader takes the file, so no reload
// answers success for a file the build did not take
func TestWaitRefusesAReloadOnceItHasEnded(t *testing.T) {
	opts, _, _, _ := waitingStart(t, "auth.key")
	if _, err := config.Load(opts.configPath); err != nil {
		t.Fatalf("the loader refuses the file the test means it to take: %v", err)
	}
	w := &wait{path: opts.configPath, load: config.Load, ended: true}
	answer := httptest.NewRecorder()
	w.ServeHTTP(answer, httptest.NewRequest(http.MethodPost, control.PathReload, nil))
	if answer.Code != http.StatusServiceUnavailable {
		t.Errorf("a reload once the wait ended answered %d %q, want 503", answer.Code, answer.Body.String())
	}
}

// The node is built from the read of the file that ends the wait, never from a read after it: here the key arrives and the
// file is rewritten right after the first tick's next has read it
func TestDaemonBuildsFromTheReadThatEndsTheWait(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	reads := 0
	s.load = func(path string) (*config.Config, error) {
		cfg, err := config.Load(path)
		// the start reads first and the first tick's next second
		if reads++; reads == 2 {
			body, readErr := os.ReadFile(path)
			err = errors.Join(err, readErr, os.WriteFile(missing, nil, 0o600),
				os.WriteFile(path, []byte(strings.Replace(string(body), "port: 14000", "port: 14002", 1)), 0o600))
		}
		return cfg, err
	}
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	cfg := built(t, reached, "the key was there")
	<-code
	if began, _ := waitLines(logged, "auth.key"); began != 1 {
		t.Errorf("the start logged its wait for the key %d times, want once:\n%s", began, logged.String())
	}
	if cfg.Link.Port != 14000 {
		t.Errorf("the node was built from link.port %d, want the 14000 of the read that ended the wait", cfg.Link.Port)
	}
	if body, err := os.ReadFile(opts.configPath); err != nil || !strings.Contains(string(body), "port: 14002") {
		t.Errorf("the file after the wait reads %q and %v, want the rewrite's port 14002", body, err)
	}
}

// SIGTERM while the start waits for its key ends the wait and the start, which builds no node, says it stopped in the wait
// and nothing of undoing a build, and exits 0
func TestDaemonStoppedInTheKeyWaitBuildsNoNode(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, "auth.key"); return began != 0 })
	signalSelf(t, syscall.SIGTERM)
	select {
	case got := <-code:
		if got != 0 {
			t.Errorf("the start stopped in its wait exited %d", got)
		}
	case <-time.After(daemonSettle):
		// the key ends a wait the stop did not, so the start returns before the next test
		if err := os.WriteFile(missing, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		<-code
		t.Fatal("SIGTERM did not end the wait for the key")
	}
	notBuilt(t, reached, "a stop in its wait")
	if text := logged.String(); !strings.Contains(text, "stopping in the wait") || strings.Contains(text, "undoes what it built") {
		t.Errorf("the start stopped in its wait logged\n%s\nwant its stop in the wait and nothing of undoing a build", text)
	}
}

// A key path the stat refuses for another reason than its absence, here one under a regular file, starts no wait: the
// start warns with the stat's error and builds the node at once
func TestDaemonGoesOnPastAKeyItCannotStat(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	under := filepath.Join(filepath.Dir(missing), "trust.json", "key.pem")
	rewrite(t, opts.configPath, missing, under)
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	select {
	case got := <-code:
		if got != 1 {
			t.Errorf("the start whose node refused exited %d", got)
		}
	case <-time.After(daemonSettle):
		signalSelf(t, syscall.SIGTERM)
		<-code
		t.Fatal("the start waited for a key under a regular file")
	}
	built(t, reached, "the stat of the key failed")
	if began, _ := waitLines(logged, "auth.key"); began != 0 {
		t.Errorf("the start logged a wait for a key under a regular file %d times:\n%s", began, logged.String())
	}
	if !strings.Contains(logged.String(), "level=WARN msg=\"the stat of a file the config names failed") {
		t.Errorf("the start logged\n%s\nwant a warning with the stat's error", logged.String())
	}
}

// A file the wait found missing and whose stat then fails for another reason, here as its directory turns into a regular
// file, ends the wait with a warning holding the error and no line saying it exists
func TestDaemonLogsNoArrivalOfAFileItCannotStat(t *testing.T) {
	logged := logTo(t)
	opts, missing, s, reached := waitingStart(t, "auth.key")
	dir := filepath.Join(filepath.Dir(missing), "keys")
	rewrite(t, opts.configPath, missing, filepath.Join(dir, "key.pem"))
	code := make(chan int, 1)
	go func() { code <- startDaemon(opts, s) }()
	waitTill(t, "the wait", func() bool { began, _ := waitLines(logged, "auth.key"); return began != 0 })
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	built(t, reached, "the stat of the key failed")
	<-code
	if _, ended := waitLines(logged, "auth.key"); ended != 0 {
		t.Errorf("the wait logged a key it cannot stat as there %d times:\n%s", ended, logged.String())
	}
	if !strings.Contains(logged.String(), "not a directory") {
		t.Errorf("the start logged\n%s\nwant a warning with the stat's error", logged.String())
	}
}
