// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// executeApart drives the command tree with stdout and stderr kept apart, and stdin as its standard input where it is not nil
func executeApart(t *testing.T, stdin io.Reader, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut strings.Builder
	root := newRoot()
	if stdin != nil {
		root.SetIn(stdin)
	}
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// the debug tree is listed in the usage and lists its own commands when asked
func TestDebugIsListedAndListsItsCommands(t *testing.T) {
	usage, err := execute(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(usage, "debug") {
		t.Errorf("the usage does not name the debug tree: %q", usage)
	}
	tree, err := execute(t, "debug", "--help")
	if err != nil {
		t.Fatal(err)
	}
	// the description is wrapped, so a phrase may break across lines
	tree = strings.Join(strings.Fields(tree), " ")
	for _, want := range []string{"socket", "runtime", "buildinfo", "netmon", "probe", "updown", "rules", "route", "egress", "segments", "not a stable interface", "--control", "--json"} {
		if !strings.Contains(tree, want) {
			t.Errorf("debug --help reads %q, want it to carry %q", tree, want)
		}
	}
}

// debug socket prints the daemon's own bytes and its status line apart from them
func TestDebugSocketPrintsTheDaemonsBytes(t *testing.T) {
	socket := serveStub(t)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	response, err := (&http.Client{Transport: transport}).Get("http://control" + control.PathStatus)
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeApart(t, nil, "debug", "socket", "GET", control.PathStatus, "--control", socket)
	if err != nil {
		t.Fatalf("debug socket failed: %v", err)
	}
	if stdout != string(want) {
		t.Errorf("debug socket printed %q, want the daemon's own %q", stdout, want)
	}
	if !strings.Contains(stderr, "200 OK") {
		t.Errorf("the status line reads %q", stderr)
	}
}

// a path the daemon does not serve exits 1, with its sentence on stdout
func TestDebugSocketExitsOneOnARefusal(t *testing.T) {
	socket := serveStub(t)
	stdout, stderr, err := executeApart(t, nil, "debug", "socket", control.PathDebug+"nothing-here", "--control", socket)
	if code, ok := errors.AsType[exitCode](err); !ok || code != 1 {
		t.Fatalf("a refused path ended with %v, want exit status 1", err)
	}
	if !strings.Contains(stdout, "no debug path is called") || !strings.Contains(stderr, "404") {
		t.Errorf("a refused path printed %q and %q", stdout, stderr)
	}
}

// a method, a path and a body are read in that order, with the method left to the body
func TestDebugSocketReadsItsArguments(t *testing.T) {
	for name, test := range map[string]struct {
		args   []string
		method string
		body   string
		fails  bool
	}{
		"a path":                 {args: []string{"/v0/status"}, method: http.MethodGet},
		"a path and a body":      {args: []string{"/v0/reload", "{}"}, method: http.MethodPost, body: "{}"},
		"a method and a path":    {args: []string{"head", "/v0/status"}, method: http.MethodHead},
		"stdin for the body":     {args: []string{"POST", "/v0/reload", "-"}, method: http.MethodPost, body: "from stdin"},
		"a method and no path":   {args: []string{"GET"}, fails: true},
		"a path with no slash":   {args: []string{"GET", "v0/status"}, fails: true},
		"something after a body": {args: []string{"/v0/reload", "{}", "extra"}, fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			method, _, body, err := rawRequest(test.args, strings.NewReader("from stdin"))
			if test.fails {
				if err == nil {
					t.Fatalf("%q was taken as %s", test.args, method)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if body != nil {
				raw, _ := io.ReadAll(body)
				got = string(raw)
			}
			if method != test.method || got != test.body {
				t.Errorf("%q read as %s with %q, want %s with %q", test.args, method, got, test.method, test.body)
			}
		})
	}
}

// stdinHold is the longest a test's standard input holds the second part of its body for a dial that comes before its end
const stdinHold = 400 * time.Millisecond

// heldStdin yields its parts in order, and before the second waits for a dial or for stdinHold, whichever comes first
type heldStdin struct {
	parts  []string
	dialed <-chan struct{}
	given  int
	ended  atomic.Bool
}

func (s *heldStdin) Read(b []byte) (int, error) {
	if s.given == len(s.parts) {
		s.ended.Store(true)
		return 0, io.EOF
	}
	if s.given > 0 {
		select {
		case <-s.dialed:
		case <-time.After(stdinHold):
		}
	}
	n := copy(b, s.parts[s.given])
	s.given++
	return n, nil
}

// dialWatch is the daemon's socket, which notes a connection that came before the standard input had ended
type dialWatch struct {
	net.Listener
	stdin  *heldStdin
	once   sync.Once
	dialed chan struct{}
	early  atomic.Bool
}

func (l *dialWatch) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		if !l.stdin.ended.Load() {
			l.early.Store(true)
		}
		l.once.Do(func() { close(l.dialed) })
	}
	return conn, err
}

// the command reads a body on standard input to its end before it dials, and sends it whole and with its length
// so slow standard input is no wait of the daemon's, whose request timeout does not wait on it
func TestDebugSocketReadsStandardInputBeforeItDials(t *testing.T) {
	socket := filepath.Join(shortDir(t), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan struct{})
	stdin := &heldStdin{parts: []string{`{"peer":`, `"example/gateway"}`}, dialed: dialed}
	watch := &dialWatch{Listener: listener, stdin: stdin, dialed: dialed}
	want := `{"peer":"example/gateway"}`
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != int64(len(want)) {
			http.Error(w, fmt.Sprintf("a body of length %d, want %d", r.ContentLength, len(want)), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write(body)
	})}
	go server.Serve(watch)
	t.Cleanup(func() { server.Close() })
	// where go test sets a deadline the exchange may take the time the test binary has left, so go test's -timeout and
	// not load ends a hung run
	// where go test sets no deadline the exchange may take a day
	timeout := 24 * time.Hour
	if deadline, ok := t.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	out, _, err := executeApart(t, stdin, "debug", "socket", "POST", control.PathRedial, "-", "--control", socket, "--timeout", timeout.String())
	if err != nil || out != want || watch.early.Load() {
		t.Errorf("a body on standard input ended with %v and %q, dialed before its end %v, want %q sent after its end", err, out, watch.early.Load(), want)
	}
}

// a body past the daemon's limit is refused by the command before it dials, by the limit, and one at the limit is taken
func TestDebugSocketRefusesABodyPastTheLimitBeforeItDials(t *testing.T) {
	if _, _, body, err := rawRequest([]string{control.PathRedial, "-"}, strings.NewReader(strings.Repeat(" ", control.MaxRequest))); err != nil || body == nil {
		t.Errorf("a body of %d bytes on standard input was refused: %v", control.MaxRequest, err)
	}
	// nothing listens here, so a command that dialed would fail by naming the missing socket
	socket := filepath.Join(shortDir(t), "control.sock")
	_, _, err := executeApart(t, strings.NewReader(strings.Repeat(" ", control.MaxRequest+1)), "debug", "socket", "POST", control.PathRedial, "-", "--control", socket)
	if err == nil || !strings.Contains(err.Error(), strconv.Itoa(control.MaxRequest)) {
		t.Errorf("a body of %d bytes on standard input ended with %v, want a refusal that names the limit", control.MaxRequest+1, err)
	}
}

// debug runtime reads the daemon's process and prints it or its wire form
func TestDebugRuntimeReadsTheDaemon(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, "debug", "runtime", "--control", socket)
	if err != nil {
		t.Fatalf("debug runtime failed: %v", err)
	}
	for _, want := range []string{"1.2.3", "go1.26.7", "41"} {
		if !strings.Contains(out, want) {
			t.Errorf("debug runtime printed %q, want it to carry %q", out, want)
		}
	}
	out, err = execute(t, "debug", "runtime", "--json", "--control", socket)
	if err != nil || !strings.Contains(out, `"goroutines": 41`) {
		t.Errorf("debug runtime --json printed %q, %v", out, err)
	}
}
