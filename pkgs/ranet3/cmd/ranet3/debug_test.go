// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
)

// executeApart drives the command tree with stdout and stderr kept apart
func executeApart(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut strings.Builder
	root := newRoot()
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
	for _, want := range []string{"socket", "runtime", "buildinfo", "not a stable interface", "--control", "--json"} {
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

	stdout, stderr, err := executeApart(t, "debug", "socket", "GET", control.PathStatus, "--control", socket)
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
	stdout, stderr, err := executeApart(t, "debug", "socket", control.PathDebug+"nothing-here", "--control", socket)
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
