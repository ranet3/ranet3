// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
)

// serveTrace answers a trace with a stream.live note and one record, then holds the stream open until its reader goes
// it keeps the query of each trace it was asked
func serveTrace(t *testing.T) (string, chan url.Values) {
	t.Helper()
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	asked := make(chan url.Values, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- r.URL.Query()
		fmt.Fprintln(w, `{"note":{"at":"2026-10-28T19:30:00Z","kind":"stream.live"}}`)
		fmt.Fprintln(w, `{"packet":{"arrival":"session","from":"example/gateway:0@1","decision":"forward","next":"example/relay:1@0","src":"192.0.2.1","dst":"192.0.2.3","proto":17,"hop_limit":64,"length":48}}`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return path, asked
}

// debug trace prints what the daemon streams until --for has passed, then exits 0, and under --json the wire lines
// its flags reach the daemon as the query they spell
func TestDebugTracePrintsUntilItsBound(t *testing.T) {
	socket, asked := serveTrace(t)
	out, err := execute(t, "debug", "trace", "--for", waitShort.String(), "--control", socket,
		"--src", "192.0.2.1", "--dst", "192.0.2.0/24", "--proto", "udp", "--decision", "forward", "--peer", "gateway", "--rate", "5", "--payload", "64")
	if err != nil || !strings.Contains(out, "stream.live") ||
		!strings.Contains(out, "forward udp 192.0.2.1 > 192.0.2.3 arrival=session from=example/gateway:0@1 next=example/relay:1@0 hop_limit=64 length=48") {
		t.Errorf("debug trace printed %q and ended with %v", out, err)
	}
	want := url.Values{"src": {"192.0.2.1/32"}, "dst": {"192.0.2.0/24"}, "proto": {"17"}, "decision": {"forward"}, "peer": {"gateway"}, "rate": {"5"}, "payload": {"64"}}
	if got := <-asked; got.Encode() != want.Encode() {
		t.Errorf("the daemon was asked %v, want %v", got, want)
	}
	out, err = execute(t, "debug", "trace", "--for", waitShort.String(), "--json", "--control", socket)
	if err != nil {
		t.Fatalf("debug trace --json ended with %v", err)
	}
	var lines []control.TraceLine
	for text := range strings.Lines(out) {
		var line control.TraceLine
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			t.Fatalf("debug trace --json printed %q: %v", text, err)
		}
		lines = append(lines, line)
	}
	if len(lines) != 2 || lines[0].Note == nil || lines[1].Packet == nil || lines[1].Packet.Next != "example/relay:1@0" {
		t.Errorf("debug trace --json printed %q", out)
	}
	if got := <-asked; got.Encode() != "rate=1000" {
		t.Errorf("a trace naming nothing asked the daemon for %v", got)
	}
}

// a flag out of bounds or that does not parse is refused with its value before the command dials
func TestDebugTraceRefusesItsFlagsOutOfBounds(t *testing.T) {
	gone := filepath.Join(filepath.Dir(socketPath(t)), "gone.sock")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--for", "0s"}, "--for"},
		{[]string{"--src", "192.0.2.0/33"}, "192.0.2.0/33"},
		{[]string{"--dst", "example.org"}, "example.org"},
		{[]string{"--proto", "ospf"}, "ospf"},
		{[]string{"--proto", "256"}, "256"},
		{[]string{"--decision", "accept"}, "accept"},
		{[]string{"--rate", "0"}, "rate"},
		{[]string{"--rate", "10001"}, "10001"},
		{[]string{"--payload", "-1"}, "payload"},
		{[]string{"--payload", "65536"}, "65536"},
	} {
		args := append([]string{"debug", "trace", "--control", gone}, c.args...)
		if out, err := execute(t, args...); err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "daemon") {
			t.Errorf("%q printed %q and ended with %v, want a refusal naming %q", args, out, err, c.want)
		}
	}
}
