// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

// writingStub is a stubSource that also takes the verbs, recording the call so
// a test can tell a command that reached the daemon from one that printed
// something plausible without asking it anything.
type writingStub struct {
	stubSource
	mu   sync.Mutex
	last string
	// missed goes in every answer the stub gives
	missed []control.Missed
}

// a stub that stopped matching the interface would leave every verb refused rather than fail to build
var _ control.Sink = (*writingStub)(nil)

func (s *writingStub) SetSubsystem(_ context.Context, name control.Subsystem, on bool) (control.Result, error) {
	state := "stopped"
	if on {
		state = "running"
	}
	return s.record(fmt.Sprintf("set %s %s", name, state))
}

func (s *writingStub) Redial(_ context.Context, peer string, all bool) (control.Result, error) {
	if all {
		return s.record("redial --all")
	}
	return s.record("redial " + peer)
}

func (s *writingStub) Rekey(_ context.Context, peer string, all bool) (control.Result, error) {
	if all {
		return s.record("rekey --all")
	}
	return s.record("rekey " + peer)
}

func (s *writingStub) Reload(context.Context) (control.Result, error) { return s.record("reload") }

func (s *writingStub) Down(context.Context) (control.Result, error) { return s.record("down") }

func (s *writingStub) Up(context.Context) (control.Result, error) { return s.record("up") }

// Sessions names a peer the peers list does not. The completion unions the
// two, and a peer that only dials this node has no entry in the peers list and
// is the peer a redial is for, so spelling both halves the same way would let
// either be deleted unseen.
func (*writingStub) Sessions() []control.Session {
	return []control.Session{{Path: "example/inbound:0@0", Peer: "example/inbound", Active: true}}
}

func (s *writingStub) record(call string) (control.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = call
	return control.Result{Acted: []string{call}, Missed: s.missed, Detail: "the daemon took " + call}, nil
}

func (s *writingStub) answerMissing(missed ...control.Missed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missed = missed
}

func (s *writingStub) asked() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// serveWritingStub starts a control socket that takes the verbs and returns
// its path with the stub behind it.
func serveWritingStub(t *testing.T) (string, *writingStub) {
	t.Helper()
	sink := &writingStub{}
	return serve(t, sink), sink
}

// Every verb reaches the daemon with the argument that was typed, and prints
// the sentence the daemon answered rather than one of its own.
func TestVerbsReachTheDaemonAsTyped(t *testing.T) {
	socket, sink := serveWritingStub(t)
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"disable":    {args: []string{"disable", "steering"}, want: "set steering stopped"},
		"enable":     {args: []string{"enable", "reconciler"}, want: "set reconciler running"},
		"redial":     {args: []string{"redial", "example/gateway"}, want: "redial example/gateway"},
		"redial all": {args: []string{"redial", "--all"}, want: "redial --all"},
		"rekey one":  {args: []string{"rekey", "example/gateway"}, want: "rekey example/gateway"},
		"rekey all":  {args: []string{"rekey", "--all"}, want: "rekey --all"},
		"reload":     {args: []string{"reload"}, want: "reload"},
		"down":       {args: []string{"down"}, want: "down"},
		"up":         {args: []string{"up"}, want: "up"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, append(test.args, "--control", socket)...)
			if err != nil {
				t.Fatalf("%v failed: %v", test.args, err)
			}
			if got := sink.asked(); got != test.want {
				t.Errorf("the daemon was asked %q, want %q", got, test.want)
			}
			if !strings.Contains(out, test.want) {
				t.Errorf("the command printed %q, want the daemon's own answer", out)
			}
		})
	}
}

// --json on a verb is the answer as a script parses it, so a fleet tool reads
// the field names the daemon serves rather than the sentence.
func TestVerbJSONPrintsTheWireForm(t *testing.T) {
	socket, _ := serveWritingStub(t)
	out, err := execute(t, "reload", "--control", socket, "--json")
	if err != nil {
		t.Fatalf("reload --json failed: %v", err)
	}
	if !strings.Contains(out, `"detail"`) || !strings.Contains(out, `"acted"`) {
		t.Errorf("reload --json printed %q", out)
	}
}

// a verb whose answer lists an entry it did not reach prints the answer with why and exits writeMissed, under --json as well
func TestVerbMissingAnEntryExitsWriteMissed(t *testing.T) {
	socket, sink := serveWritingStub(t)
	sink.answerMissing(control.Missed{Entry: "example/gateway:0@0", Reason: "ike: a Child SA rekey waits out the retry delay of the one that failed"})
	for _, args := range [][]string{{"rekey", "--all"}, {"rekey", "--all", "--json"}} {
		out, err := execute(t, append(args, "--control", socket)...)
		if code, ok := errors.AsType[exitCode](err); !ok || code != writeMissed {
			t.Errorf("%v ended with %v, want exit status %d", args, err, writeMissed)
		}
		if !strings.Contains(out, "example/gateway:0@0") || !strings.Contains(out, "retry delay") {
			t.Errorf("%v printed %q, want the session that did not rekey and why", args, out)
		}
	}
}

// A verb given the wrong arguments is refused here rather than at the daemon,
// and a daemon that refuses says why in its own words.
func TestVerbsRefuseWhatTheyCannotActOn(t *testing.T) {
	socket, _ := serveWritingStub(t)
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		// The whole message rather than a substring every cobra argument
		// error carries: with "arg" alone any of these refusals
		// satisfies any of the expectations.
		"disable with no subsystem": {args: []string{"disable"}, want: "accepts 1 arg(s), received 0"},
		"disable with two":          {args: []string{"disable", "steering", "responder"}, want: "accepts 1 arg(s), received 2"},
		// The same sentence as the first, from the other validator: rekey
		// decides on --all where disable takes a fixed count.
		"rekey with neither":      {args: []string{"rekey"}, want: "accepts 1 arg(s), received 0"},
		"rekey with both":         {args: []string{"rekey", "example/gateway", "--all"}, want: `ranet3 rekey takes no arguments, got "example/gateway"`},
		"redial with neither":     {args: []string{"redial"}, want: "accepts 1 arg(s), received 0"},
		"redial with both":        {args: []string{"redial", "example/gateway", "--all"}, want: `ranet3 redial takes no arguments, got "example/gateway"`},
		"reload with an argument": {args: []string{"reload", "now"}, want: `ranet3 reload takes no arguments, got "now"`},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, append(test.args, "--control", socket)...)
			if err == nil {
				t.Fatalf("%v was accepted, printing %q", test.args, out)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("the refusal reads %q, want it to carry %q", err, test.want)
			}
		})
	}
}

// A verb against a daemon that is not running says so, rather than reporting a
// change nothing made.
func TestVerbsSayWhenNoDaemonAnswers(t *testing.T) {
	gone := socketPath(t)
	for _, args := range [][]string{{"disable", "steering"}, {"redial", "gateway"}, {"rekey", "--all"}, {"reload"}} {
		if _, err := execute(t, append(args, "--control", gone)...); err == nil {
			t.Errorf("%v reported success against a socket nothing is serving", args)
		} else if !strings.Contains(err.Error(), "daemon") {
			t.Errorf("the failure reads %q, want it to name the daemon", err)
		}
	}
}

// A subsystem is completed from the closed set, which a node that is not
// running still answers for, and a peer is completed from the daemon, which
// knows what this node dials and answers.
func TestArgumentsAndFlagValuesAreCompleted(t *testing.T) {
	socket, _ := serveWritingStub(t)
	for name, test := range map[string]struct {
		command string
		flag    string
		// word is the one being completed, empty for a fresh argument
		word string
		want string
	}{
		"a subsystem":                      {command: "disable", want: "steering"},
		"a peer this node dials":           {command: "redial", want: "example/gateway"},
		"a peer that only dials this node": {command: "redial", want: "example/inbound"},
		"every peer":                       {command: "redial", word: "--a", want: "--all"},
		// rekey takes the same completion, so this holds the wiring rather
		// than the function the case above already drives.
		"the same peers under rekey": {command: "rekey", want: "example/inbound"},
		// the usage of --log-level no longer lists the levels
		// so completion is where the command line names them
		"a log level":       {command: "daemon", flag: "--log-level", want: "debug\ninfo\nwarn\nerror\n"},
		"a state directory": {command: "daemon", flag: "--state-dir", want: "ShellCompDirectiveFilterDirs"},
	} {
		t.Run(name, func(t *testing.T) {
			words := []string{cobra.ShellCompRequestCmd, test.command, "--control", socket}
			if test.flag != "" {
				words = append(words, test.flag)
			}
			out, err := execute(t, append(words, test.word)...)
			if err != nil {
				t.Fatalf("completing %s failed: %v", test.command, err)
			}
			if !strings.Contains(out, test.want) {
				t.Errorf("%s completed to %q, want it to offer %q", test.command, out, test.want)
			}
		})
	}
}

// pinning dials one endpoint of example/alpha and holds a session another endpoint of it opened
type pinning struct{ stubSource }

func (pinning) Peers() []control.Peer {
	return []control.Peer{{Path: "example/alpha:1@0", Peer: "example/alpha:1"}}
}

func (pinning) Sessions() []control.Session {
	return []control.Session{{Path: "example/alpha:2@0", Peer: "example/alpha", Active: true}}
}

// a peer completes to the canonical form the daemon names it by, the endpoint a pinned peer names and the node a session names
func TestPeersCompleteToTheirCanonicalForm(t *testing.T) {
	socket := serve(t, pinning{})
	for word, want := range map[string][]string{"": {"example/alpha", "example/alpha:1"}, "example/alpha:": {"example/alpha:1"}} {
		out, err := execute(t, cobra.ShellCompRequestCmd, "redial", "--control", socket, word)
		if err != nil {
			t.Fatalf("completing %q failed: %v", word, err)
		}
		offered, _, _ := strings.Cut(out, "\n:")
		if got := strings.Fields(offered); !slices.Equal(got, want) {
			t.Errorf("redial %q completed to %q, want %q", word, got, want)
		}
	}
}

// The usage lists the verbs beside the reads, because the bare binary's
// listing is the whole of the built-in documentation.
func TestBareInvocationListsTheVerbs(t *testing.T) {
	out, err := execute(t)
	if err != nil {
		t.Fatalf("the bare binary failed: %v", err)
	}
	for _, want := range []string{"disable", "enable", "redial", "rekey", "reload", "down", "up"} {
		if !strings.Contains(out, want) {
			t.Errorf("the usage reads %q, want it to name %q", out, want)
		}
	}
}
