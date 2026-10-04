// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordPoll is how often a test looks again for an event it waits on
const recordPoll = 10 * time.Millisecond

// recorder keeps what a Recorder was handed, one line per event
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) record(local, remote Identity, kind string, attrs ...slog.Attr) {
	line := []string{kind, local.CommonName + ">" + remote.CommonName}
	for _, attr := range attrs {
		if attr.Key != "err" && attr.Key != "from" {
			line = append(line, attr.String())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.Join(line, " "))
}

func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.lines)
}

// both roles record the rekeys they start, with the session's two ends, the SA and how it came out
func TestSessionsRecordTheirRekeys(t *testing.T) {
	answered, dialed := &recorder{}, &recorder{}
	h := newResponderHarness(t, nil, answered.record)
	cfg := h.peerConfig()
	cfg.Events = dialed.record
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	responder := <-h.sessions
	<-h.identities
	go initiator.Run(ctx)
	go responder.Run(ctx)

	// a rekey asked for while another runs runs no exchange, so it records nothing
	initiator.childRekeying.Store(true)
	if err := initiator.RekeyChild(); err == nil {
		t.Error("a rekey asked for while another ran succeeded")
	}
	if err := initiator.RekeyChildProactively(); err != nil {
		t.Errorf("a proactive rekey that found one running failed: %v", err)
	}
	initiator.childRekeying.Store(false)
	if err := initiator.RekeyChild(); err != nil {
		t.Fatalf("the initiator could not rekey its Child SA: %v", err)
	}
	if err := responder.RekeyIKE(); err != nil {
		t.Fatalf("the responder could not rekey the IKE SA: %v", err)
	}
	initiator.Mux().Close()
	if err := initiator.RekeyChild(); err == nil {
		t.Fatal("a rekey over a closed session succeeded")
	}
	if got, want := dialed.recorded(), []string{
		"ike.rekey.started client>server sa=child", "ike.rekey.completed client>server sa=child",
		"ike.rekey.started client>server sa=child", "ike.rekey.failed client>server sa=child",
	}; !slices.Equal(got, want) {
		t.Errorf("the dialed session recorded %q, want %q", got, want)
	}
	if got, want := answered.recorded(), []string{
		"ike.rekey.started server>client sa=ike", "ike.rekey.completed server>client sa=ike",
	}; !slices.Equal(got, want) {
		t.Errorf("the answered session recorded %q, want %q", got, want)
	}
}

// a handshake the responder refuses is recorded where it is said, with no session to name
func TestResponderRecordsARefusedHandshake(t *testing.T) {
	answered := &recorder{}
	h := newResponderHarness(t, func(Identity) (ed25519.PublicKey, bool) { return nil, false }, answered.record)
	if session, err := h.dial(t); err == nil {
		session.Mux().Close()
		t.Fatal("a peer the lookup refuses was let in")
	}
	for deadline := time.Now().Add(answerBudget); !slices.Contains(answered.recorded(), "ike.handshake.failed >"); {
		if time.Now().After(deadline) {
			t.Fatalf("the refusal was not recorded, only %q", answered.recorded())
		}
		time.Sleep(recordPoll)
	}
}
