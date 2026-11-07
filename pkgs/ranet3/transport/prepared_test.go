// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
)

// readied is one socket a Prepare saw, by its network and destination
type readied struct {
	network string
	to      netip.AddrPort
}

// recordingPrepare records every socket it readies and hands it on to then, or refuses it with refuse where refuse is set
type recordingPrepare struct {
	mu     sync.Mutex
	seen   []readied
	then   func(string, netip.AddrPort, syscall.RawConn) error
	refuse error
}

func (r *recordingPrepare) prepare(network string, to netip.AddrPort, raw syscall.RawConn) error {
	r.mu.Lock()
	r.seen = append(r.seen, readied{network, to})
	r.mu.Unlock()
	if r.refuse != nil {
		return r.refuse
	}
	if r.then != nil {
		return r.then(network, to, raw)
	}
	return nil
}

// take returns what the recording saw since the last take
func (r *recordingPrepare) take() []readied {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := r.seen
	r.seen = nil
	return seen
}

// a hub whose runtime names no Prepare is refused, never read as one that does nothing
func TestNewHubRefusesARuntimeWithNoPrepare(t *testing.T) {
	var unprepared Runtime
	hub, err := NewHub(0, unprepared)
	if hub != nil {
		_ = hub.Close()
	}
	if !errors.Is(err, errUnprepared) {
		t.Fatalf("a hub with no Prepare answered %v, want the refusal", err)
	}
}

// a Prepare that refuses the listener's socket refuses the hub, after it saw the listener with no destination
func TestHubIsRefusedWhereItsPrepareRefusesTheListener(t *testing.T) {
	refusal := errors.New("refused by the test")
	recording := &recordingPrepare{refuse: refusal}
	hub, err := NewHub(0, Runtime{Prepare: recording.prepare})
	if hub != nil {
		_ = hub.Close()
	}
	if !errors.Is(err, refusal) {
		t.Fatalf("a hub whose Prepare refuses every socket answered %v, want its refusal", err)
	}
	if seen := recording.take(); len(seen) == 0 || slices.ContainsFunc(seen, func(r readied) bool { return r.to.IsValid() }) {
		t.Errorf("the refused hub's Prepare saw %v, want the listener with no destination", seen)
	}
}
