// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// sweepHeld is how long a test watches a sweep that has a dialer still to wait for, which it must not return within
const sweepHeld = 200 * time.Millisecond

// the sweep stops every dialer and returns only once each has ended, session and all
// a dialer ending late, as one unwinding a session does, holds the sweep until it has
func TestSweepWaitsForEveryDialerItStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, sessions: newSessionSet(), dialers: make(map[string]*dialer)}
	c.cfg.Store(&config.Config{})
	c.storeIndex(trust(t, registry.Registry{}))
	release := make(chan struct{})
	dialing, stop := context.WithCancel(ctx)
	slow := &dialer{cancel: stop, wake: make(chan struct{}, 1), done: make(chan struct{})}
	c.dialers["example/slow:0@0"] = slow
	c.peers.Go(func() {
		defer close(slow.done)
		<-dialing.Done()
		<-release
	})

	c.stopDialers()
	left := make(chan struct{})
	go func() {
		defer close(left)
		c.leave()
	}()
	select {
	case <-left:
		t.Fatal("the sweep returned while a dialer it stopped was still running")
	case <-time.After(sweepHeld):
	}
	if dialing.Err() == nil {
		t.Error("the sweep is waiting on a dialer it never stopped")
	}
	close(release)
	select {
	case <-left:
	case <-time.After(convergeBudget):
		t.Fatal("the sweep did not return once its last dialer had ended")
	}
	if got := dialerCount(c); got != 0 {
		t.Errorf("the sweep left %d dialers in the map", got)
	}
	c.peers.Wait()
}

// a dialer dropped while the node runs tells its peer the session is gone, once
// a session the sweep already told is not told again, though the sweep stops its dialer while the node runs
func TestSweptSessionIsNotToldAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, sessions: newSessionSet()}
	var mu sync.Mutex
	var told []*ike.Session
	c.sessions.close = func(sess *ike.Session) {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, sess)
	}
	toldCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(told)
	}
	dropped, swept := &ike.Session{}, &ike.Session{}
	c.sessions.adoptPreferred("example/dropped:0@0", dropped, true, nil)
	c.sessions.adoptPreferred("example/swept:0@0", swept, true, nil)
	dial, stop := context.WithCancel(ctx)
	stop()

	c.tellDropped(dial, "example/dropped:0@0", dropped)
	if got := toldCount(); got != 1 {
		t.Fatalf("the peer of a dropped dialer was told %d times, want once", got)
	}
	if got := c.sessions.paths(); slices.Contains(got, "example/dropped:0@0") {
		t.Errorf("the set still holds the session it told the peer about: %v", got)
	}
	if closed := c.sessions.closeAll(); !slices.Equal(closed, []string{"example/swept:0@0"}) {
		t.Errorf("the sweep closed %v, want the one session still held", closed)
	}
	c.tellDropped(dial, "example/swept:0@0", swept)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(told, []*ike.Session{dropped, swept}) {
		t.Errorf("the peers were told %d times, want once for each session", len(told))
	}
}

// the shutdown's sweep stops the dialers, the responder and the speaker while the node's context still runs
// it returns once every session has unwound, so no Babel neighbor is left, and the peer was told
func TestShutdownSweepStopsEveryLoopBeforeTheContextGoes(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})
	waitFor(t, convergeBudget, "a Babel neighbor at alpha", func() bool {
		return len(alpha.client.speaker.Stats().Neighbors) == 1
	})

	c := alpha.client
	c.stopDialers()
	if closed := c.leave(); len(closed) != 1 {
		t.Errorf("the sweep closed %v, want the one session alpha held", closed)
	}
	if c.ctx.Err() != nil {
		t.Fatal("the sweep canceled the node's context, which is the shutdown's own last step")
	}
	c.dialersMu.Lock()
	dialers, responder, speaking := len(c.dialers), c.responder, c.speakerRun
	c.dialersMu.Unlock()
	if dialers != 0 || responder != nil || speaking != nil {
		t.Errorf("after the sweep %d dialers run, the responder is %v and the speaker %v, want none of them", dialers, responder, speaking)
	}
	if got := c.speaker.Stats().Neighbors; len(got) != 0 {
		t.Errorf("the sweep returned with %d Babel neighbors still registered", len(got))
	}
	waitFor(t, convergeBudget, "bravo to be told its session is gone", func() bool {
		return len(bravo.client.sessions.paths()) == 0
	})
}
