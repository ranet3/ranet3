// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
)

var (
	contactLocal = identity.MustParse("example/self:0")
	// contactPeer and contactSecond are 2 endpoints of 1 peer node, so 2 paths to it, and contactOther an endpoint of another node
	contactPeer, contactSecond, contactOther = identity.MustParse("example/peer:0"), identity.MustParse("example/peer:1"), identity.MustParse("example/other:0")
)

// contactSet is a session set whose handshakes end where ended holds them, which keeps what it closes and what it drops
type contactSet struct {
	*sessionSet
	tb      testing.TB
	mu      sync.Mutex
	gone    map[*ike.Session]bool
	closed  []*ike.Session
	dropped []*ike.Session
}

func newContactSet(tb testing.TB) *contactSet {
	c := &contactSet{sessionSet: newSessionSet(), tb: tb, gone: make(map[*ike.Session]bool)}
	c.events = events.New()
	c.trust = admittingUnder(seeded(1), contactPeer.Node(), contactOther.Node())
	c.active = func(*ike.Session) bool { return true }
	c.endpoint = func(*ike.Session) string { return "198.51.100.7:4500" }
	c.ended = func(sess *ike.Session) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.gone[sess]
	}
	c.close = func(sess *ike.Session) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = append(c.closed, sess)
	}
	c.drop = func(sess *ike.Session) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.dropped = append(c.dropped, sess)
	}
	return c
}

// end has sess's handshake fail, which closes its mux
func (c *contactSet) end(sess *ike.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gone[sess] = true
}

// take adopts sess at peer's path with the rule already applied, contact as adopt passes it
func (c *contactSet) take(peer identity.Identity, sess *ike.Session, preferred bool, contact time.Time) (func(), bool) {
	path := identity.Path(peer, contactLocal)
	return c.adoptFor(path, sess, preferred, false, contact, contactLocal, peer, seeded(1), testDriver(c.tb, path), nil)
}

// after a restart a peer dialed on 2 paths at once gets the notice on the first IKE_AUTH alone, request or response
// and every later one goes without it while any SA to the peer's node is live or past its decision, on whichever path
// another node's first one carries it all the same
func TestInitialContactGoesOnTheFirstHandshakeToAPeerAlone(t *testing.T) {
	set := newContactSet(t)
	first, second := &ike.Session{}, &ike.Session{}
	if !set.initialContact(first, contactPeer) {
		t.Fatal("the first handshake after a restart went without INITIAL_CONTACT")
	}
	if set.initialContact(second, contactSecond) {
		t.Error("a second path's handshake beside the first carried INITIAL_CONTACT as well")
	}
	if !set.initialContact(&ike.Session{}, contactOther) {
		t.Error("another node's first handshake went without INITIAL_CONTACT")
	}

	// a handshake that failed is no SA, and the one still under way is
	set.end(first)
	beside := &ike.Session{}
	if set.initialContact(beside, contactPeer) {
		t.Error("a handshake carried INITIAL_CONTACT while another to the peer was under way")
	}
	set.end(second)
	set.end(beside)
	third := &ike.Session{}
	if !set.initialContact(third, contactSecond) {
		t.Error("the first handshake once every other one to the peer failed went without INITIAL_CONTACT")
	}

	// a live session is an SA too, and once adopted it is counted as one alone
	release, adopted := set.take(contactSecond, third, true, time.Time{})
	if !adopted {
		t.Fatal("the session was not adopted, so this proves nothing")
	}
	behind := &ike.Session{}
	if set.initialContact(behind, contactPeer) {
		t.Error("a handshake carried INITIAL_CONTACT while the peer's session on another path was live")
	}
	set.end(behind)
	release()
	if !set.initialContact(&ike.Session{}, contactPeer) {
		t.Error("the first handshake once the peer's last session ended went without INITIAL_CONTACT")
	}
}

// a node that lost its session with no Delete, as a restart loses it, gets the path back in the next handshake on it, which it dials or answers
// that handshake carries INITIAL_CONTACT, which ends the stale session at the other end without a Delete
// dialing, the node loses the session both ends prefer, which the rule alone keeps at the other end until dead peer detection
// answering, the node loses the one it dialed, and the other end dials once it reads that one as dead
func TestNodeThatLostItsSessionGetsThePathBackInOneHandshake(t *testing.T) {
	for _, dials := range []bool{true, false} {
		t.Run(map[bool]string{true: "dialing", false: "answering"}[dials], func(t *testing.T) {
			alpha, bravo := newLoopbackMesh(t)
			// keeper is the end whose dial both ends prefer
			keeper, loser := alpha, bravo
			if !preferInitiator(identity.MustParse("example/"+alpha.name+":0"), identity.MustParse("example/"+bravo.name+":0")) {
				keeper, loser = bravo, alpha
			}
			quiet := *keeper.cfg
			if !dials {
				// the loser dials the first session alone and not again, and the keeper dials once the test asks
				quiet.Dial.To = nil
				keeper.client.cfg.Store(&quiet)
				loser.client.dialRetry = longDialRetry
			}
			run(t, alpha, bravo)
			waitFor(t, convergeBudget, "both ends holding one session", func() bool {
				a, aok := preferenceOf(alpha)
				b, bok := preferenceOf(bravo)
				return aok && bok && a == b && a == dials
			})
			lost, stale := loser.client.sessions.snapshot()[0], keeper.client.sessions.snapshot()[0]
			if !loser.client.sessions.take(lost.path, lost.session) {
				t.Fatal("the losing end's session left its set before the test took it")
			}
			lost.session.Mux().Close()
			if dials {
				loser.client.wakeDialers(loser.client.matchingDialers(lost.path, false))
			} else {
				set := keeper.client.sessions
				set.mu.Lock()
				set.active = func(sess *ike.Session) bool { return sess != stale.session }
				set.mu.Unlock()
				keeper.client.cfg.Store(keeper.cfg)
				keeper.client.syncPeers()
			}

			waitFor(t, convergeBudget, "the end that kept the stale session to end it at the notice", func() bool {
				for _, closed := range recorded(keeper.events, "ike.sa.closed") {
					if closed.Peer == stale.path && closed.Attrs["reason"] == "initial contact" {
						return true
					}
				}
				return false
			})
			waitFor(t, convergeBudget, "both ends holding the new session", func() bool {
				held := keeper.client.sessions.snapshot()
				a, aok := preferenceOf(alpha)
				b, bok := preferenceOf(bravo)
				return len(held) == 1 && held[0].session != stale.session && aok && bok && a == b
			})
		})
	}
}

// on the set as it runs, a handshake to the peer holds the notice back from its decision until its mux closes
// a second dialed beside the first carries no INITIAL_CONTACT, and the next once both muxes closed carries it
// a handshake whose Child SA the tunnel refused still holds it back while it is being closed, its mux still open
func TestInitialContactWaitsForTheMuxOfEveryHandshakeToThePeer(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	for _, node := range []*loopbackNode{alpha, bravo} {
		quiet := *node.cfg
		quiet.Dial.To = nil
		node.client.cfg.Store(&quiet)
	}
	set := alpha.client.sessions
	var mu sync.Mutex
	var carried []bool
	decide := func(sess *ike.Session, peer identity.Identity) bool {
		sent := set.contact(sess, peer)
		mu.Lock()
		defer mu.Unlock()
		carried = append(carried, sent)
		return sent
	}
	last := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return carried[len(carried)-1]
	}
	// the set closes a session whose Child SA the tunnel refused, and before it does a handshake to the peer is dialed beside it
	var ctx context.Context
	var refused, beside *ike.Session
	closeSession := set.close
	set.close = func(sess *ike.Session) {
		if sess == refused {
			beside, _, _, _ = dialOnce(t, ctx, alpha, decide)
		}
		closeSession(sess)
	}
	ctx, _ = run(t, alpha, bravo)

	first, _, _, _ := dialOnce(t, ctx, alpha, decide)
	if !last() {
		t.Error("the first handshake to the peer went without INITIAL_CONTACT")
	}
	second, _, _, _ := dialOnce(t, ctx, alpha, decide)
	if last() {
		t.Error("a handshake beside another to the peer whose mux is open carried INITIAL_CONTACT")
	}
	first.Mux().Close()
	second.Mux().Close()
	sess, local, remote, key := dialOnce(t, ctx, alpha, decide)
	if !last() {
		t.Error("the first handshake once every other one's mux closed went without INITIAL_CONTACT")
	}

	refused = sess
	child := sess.Child()
	child.EncrID = 0
	if err := alpha.client.serveSession(ctx, sess, child, local, remote, key, true); err == nil {
		t.Fatal("alpha served a session whose Child SA its tunnel could not install")
	}
	if beside == nil {
		t.Fatal("the refused session was not closed through the set, so this proves nothing")
	}
	defer beside.Mux().Close()
	if last() {
		t.Error("a handshake beside one whose Child SA was refused and whose mux was still open carried INITIAL_CONTACT")
	}
}

// a session of the path adopted after the notice's session started and before that session's adopt comes from a dial that crossed the notice's, and the rule settles the two
// keeper, the end whose dial both ends prefer, answers the other end's notice and holds that handshake past its decision until its own crossing dial holds the path
// the crossing session stays at both ends, and neither ends a session at the notice
func TestCrossingSessionTakenAfterTheNoticeStartedStays(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	keeper, loser := alpha, bravo
	if !preferInitiator(identity.MustParse("example/"+alpha.name+":0"), identity.MustParse("example/"+bravo.name+":0")) {
		keeper, loser = bravo, alpha
	}
	quiet := *keeper.cfg
	quiet.Dial.To = nil
	keeper.client.cfg.Store(&quiet)
	set := keeper.client.sessions
	decide := set.contact
	held, release := make(chan *ike.Session, 1), make(chan struct{})
	var first atomic.Bool
	set.contact = func(sess *ike.Session, peer identity.Identity) bool {
		sent := decide(sess, peer)
		if first.CompareAndSwap(false, true) {
			held <- sess
			<-release
		}
		return sent
	}
	run(t, alpha, bravo)
	// let go before the nodes stop, however the test ends
	letGo := sync.OnceFunc(func() { close(release) })
	t.Cleanup(letGo)
	var notice *ike.Session
	select {
	case notice = <-held:
	case <-time.After(convergeBudget):
		t.Fatal("the loser's first handshake never reached keeper's decision")
	}
	keeper.client.cfg.Store(keeper.cfg)
	keeper.client.syncPeers()
	var crossing *ike.Session
	waitFor(t, convergeBudget, "keeper's crossing session holding the path", func() bool {
		if live := set.snapshot(); len(live) == 1 {
			crossing = live[0].session
		}
		return crossing != nil
	})
	letGo()
	// keeper's adopt of the notice's session ends one of the two, the notice's by the rule or the crossing one at the notice
	waitFor(t, convergeBudget, "keeper to settle the notice's session against the crossing one", func() bool {
		return notice.Mux().IsClosed() || crossing.Mux().IsClosed()
	})
	if !notice.InitialContact() {
		t.Fatal("the loser's first handshake carried no INITIAL_CONTACT, so this proves nothing")
	}
	if crossing.Mux().IsClosed() {
		t.Fatal("the notice ended keeper's crossing session, which was taken after the notice's session started and which the other end still holds")
	}
	waitFor(t, convergeBudget, "keeper to turn the notice's session away", func() bool { return notice.Mux().IsClosed() })
	if live := set.snapshot(); len(live) != 1 || live[0].session != crossing {
		t.Error("keeper's path is not held by the crossing session")
	}
	waitFor(t, convergeBudget, "the loser holding the crossing session", func() bool {
		preferred, ok := preferenceOf(loser)
		return ok && preferred
	})
	for _, node := range []*loopbackNode{keeper, loser} {
		for _, closed := range recorded(node.events, "ike.sa.closed") {
			if closed.Attrs["reason"] == "initial contact" {
				t.Errorf("%s ended a session at the notice: %+v", node.name, closed)
			}
		}
	}
}

// the notice deletes the session of its own path that was adopted before the notice's SA started, whatever the rule would keep, with no Delete
// a session of that path adopted since, from a dial that crossed the notice's, is settled by the rule as before, and another path's session stays
func TestInitialContactEndsTheOlderSessionOfItsPathAlone(t *testing.T) {
	t.Run("older", func(t *testing.T) {
		set := newContactSet(t)
		older, elsewhere, notice := &ike.Session{}, &ike.Session{}, &ike.Session{}
		set.take(contactPeer, older, true, time.Time{})
		set.take(contactSecond, elsewhere, true, time.Time{})
		started := set.live[identity.Path(contactPeer, contactLocal)].adopted.Add(time.Millisecond)
		if _, adopted := set.take(contactPeer, notice, false, started); !adopted {
			t.Fatal("the notice's session lost to the session its peer no longer holds")
		}
		if len(set.dropped) != 1 || set.dropped[0] != older || len(set.closed) != 0 {
			t.Errorf("the set dropped %v and closed %v, want the older session dropped without a Delete and nothing closed", set.dropped, set.closed)
		}
		if set.live[identity.Path(contactPeer, contactLocal)].session != notice {
			t.Error("the notice's path is not held by the notice's session")
		}
		if set.live[identity.Path(contactSecond, contactLocal)].session != elsewhere {
			t.Error("the notice ended the peer's session on another path")
		}
	})
	t.Run("newer", func(t *testing.T) {
		set := newContactSet(t)
		crossing, notice := &ike.Session{}, &ike.Session{}
		set.take(contactPeer, crossing, true, time.Time{})
		started := set.live[identity.Path(contactPeer, contactLocal)].adopted.Add(-time.Millisecond)
		if _, adopted := set.take(contactPeer, notice, false, started); adopted {
			t.Error("the notice's session took the path from a preferred one adopted after it started")
		}
		if len(set.dropped) != 0 || len(set.closed) != 1 || set.closed[0] != notice {
			t.Errorf("the set dropped %v and closed %v, want the notice's session closed by the rule and nothing dropped", set.dropped, set.closed)
		}
		if set.live[identity.Path(contactPeer, contactLocal)].session != crossing {
			t.Error("the crossing session no longer holds the path")
		}
	})
}
