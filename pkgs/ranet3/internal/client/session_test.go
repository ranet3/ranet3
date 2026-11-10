// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"crypto/ed25519"
	"maps"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
)

var adoptedPeer, adoptedKey = identity.MustParse("example/adopted:0"), seeded(9)

// adoptPreferred is adopt with the rule already applied, for a test that drives the resolution without two identities to derive it from
// the session's peer is adoptedPeer, which the set's trust is widened to admit, so adopt and revoke still ask the trust about it
func (s *sessionSet) adoptPreferred(tb testing.TB, path string, sess *ike.Session, preferred bool, attach func() func()) (func(), bool) {
	s.mu.Lock()
	if _, widened := s.trust.(adoptedTrust); !widened {
		s.trust = adoptedTrust{s.trust}
	}
	s.mu.Unlock()
	return s.adoptFor(path, sess, preferred, false, time.Time{}, identity.Identity{}, adoptedPeer, adoptedKey, testDriver(tb, path), attach)
}

// adoptAt is adopt of sess at path with a testDriver at the same path and nothing to attach
func (s *sessionSet) adoptAt(tb testing.TB, path string, sess *ike.Session, local, remote identity.Identity, key ed25519.PublicKey, dialed bool) (func(), bool) {
	return s.adopt(path, sess, local, remote, key, dialed, testDriver(tb, path), nil)
}

// testDriver is a driver for a session at path with no mux, never opened and so never searching, its peer a sink closed when tb ends
// a reload's sweep sets the peer's MTU, and an Ack, a move or a confirmation is queued for a search that never reads it
func testDriver(tb testing.TB, path string) *pathDriver {
	d := newPathDriver(nil, nil, nil, &probeTotals{}, defaultProbeTimeout, confirmInterval)
	d.peer = sinkPeer(tb, path)
	return d
}

// caseTB is a property case's testing.TB, whose cleanups run when end is called at the case's end rather than when the test ends
type caseTB struct {
	testing.TB
	cleanups []func()
}

func (c *caseTB) Cleanup(f func()) { c.cleanups = append(c.cleanups, f) }

// end runs the case's cleanups, the last registered first
func (c *caseTB) end() {
	for _, f := range slices.Backward(c.cleanups) {
		f()
	}
}

type adoptedTrust struct{ held ike.Trust }

func (t adoptedTrust) Key(id identity.Identity) (ed25519.PublicKey, ike.Family, error) {
	if id.Node() == adoptedPeer.Node() {
		return adoptedKey, 0, nil
	}
	return t.held.Key(id)
}

// a session naming no peer is refused under a trust that admits every node, when adopted and when a reload's sweep finds it
// so no session is held that the trust was not asked about
func TestSessionNamingNoPeerIsRefusedUnderATrustAdmittingEveryNode(t *testing.T) {
	set, closed := revokingSet()
	set.trust = trustFunc(func(identity.Identity) (ed25519.PublicKey, error) { return nil, nil })
	local, refused := identity.MustParse("example/local:0"), &ike.Session{}
	if _, ok := set.adoptAt(t, identity.Path(identity.Identity{}, local), refused, local, identity.Identity{}, nil, true); ok {
		t.Error("a session naming no peer was adopted")
	}

	held := &ike.Session{}
	set.mu.Lock()
	set.live["@1"] = &liveSession{session: held, local: identity.MustParse("example/local:1"), pmtu: testDriver(t, "@1")}
	set.mu.Unlock()
	set.revoke()
	if len(set.live) != 0 {
		t.Errorf("the sweep left %d sessions live, want the one naming no peer closed", len(set.live))
	}
	if got := closed.all(); len(got) != 2 || got[0] != refused || got[1] != held {
		t.Errorf("the set closed %v, want the refused handshake and then the swept session", got)
	}
	got := recorded(set.events, "ike.session.revoked")
	if len(got) != 2 {
		t.Fatalf("the set recorded %v, want one revocation at the handshake and one at the sweep", got)
	}
	for i, want := range []struct{ path, reason string }{{"@0", "handshake"}, {"@1", "reload"}} {
		attrs := map[string]string{"reason": want.reason, "peer": "", "endpoint": "198.51.100.7:4500", "err": "the session names no peer"}
		if got[i].Peer != want.path || !maps.Equal(got[i].Attrs, attrs) {
			t.Errorf("the set recorded %v at %s, want %v at %s", got[i].Attrs, got[i].Peer, attrs, want.path)
		}
	}
}
