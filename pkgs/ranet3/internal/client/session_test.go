// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"crypto/ed25519"
	"maps"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
)

// adoptedPeer is the peer of every session adoptPreferred adopts, verified under adoptedKey
var adoptedPeer, adoptedKey = identity.MustParse("example/adopted:0"), seeded(9)

// adoptPreferred is adopt with the rule already applied, for a test that drives the resolution without two identities to derive it from
// the session's peer is adoptedPeer, which the set's trust is widened to admit, so adopt and revoke still ask the trust about it
func (s *sessionSet) adoptPreferred(path string, sess *ike.Session, preferred bool, attach func() func()) (func(), bool) {
	s.mu.Lock()
	if _, widened := s.trust.(adoptedTrust); !widened {
		s.trust = adoptedTrust{s.trust}
	}
	s.mu.Unlock()
	return s.adoptFor(path, sess, preferred, false, time.Time{}, identity.Identity{}, adoptedPeer, adoptedKey, nil, attach)
}

// adoptedTrust admits adoptedPeer's node under adoptedKey and asks held about every other node
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
	if _, ok := set.adopt(identity.Path(identity.Identity{}, local), refused, local, identity.Identity{}, nil, true, nil, nil); ok {
		t.Error("a session naming no peer was adopted")
	}

	held := &ike.Session{}
	set.mu.Lock()
	set.live["@1"] = &liveSession{session: held, local: identity.MustParse("example/local:1")}
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
