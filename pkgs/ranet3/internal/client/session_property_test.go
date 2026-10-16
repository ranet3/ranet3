// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"crypto/ed25519"
	"fmt"
	"maps"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// trustPool is the nodes the sessions of these properties are with, in two organizations that both name a node a
var trustPool = [...]struct{ org, name string }{{"alpha", "a"}, {"alpha", "b"}, {"bravo", "a"}, {"bravo", "c"}}

// trustKeys is the keys a trust holds a node under and a session was verified with
var trustKeys = []ed25519.PublicKey{seeded(1), seeded(2), seeded(3)}

// what a reload does to one node of the pool
const (
	keepsNode = iota
	changesKey
	dropsNode
	renumbersSerial
	reloadChanges
)

// trustedNode is one node of the pool as a trust document holds it
type trustedNode struct {
	org, name string
	listed    bool
	// key indexes trustKeys
	key     int
	serials []string
}

// refusal is the error a trust holding node gives a session of it verified under trustKeys[key], or "" where it admits the session
func (node trustedNode) refusal(key int) string {
	switch {
	case !node.listed:
		return fmt.Sprintf("registry: %s/%s is not in the trust document", node.org, node.name)
	case node.key != key:
		return fmt.Sprintf("the trust document holds another key for %s/%s", node.org, node.name)
	}
	return ""
}

// drawReload draws the trust before a reload and after it, the pool's nodes going through every change a reload makes, one each
func drawReload(ht *hegel.T) (before, after []trustedNode) {
	rotation := hegel.Draw(ht, pbt.Spanning(0, reloadChanges-1))
	for i, node := range trustPool {
		was := trustedNode{org: node.org, name: node.name, listed: true, key: hegel.Draw(ht, pbt.Spanning(0, len(trustKeys)-1)), serials: []string{"0", "1"}}
		now := was
		switch (i + rotation) % reloadChanges {
		case changesKey:
			now.key = (was.key + hegel.Draw(ht, pbt.Spanning(1, len(trustKeys)-1))) % len(trustKeys)
		case dropsNode:
			now.listed = false
		case renumbersSerial:
			now.serials = []string{"0", "2"}
		}
		before, after = append(before, was), append(after, now)
	}
	return before, after
}

// indexOf is the trust document holding nodes as they say, one block for each node it lists
func indexOf(ht *hegel.T, nodes []trustedNode) *registry.Index {
	var document registry.Registry
	for _, node := range nodes {
		if !node.listed {
			continue
		}
		listed := registry.Node{CommonName: node.name}
		for _, serial := range node.serials {
			listed.Endpoints = append(listed.Endpoints, registry.Endpoint{SerialNumber: serial, AddressFamily: "ip4", Port: 13000})
		}
		document = append(document, registry.Organization{Organization: node.org, PublicKey: keyPEM(trustKeys[node.key]), Nodes: []registry.Node{listed}})
	}
	x, err := registry.New(document)
	if err != nil {
		ht.Fatalf("%v", err)
	}
	return x
}

// drawnSession is a session with node trustPool[node], verified under trustKeys[key]
type drawnSession struct {
	path        string
	node        int
	peer, local identity.Identity
	key         int
	dialed      bool
	session     *ike.Session
}

// drawSessions draws whether a session runs between each endpoint the trust before a reload lists and each of this node's two
// a session's key is its node's key before the reload or any key
func drawSessions(ht *hegel.T, before []trustedNode) []drawnSession {
	var drawn []drawnSession
	for i, node := range before {
		for _, serial := range node.serials {
			for _, localSerial := range []string{"0", "1"} {
				if !hegel.Draw(ht, hegel.Booleans()) {
					continue
				}
				peer, local := identity.MustParse(node.org+"/"+node.name+":"+serial), identity.MustParse("alpha/self:"+localSerial)
				key := node.key
				if hegel.Draw(ht, hegel.Booleans()) {
					key = hegel.Draw(ht, pbt.Spanning(0, len(trustKeys)-1))
				}
				drawn = append(drawn, drawnSession{path: identity.Path(peer, local), node: i, peer: peer, local: local, key: key,
					dialed: hegel.Draw(ht, hegel.Booleans()), session: &ike.Session{}})
			}
		}
	}
	return drawn
}

// drawnRefusal is a session the model refuses and the attributes of its ike.session.revoked
type drawnRefusal struct {
	session *ike.Session
	attrs   map[string]string
}

// expectSessions checks that set holds exactly kept, by path, and closed exactly the sessions of refused, each once
// and that it recorded one ike.session.revoked at each path of refused, with the attributes refused gives it
func expectSessions(ht *hegel.T, set *sessionSet, closed *closedSessions, kept map[string]*ike.Session, refused map[string]drawnRefusal) {
	held := make(map[string]*ike.Session, len(set.live))
	for path, live := range set.live {
		held[path] = live.session
	}
	if !maps.Equal(held, kept) {
		ht.Fatalf("the set holds %v, want %v", held, kept)
	}
	gone, told := make(map[*ike.Session]bool), make(map[*ike.Session]bool)
	for _, refusal := range refused {
		gone[refusal.session] = true
	}
	all := closed.all()
	for _, sess := range all {
		told[sess] = true
	}
	if len(all) != len(refused) || !maps.Equal(told, gone) {
		ht.Fatalf("the set closed %d sessions, want exactly the %d it refused, each once", len(all), len(refused))
	}
	revoked := recorded(set.events, "ike.session.revoked")
	if len(revoked) != len(refused) {
		ht.Fatalf("the set recorded %v, want one revocation at each of %v", revoked, refused)
	}
	for _, event := range revoked {
		if want, ok := refused[event.Peer]; !ok || !maps.Equal(event.Attrs, want.attrs) {
			ht.Fatalf("the set recorded %v at %s, want %v", event.Attrs, event.Peer, want.attrs)
		}
	}
}

// a reload's sweep keeps exactly the sessions whose node the trust it stored holds under the key that verified them, whichever end dialed and at whichever endpoint
// and closes every other one with its ike.session.revoked
func TestRevokeKeepsExactlyTheSessionsTheTrustHoldsUnderTheirKey(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		before, after := drawReload(ht)
		set, closed := revokingSet()
		drawn := drawSessions(ht, before)
		for _, s := range drawn {
			set.trust = admittingUnder(trustKeys[s.key], s.peer)
			if _, ok := set.adopt(s.path, s.session, s.local, s.peer, trustKeys[s.key], s.dialed, nil, nil); !ok {
				ht.Fatalf("%s was refused under a trust holding its key, so this proves nothing", s.path)
			}
		}
		set.trust = indexTrust{indexOf(ht, after)}
		set.revoke()
		kept, refused := make(map[string]*ike.Session), make(map[string]drawnRefusal)
		for _, s := range drawn {
			if why := after[s.node].refusal(s.key); why != "" {
				refused[s.path] = drawnRefusal{s.session, map[string]string{"reason": "reload", "peer": s.peer.String(), "endpoint": set.endpoint(s.session), "err": why}}
			} else {
				kept[s.path] = s.session
			}
		}
		expectSessions(ht, set, closed, kept, refused)
	})
}

// adopt admits a handshake exactly when the trust in force holds its peer's node under the key that verified it, whichever end dialed and at whichever endpoint
// so a handshake verified before a reload and adopted after its sweep answers to the trust the reload stored, and each refusal is recorded
func TestAdoptAdmitsExactlyTheHandshakesTheTrustHoldsUnderTheirKey(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		before, after := drawReload(ht)
		set, closed := revokingSet()
		set.trust = indexTrust{indexOf(ht, after)}
		kept, refused := make(map[string]*ike.Session), make(map[string]drawnRefusal)
		for _, s := range drawSessions(ht, before) {
			_, admitted := set.adopt(s.path, s.session, s.local, s.peer, trustKeys[s.key], s.dialed, nil, nil)
			why := after[s.node].refusal(s.key)
			if admitted != (why == "") {
				ht.Fatalf("%s verified under key %d was admitted %t under %+v", s.path, s.key, admitted, after[s.node])
			}
			if admitted {
				kept[s.path] = s.session
			} else {
				refused[s.path] = drawnRefusal{s.session, map[string]string{"reason": "handshake", "peer": s.peer.String(), "endpoint": set.endpoint(s.session), "err": why}}
			}
		}
		expectSessions(ht, set, closed, kept, refused)
	})
}
