// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// what one step of the property does short of a restart
const (
	contactDials = iota
	contactSettles
	contactEnds
	contactSteps
)

// contactRestartOdds is 1 in how many steps restarts the node, rare enough that the runs between restarts reach a session's end and the dial after it
const contactRestartOdds = 8

// contactEndpoints is the 2 paths to 1 peer node and 1 path to another, which the steps draw from
var contactEndpoints = []identity.Identity{contactPeer, contactSecond, contactOther}

// contactHandshake is a handshake of the model past its IKE_AUTH decision, to endpoint
type contactHandshake struct {
	session  *ike.Session
	endpoint identity.Identity
}

// contactLive is a session the model holds on a path, with whether both ends prefer it and an instant before its adopt
type contactLive struct {
	contactHandshake
	preferred bool
	before    time.Time
}

// contactRelease is the release of a session adopted on path
type contactRelease struct {
	path    string
	session *ike.Session
	release func()
}

// over dials, crossings, failures, session ends and restarts on 2 paths to 1 peer, an IKE_AUTH carries INITIAL_CONTACT exactly when the model holds no SA to the peer's node:
// no session it holds live and no handshake past its decision that has neither been adopted nor failed
// so at most 1 handshake to a peer carries it while this node holds no SA to it, and none does otherwise
// the model keeps its own sessions by path, each adopted where the path is free, the notice's session started after the path's was adopted, or the rule lets it replace that one
func TestInitialContactGoesOutExactlyWhileNoSAToThePeerExists(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		set := newContactSet()
		var open []contactHandshake
		live := map[string]contactLive{}
		var releases []contactRelease
		holds := func(node identity.Identity) bool {
			if slices.ContainsFunc(open, func(h contactHandshake) bool { return h.endpoint.Node() == node }) {
				return true
			}
			for _, l := range live {
				if l.endpoint.Node() == node {
					return true
				}
			}
			return false
		}
		drawn := func(n int) int { return hegel.Draw(ht, pbt.Spanning(0, n-1)) }
		for range hegel.Draw(ht, pbt.Spanning(1, 40)) {
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/contactRestartOdds)) {
				set, open, live, releases = newContactSet(), nil, map[string]contactLive{}, nil
				continue
			}
			switch drawn(contactSteps) {
			case contactDials:
				endpoint := contactEndpoints[drawn(len(contactEndpoints))]
				sess, want := &ike.Session{}, !holds(endpoint.Node())
				if got := set.initialContact(sess, endpoint); got != want {
					ht.Fatalf("a handshake to %s carried INITIAL_CONTACT %t, want %t, with %d handshakes under way and %d sessions live", endpoint, got, want, len(open), len(live))
				}
				open = append(open, contactHandshake{sess, endpoint})
			case contactSettles:
				if len(open) == 0 {
					continue
				}
				at := drawn(len(open))
				h := open[at]
				open = slices.Delete(open, at, at+1)
				if drawn(2) == 0 {
					set.end(h.session)
					continue
				}
				path := identity.Path(h.endpoint, contactLocal)
				previous, held := live[path]
				// no notice, or a notice whose session started after the path's session was adopted, or before it, which a crossing dial's session is
				var contact time.Time
				older := false
				switch drawn(3) {
				case 1:
					contact, older = time.Now().Add(time.Millisecond), true
				case 2:
					contact = time.Now().Add(-time.Millisecond)
					if held {
						contact = previous.before.Add(-time.Millisecond)
					}
				}
				preferred := drawn(2) == 0
				before := time.Now()
				release, adopted := set.take(h.endpoint, h.session, preferred, contact)
				want := !held || older || !(previous.preferred && !preferred)
				if adopted != want {
					ht.Fatalf("a session to %s preferred %t was adopted %t against one preferred %t, want %t", h.endpoint, preferred, adopted, previous.preferred, want)
				}
				if adopted {
					live[path] = contactLive{h, preferred, before}
					releases = append(releases, contactRelease{path, h.session, release})
				}
			case contactEnds:
				if len(releases) == 0 {
					continue
				}
				at := drawn(len(releases))
				r := releases[at]
				r.release()
				if live[r.path].session == r.session {
					delete(live, r.path)
				}
				releases = slices.Delete(releases, at, at+1)
			}
		}
	})
}
