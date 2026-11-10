// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/srv6"
)

// serveSession runs one established IKE SA until it ends, whichever end opened it
// child is the Child SA its handshake established, which the tunnel installs first
// dialed says this node did
// key is the key that verified remote's AUTH
// the resolution against a competing session happens here
// the babel registration goes in under the same decision
// it returns errSessionEstablished when another session already holds the path
// and that is not a failure
// any other end it returns as a *servedEnd
func (c *Client) serveSession(ctx context.Context, sess *ike.Session, child ike.ChildSA, local, remote identity.Identity, key ed25519.PublicKey, dialed bool) error {
	defer sess.Mux().Close()
	sessionName := identity.Path(remote, local)
	// read before adopt publishes the session
	// after that a rekey may replace the Child SA
	suite := sess.Suite()
	slog.Info(fmt.Sprintf("peer %s: connected (SPI %08x/%08x)", sessionName, child.LocalSPI, child.RemoteSPI))
	established := []slog.Attr{slog.String("role", ikeRole(dialed)),
		slog.String("spi_in", fmt.Sprintf("%08x", child.LocalSPI)), slog.String("spi_out", fmt.Sprintf("%08x", child.RemoteSPI)),
		slog.String("ike", suite.IKE()), slog.String("esp", suite.ESP())}

	tunnel := &tunnel{replayWindow: c.config().Crypto().ReplayWindow(), started: time.Now()}
	tunnel.askedAt.Store(-int64(rekeyAskInterval))
	// requestRekey owns the goroutine and the one-at-a-time guard
	// so this may block
	// RFC 7296 section 1.3.1: "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA"
	// a failed rekey leaves the IKE SA up and the schedule retries
	tunnel.rekey = func() {
		if err := sess.RekeyChildProactively(); err != nil && !sess.Mux().IsClosed() {
			slog.Warn(fmt.Sprintf("peer %s: proactive Child SA rekey: %v", sessionName, err))
		}
	}
	tunnel.spent = sess.ChildSequenceSpent
	tunnel.failed = sess.ChildFailed
	if err := tunnel.install(child); err != nil {
		c.sessions.close(sess)
		return &servedEnd{err: err}
	}
	sess.SetChildHandler(tunnel.install)
	sess.SetChildRetireHandler(tunnel.retire)
	pmtu := newPathDriver(sess.Mux(), c.speaker.Probe, c.events, &c.probes, cmp.Or(c.probeTimeout, defaultProbeTimeout), cmp.Or(c.confirmEvery, confirmInterval))
	peer := netstack.NewPeer(sessionName, tunnel.reserve, pmtu.transmit, c.events.Emit)
	pmtu.peer = peer
	// the mux closes before Peer.Close
	// Peer.Close waits with no deadline for a sender that may be inside SendESPBatch on it
	defer func() {
		_ = sess.Mux().Close()
		peer.Close()
	}()
	route := pmtu.open()
	release, adopted := c.sessions.adopt(sessionName, sess, local, remote, key, dialed, pmtu, func() func() {
		// under the set's lock
		// so a reload's sweep of the set either finds this session or stored the link.mtu and the steering table read here
		pmtu.start(c.config().Link.SessionMTU(), c.sessions.steering, route)
		return c.speaker.AddPeer(peer, remote).Close
	})
	if !adopted {
		release()
		return errSessionEstablished
	}
	c.endpointsChanged()
	defer func() {
		// out of the set first, so the pass this wakes reads the live sends without it
		release()
		c.endpointsChanged()
	}()
	// recorded once the session holds its path
	// so one that lost the path is recorded only as resolved
	c.events.Emit("ike.session.established", sessionName, established...)
	// without a Delete the peer sends into a dead SPI until its own liveness check gives up
	defer c.tellDropped(ctx, sessionName, sess)

	emit := c.inboundEmit(sessionName, sess.NoteTraffic, peer)
	results := make(chan sessionResult, 2)
	go func() { results <- sessionResult{ikeControl, sess.Run(ctx)} }()
	go func() {
		results <- sessionResult{"ESP receive", receiveESP(sess.Mux(), c.workers, tunnel.decryptBatch, emit)}
	}()
	first := pmtu.serve(results)
	_ = sess.Mux().Close()
	first = endOf(first, <-results)
	ended := fmt.Errorf("%s session ended: %w", first.component, first.err)
	if ctx.Err() != nil {
		ended = ctx.Err()
	}
	// with what its established event carried
	// so a reader pairs the two across a replacement
	c.events.Emit("ike.session.ended", sessionName, append(established, slog.String("err", ended.Error()))...)
	return &servedEnd{err: ended, held: true}
}

// servedEnd is how a session serveSession ran ended, held saying it had held its path
// the end of one that held it is the session's ordinary end, and one that ended before is a failure
type servedEnd struct {
	err  error
	held bool
}

func (e *servedEnd) Error() string { return e.err.Error() }
func (e *servedEnd) Unwrap() error { return e.err }

// inboundEmit is the emit of the session at path, which receiveESP calls on one goroutine with each batch of results in receive order
// beside the outer ECN field of each, nil when every one arrived Not-ECT, and the hold on the storage they lie in
func (c *Client) inboundEmit(path string, noteTraffic func(), peer *netstack.Peer) func([]inboundDecrypted, []inboundECN, netstack.Hold) {
	var frames [][]byte
	var ecn sessionECN
	return func(results []inboundDecrypted, outer []inboundECN, hold netstack.Hold) {
		esp.CommitBatch(results)
		frames = frames[:0]
		mtu := peer.MTU()
		var dropped int
		var lastError error
		for i, result := range results {
			// each datagram's view is this session's alone, so each packet the loop keeps goes on as a slice of the datagram it was decrypted in, under hold, and the loop copies nothing itself
			frame, nextHeader, err := result.Frame(netstack.TUNHeadroom)
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			noteTraffic()
			inner, deliver, err := validateESPTunnelPayload(frame[netstack.TUNHeadroom:], nextHeader)
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			if deliver && outer != nil && !ecn.decapsulate(inner, outer[i]) {
				dropped, lastError = dropped+1, errECNDropped
				continue
			}
			if deliver && !c.speaker.Receive(peer, inner) {
				// a SYN from the peer has its MSS lowered to what this session carries back to it
				c.Mesh.ClampMSS(inner, mtu)
				end := netstack.TUNHeadroom + len(inner)
				frames = append(frames, frame[:end:end])
			}
		}
		if dropped > 0 {
			c.noteInboundDropped(path, dropped, lastError)
		}
		c.countInbound(len(results) - dropped)
		c.settleECN(&ecn, path)
		c.Mesh.DeliverInboundBatch(frames, mtu, peer, hold)
		clear(frames)
	}
}

// endOf picks which of its two halves' ends a session reports, first being the half that ended first
// ESP receive ends only as the mux closes, so the IKE control half's end says why the session ended, the IKE SA's replacement for a new handshake among them, whichever half saw the close first
func endOf(first, second sessionResult) sessionResult {
	if second.component == ikeControl {
		return second
	}
	return first
}

const ikeControl = "IKE control"

// sessionResult is how one of a session's two halves ended, IKE's control loop or ESP's receive
type sessionResult struct {
	component string
	err       error
}

// tellDropped tells the peer a session whose dialer was dropped while the node runs is gone
// only a session the set still holds is told, so one the sweep or a replacement closed is told once
func (c *Client) tellDropped(ctx context.Context, path string, sess *ike.Session) {
	if dialerWasDropped(ctx, c.ctx) && c.sessions.take(path, sess) {
		c.sessions.close(sess)
	}
}

// sessionSet keeps at most one live SA per peer. In a full mesh every node
// dials every other one, so both ends opening an SA at once is ordinary rather
// than exceptional, and both directions land on the same path name.
//
// Newest wins is not enough to settle it. Both ends have to choose the same
// survivor, or each keeps the SA the other just closed and neither carries
// traffic until dead peer detection notices, and the end whose SA loses has to
// know not to dial straight back in, or the two take turns evicting each other
// for as long as the process runs. strongSwan's unique=replace resolves the
// far end by sending a Delete, which this does too, but it also needs a rule
// that does not depend on arrival order.
//
// preferred is that rule. Both nodes compare the same two names with
// identity.Compare and so agree on which of them should be the initiator. The
// SA opened in that direction is the one both keep, whichever order the two
// handshakes finish in. The newer session wins only when the two are equally
// preferred, which is a genuine reconnect rather than a collision, or when its
// IKE_AUTH carried the peer's INITIAL_CONTACT and the session it meets was
// adopted before it started, which the peer no longer holds.
type sessionSet struct {
	mu   sync.Mutex
	live map[string]*liveSession
	// shut refuses any further session once the node is going. A handshake
	// still in flight completes after closeAll has swept, and without this it
	// would install a session nobody is left to tell the peer about.
	shut bool

	// close is closeSession, active is (*ike.Session).Active and rekey is
	// (*ike.Session).RekeyChild in production. A test drives the
	// resolution rule and the rekey verb without standing up two real SAs by
	// replacing them.
	// rekey is the form that fails where the session starts no exchange, so the verb can say so
	close  func(*ike.Session)
	active func(*ike.Session) bool
	rekey  func(*ike.Session) error
	// rekeyWait is how long the rekey verb waits for the rekeys it asked for, control.RekeyWait unless a test shortens it
	rekeyWait time.Duration
	// probe is (*ike.Session).Probe in production, replaced the same way
	probe func(*ike.Session)
	// endpoint is the address a session's mux sends to in production, replaced the same way
	endpoint func(*ike.Session) string
	// ended is whether a handshake's mux has closed and drop is (*ike.Session).EndAtInitialContact in production, replaced the same way
	ended func(*ike.Session) bool
	drop  func(*ike.Session)
	// contact is initialContact in production, the decision both ike configs ask, replaced the same way
	contact func(*ike.Session, identity.Identity) bool

	// handshakes holds the peer's node of each handshake past its IKE_AUTH decision that adopt has not taken, under mu
	handshakes map[*ike.Session]identity.Identity

	// events records each resolution between two sessions for one path, and each session refuses turns away
	events *events.Bus

	// trust is the trust in force, which adopt and revoke ask under mu, so a session adopted after a reload's sweep answers to the document that reload stored
	trust ike.Trust
	// steering is the steering table a session checks its budget against, which a session takes at its start and relink hands every live one, under mu
	// so whether the mesh swaps its table before or after the sweep, every session ends on the table the sweep handed
	steering *srv6.SteerTable
}

type liveSession struct {
	session   *ike.Session
	preferred bool
	// dialed is whether this node sent the session's IKE_SA_INIT
	dialed bool
	// the endpoints the two ends authenticated as, and revoke asks the trust about peer's node
	peer, local identity.Identity
	// key verified peer's AUTH, and the session stays only while the trust gives peer's node that key
	key ed25519.PublicKey
	// pmtu is the search of the session's path MTU, which sets the MTU of its peer in the mesh
	pmtu *pathDriver
	// adopted is when adopt took the session
	adopted time.Time
}

// keptAgainst reports whether adopt keeps l against a session for its path that preferred tells whether both ends prefer
func (l *liveSession) keptAgainst(preferred bool) bool { return l.preferred && !preferred }

func newSessionSet() *sessionSet {
	set := &sessionSet{
		live:       make(map[string]*liveSession),
		close:      closeSession,
		active:     (*ike.Session).Active,
		rekey:      (*ike.Session).RekeyChild,
		rekeyWait:  control.RekeyWait,
		probe:      (*ike.Session).Probe,
		endpoint:   func(sess *ike.Session) string { return sess.Mux().Endpoint().String() },
		ended:      func(sess *ike.Session) bool { return sess.Mux().IsClosed() },
		drop:       (*ike.Session).EndAtInitialContact,
		handshakes: make(map[*ike.Session]identity.Identity),
	}
	set.contact = set.initialContact
	return set
}

// initialContact is the InitialContact decision of ike for sess, a handshake to peer
// its IKE_AUTH carries INITIAL_CONTACT only where this end holds no other IKE SA to peer's node on any path, live or a handshake past this decision whose mux is open
// sess counts as such a handshake from here until adopt takes it or its mux closes, so of 2 handshakes deciding at once under mu the second finds the first
// RFC 7296 section 2.4: "The INITIAL_CONTACT notification asserts that this IKE SA is the only IKE SA currently active between the authenticated identities."
func (s *sessionSet) initialContact(sess *ike.Session, peer identity.Identity) bool {
	node := peer.Node()
	s.mu.Lock()
	defer s.mu.Unlock()
	alone := true
	for other, to := range s.handshakes {
		if s.ended(other) {
			delete(s.handshakes, other)
		} else if to == node {
			alone = false
		}
	}
	for _, live := range s.live {
		alone = alone && live.peer.Node() != node
	}
	s.handshakes[sess] = node
	return alone
}

// preferInitiator reports whether, of the two nodes, the first should be the initiator
// both ends compute it from the same pair of names, so the choice agrees
func preferInitiator(initiator, responder identity.Identity) bool {
	return identity.Compare(initiator, responder) < 0
}

// ikeEvent is the ike Recorder, which records under the session's path
// a change before any peer authenticated has no path
// an endpoint change restarts the search of the session's path MTU on the new path
func (c *Client) ikeEvent(local, remote identity.Identity, kind string, attrs ...slog.Attr) {
	path := ""
	if !remote.IsZero() {
		path = identity.Path(remote, local)
	}
	c.events.Emit(kind, path, attrs...)
	if kind == "ike.endpoint.moved" {
		c.sessions.moved(path)
		c.endpointsChanged()
	}
}

// adopt makes sess the live session for path unless the rule sessionSet states keeps the session already holding it, and reports whether it did
// dialed tells the SA's two roles apart, which both ends compute alike, and the rule never asks whether the incumbent looks alive
// a caller told false has lost and its mux is closed, and the release it gets drops the entry only while the entry is still sess
func (s *sessionSet) adopt(path string, sess *ike.Session, local, remote identity.Identity, key ed25519.PublicKey, dialed bool, pmtu *pathDriver, attach func() func()) (func(), bool) {
	initiator, responder := remote, local
	if dialed {
		initiator, responder = local, remote
	}
	var contact time.Time
	if sess.InitialContact() {
		contact = sess.StartedAt()
	}
	return s.adoptFor(path, sess, preferInitiator(initiator, responder), dialed, contact, local, remote, key, pmtu, attach)
}

// adoptFor is adopt with the rule applied, and contact, where it is not zero, the start of sess, whose IKE_AUTH carried the peer's INITIAL_CONTACT
func (s *sessionSet) adoptFor(path string, sess *ike.Session, preferred, dialed bool, contact time.Time, local, remote identity.Identity, key ed25519.PublicKey, pmtu *pathDriver, attach func() func()) (func(), bool) {
	s.mu.Lock()
	delete(s.handshakes, sess)
	if s.shut {
		s.mu.Unlock()
		// Told rather than dropped: this handshake finished after the node
		// started going, and its peer would otherwise carry the session until
		// its own dead peer detection expires, which is over a minute.
		s.close(sess)
		return func() {}, false
	}
	if err := s.refuses(remote, key); err != nil {
		s.mu.Unlock()
		s.revoked(path, "handshake", sess, remote, err)
		s.close(sess)
		return func() {}, false
	}
	previous := s.live[path]
	// contacted is whether sess's IKE_AUTH carried the peer's INITIAL_CONTACT and previous was adopted before sess started
	// sess started here before the peer could decide the notice, and the peer decided it before any SA it still holds to this node passed its own IKE_AUTH, so such an SA was adopted here after sess started
	// so previous is one the peer no longer holds, while a session adopted since comes from a dial that crossed the notice's and goes to the rule below
	contacted := previous != nil && previous.session != sess && !contact.IsZero() && previous.adopted.Before(contact)
	if previous != nil && previous.session != sess && !contacted && previous.keptAgainst(preferred) {
		s.mu.Unlock()
		slog.Info(fmt.Sprintf("peer %s: keeping the session the other end also prefers", path))
		s.events.Emit("ike.session.resolved", path, slog.String("kept", "the session already held"))
		s.close(sess)
		return func() {}, false
	}
	// Whatever else this session registers under the path's name registers
	// here, while the decision is still held. Two sessions resolving against
	// each other reach this in the order they take the path, so a session
	// already replaced cannot take the babel neighbor away from the one that
	// replaced it, which would leave the speaker holding a peer whose mux is
	// closed and the adjacency down until that session unwound.
	var detach func()
	if attach != nil {
		detach = attach()
	}
	s.live[path] = &liveSession{session: sess, preferred: preferred, dialed: dialed, peer: remote, local: local, key: key, pmtu: pmtu, adopted: time.Now()}
	s.mu.Unlock()
	switch {
	case previous == nil || previous.session == sess:
	case contacted:
		slog.Info(fmt.Sprintf("peer %s: the peer's INITIAL_CONTACT on a newer session ends the one it no longer holds", path))
		s.drop(previous.session)
	default:
		slog.Info(fmt.Sprintf("peer %s: replacing the previous session", path))
		s.events.Emit("ike.session.resolved", path, slog.String("kept", "the new session"))
		s.close(previous.session)
	}
	return func() {
		s.mu.Lock()
		if current := s.live[path]; current != nil && current.session == sess {
			delete(s.live, path)
		}
		s.mu.Unlock()
		if detach != nil {
			detach()
		}
	}, true
}

// closeSession tells the peer the SA is gone and then drops it, whether or not
// the Delete was answered.
func closeSession(sess *ike.Session) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sess.DeleteIKE()
	}()
	select {
	case <-done:
	case <-time.After(deleteGrace):
	}
	_ = sess.Mux().Close()
}

// liveSessionView is one entry of the set, copied out so that a caller reads
// it without holding the lock every handshake and every teardown needs.
type liveSessionView struct {
	path        string
	session     *ike.Session
	preferred   bool
	dialed      bool
	peer, local identity.Identity
	pmtu        *pathDriver
}

// snapshot copies the live set. The sessions themselves are pointers, so a
// caller reads each one through its own accessors afterward. What the lock
// protects is the map, and it is released before any of that happens.
func (s *sessionSet) snapshot() []liveSessionView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]liveSessionView, 0, len(s.live))
	for path, live := range s.live {
		out = append(out, liveSessionView{path: path, session: live.session, preferred: live.preferred, dialed: live.dialed, peer: live.peer, local: live.local, pmtu: live.pmtu})
	}
	return out
}

// holds reports whether a session serves this path that a dial of this end's
// would only be resolved away against, which lets a dialer stand down instead
// of opening it. dialPreferred is whether adopt would prefer that dial. A
// session that has recently proved the peer is there counts, and so does a
// session both ends prefer while the dial would not be preferred, which adopt
// keeps against the dial whether or not it still proves the peer. Behind that
// one a dialer waits out its dead peer detection, the preferred end's dial
// replacing it, or the other end's INITIAL_CONTACT ending it, by the rule
// sessionSet states. Any other session that has stopped proving the peer does not
// count, so a dialer takes over from a dead one instead of waiting out dead
// peer detection behind it.
func (s *sessionSet) holds(path string, dialPreferred bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live[path]
	return live != nil && (s.active(live.session) || live.keptAgainst(dialPreferred))
}

// relink hands every live session's search the link.mtu a reload stored and the steering table in force after the reload
// installed says the reload installed steering in place of the table the set holds, which stays otherwise
func (s *sessionSet) relink(link int, installed bool, steering *srv6.SteerTable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if installed {
		s.steering = steering
	}
	for _, live := range s.live {
		live.pmtu.relink(link, s.steering)
	}
}

// resuite has every live session check its SAs against the cap.crypto lists a reload stored
// a session adopted after the sweep checks them when its Run starts
func (s *sessionSet) resuite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, live := range s.live {
		live.session.SuitesChanged()
	}
}

// probeAcked is the speaker's Runtime.ProbeAcked, which hands an Ack to the search of the session it came through
func (s *sessionSet) probeAcked(peer *netstack.Peer, nonce uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.live[peer.ID]; live != nil && live.pmtu.peer == peer {
		live.pmtu.ack(nonce)
	}
}

// moved tells the search of the session at path that IKE moved the session to another endpoint
func (s *sessionSet) moved(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.live[path]; live != nil {
		live.pmtu.move()
	}
}

// liveCount is how many paths a session that has recently proved its peer is
// there serves.
func (s *sessionSet) liveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, live := range s.live {
		if s.active(live.session) {
			count++
		}
	}
	return count
}

// refuses is why a session with remote is not admitted, asked under mu: remote names no peer, or the trust in force no longer admits remote's node under key, the key that verified it
// it asks about the node alone, since a serial selects which endpoint a dial uses and renumbering one is a registry edit rather than a revocation
func (s *sessionSet) refuses(remote identity.Identity, key ed25519.PublicKey) error {
	if remote.IsZero() {
		return errors.New("the session names no peer")
	}
	trusted, _, err := s.trust.Key(remote.Node())
	if err != nil {
		return err
	}
	if !trusted.Equal(key) {
		return fmt.Errorf("the trust document holds another key for %s", remote.Node())
	}
	return nil
}

// revoke closes every live session refuses turns away, one naming no peer or whose peer's node the trust in force no longer admits under the key that verified it
// a reload is the only moment this node learns a node left the mesh or took another key, and the handshake check alone refuses only the next session
func (s *sessionSet) revoke() {
	type refused struct {
		path string
		live *liveSession
		err  error
	}
	s.mu.Lock()
	var gone []refused
	for path, live := range s.live {
		if err := s.refuses(live.peer, live.key); err != nil {
			gone = append(gone, refused{path, live, err})
			delete(s.live, path)
		}
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, session := range gone {
		s.revoked(session.path, "reload", session.live.session, session.live.peer, session.err)
		closing.Go(func() { s.close(session.live.session) })
	}
	closing.Wait()
}

func (s *sessionSet) revoked(path, reason string, sess *ike.Session, peer identity.Identity, err error) {
	slog.Warn(fmt.Sprintf("peer %s: %v, closing the session", path, err))
	s.events.Emit("ike.session.revoked", path, slog.String("reason", reason), slog.String("peer", peer.String()),
		slog.String("endpoint", s.endpoint(sess)), slog.String("err", err.Error()))
}

// closeMatching closes every live session naming one peer, or every live
// session, and reports which went, which is the half of a redial this side can
// do about a peer holding a session this node no longer has.
//
// The entry leaves the map before the session is closed, as revoke does, so
// the dialer woken straight afterward sees the path as free rather than
// standing down behind a session that is already going. serveSession's own
// release then finds the path held by nobody and leaves it alone.
func (s *sessionSet) closeMatching(peer string, all bool) []string {
	s.mu.Lock()
	var paths []string
	var sessions []*ike.Session
	for path, live := range s.live {
		if !all && !identity.Names(path, peer) {
			continue
		}
		paths = append(paths, path)
		sessions = append(sessions, live.session)
		delete(s.live, path)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, sess := range sessions {
		closing.Go(func() { s.close(sess) })
	}
	closing.Wait()
	slices.Sort(paths)
	return paths
}

// matching runs act, nil for none, on every live session naming one peer, or every session at all, and reports their paths sorted
func (s *sessionSet) matching(peer string, all bool, act func(liveSessionView)) []string {
	var paths []string
	for _, live := range s.snapshot() {
		if all || identity.Names(live.path, peer) {
			paths = append(paths, live.path)
			if act != nil {
				act(live)
			}
		}
	}
	slices.Sort(paths)
	return paths
}

// rekeyEach has each session given replace its Child SA, all at once, and returns the paths that rekeyed and each that did not with why
// a rekey against a peer that is gone runs a whole retransmit schedule, so the answer waits rekeyWait at most, and no longer than the caller asking, and lists a rekey still running then among those that did not
func (s *sessionSet) rekeyEach(ctx context.Context, asked []liveSessionView) ([]string, []control.Missed) {
	type outcome struct {
		path string
		err  error
	}
	outcomes := make(chan outcome, len(asked))
	for _, live := range asked {
		go func() {
			err := s.rekey(live.session)
			if err != nil {
				slog.Warn(fmt.Sprintf("peer %s: rekey asked for on the control socket: %v", live.path, err))
			}
			outcomes <- outcome{live.path, err}
		}()
	}
	ended := make(map[string]error, len(asked))
	wait := time.NewTimer(s.rekeyWait)
	defer wait.Stop()
	running := "still rekeying after " + control.Spelled(s.rekeyWait)
waiting:
	for len(ended) < len(asked) {
		select {
		case o := <-outcomes:
			ended[o.path] = o.err
		case <-wait.C:
			break waiting
		case <-ctx.Done():
			running = "still rekeying when the caller went away"
			break waiting
		}
	}
	var rekeyed []string
	var missed []control.Missed
	for _, live := range asked {
		err, done := ended[live.path]
		switch {
		case !done:
			missed = append(missed, control.Missed{Entry: live.path, Reason: running + ", and ike.rekey.completed or ike.rekey.failed tells how it ends"})
		case err != nil:
			missed = append(missed, control.Missed{Entry: live.path, Reason: err.Error()})
		default:
			rekeyed = append(rekeyed, live.path)
		}
	}
	slices.Sort(rekeyed)
	slices.SortFunc(missed, func(a, b control.Missed) int { return strings.Compare(a.Entry, b.Entry) })
	return rekeyed, missed
}

// startProbe asks one session to prove its path now, and its search to confirm the budget
// a probe never blocks, so the answer comes before any of the liveness checks it starts
func (s *sessionSet) startProbe(live liveSessionView) {
	s.probe(live.session)
	live.pmtu.confirmNow()
}

// closeAll tells every live peer the session is ending and drops it, and shuts
// the set so nothing can be adopted behind the sweep. Each is closed in
// parallel, so one unreachable peer costs deleteGrace rather than deleteGrace
// per peer.
// it reports the paths it closed, sorted
func (s *sessionSet) closeAll() []string {
	s.mu.Lock()
	s.shut = true
	paths := make([]string, 0, len(s.live))
	sessions := make([]*ike.Session, 0, len(s.live))
	for path, live := range s.live {
		paths = append(paths, path)
		sessions = append(sessions, live.session)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, sess := range sessions {
		closing.Go(func() { s.close(sess) })
	}
	closing.Wait()
	// Dropped here rather than left for each serveSession to unwind, so a
	// scrape taken during shutdown does not report sessions that have already
	// been told to go.
	s.mu.Lock()
	clear(s.live)
	s.mu.Unlock()
	slices.Sort(paths)
	return paths
}

// open lets sessions into the set again after closeAll shut it, which up does before it starts anything that adopts one
func (s *sessionSet) open() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shut = false
}

// take drops path from the set where sess still holds it, and reports whether it did
// a session the set no longer holds for path, swept by closeAll or replaced, is left alone
func (s *sessionSet) take(path string, sess *ike.Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.live[path]; live != nil && live.session == sess {
		delete(s.live, path)
		return true
	}
	return false
}
