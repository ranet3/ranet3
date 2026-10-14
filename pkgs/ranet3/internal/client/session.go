// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"log/slog"
	"slices"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// serveSession runs one established IKE SA until it ends, whichever end opened it, and dialed says this node did
// the resolution against a competing session happens here, since the babel registration goes in under the same decision
// it returns errSessionEstablished when another session already holds the path, which is not a failure
func (c *Client) serveSession(ctx context.Context, sess *ike.Session, local, remote identity.Identity, dialed bool) error {
	defer sess.Mux().Close()
	sessionName := identity.Path(remote, local)
	log.Printf("peer %s: connected (SPI %08x/%08x)", sessionName, sess.Child.LocalSPI, sess.Child.RemoteSPI)
	role := "responder"
	if dialed {
		role = "initiator"
	}
	// read before adopt publishes the session, after which a rekey may write sess.Child
	established := []slog.Attr{slog.String("role", role),
		slog.String("spi_in", fmt.Sprintf("%08x", sess.Child.LocalSPI)), slog.String("spi_out", fmt.Sprintf("%08x", sess.Child.RemoteSPI))}

	tunnel := &tunnel{replayWindow: c.config().Crypto().ReplayWindow(), started: time.Now()}
	tunnel.askedAt.Store(-int64(rekeyAskInterval))
	// requestRekey owns the goroutine and the one-at-a-time guard, and this may block
	// a failed rekey leaves the IKE SA up, as RFC 7296 section 1.3.1 asks, and the schedule retries
	tunnel.rekey = func() {
		if err := sess.RekeyChildProactively(); err != nil && !sess.Mux().IsClosed() {
			log.Printf("peer %s: proactive Child SA rekey: %v", sessionName, err)
		}
	}
	if err := tunnel.install(sess.Child); err != nil {
		return err
	}
	sess.SetChildHandler(tunnel.install)
	sess.SetChildRetireHandler(tunnel.retire)
	pmtu := newPathDriver(sess.Mux(), c.speaker.Probe, c.events, &c.probes, c.Mesh.Steering, cmp.Or(c.probeTimeout, defaultProbeTimeout), cmp.Or(c.confirmEvery, confirmInterval))
	peer := netstack.NewPeer(sessionName, func(count int) (netstack.BatchSealer, error) {
		sealer, err := tunnel.reserve(count)
		// closing the mux withdraws every route through this peer, which fatalReserveError keeps to the refusals that deserve it
		if fatalReserveError(err) {
			_ = sess.Mux().Close()
		}
		return sealer, err
	}, pmtu.transmit, c.events.Emit)
	pmtu.peer = peer
	// the mux closes before Peer.Close, which waits with no deadline for a sender that may be inside SendESPBatch on it
	defer func() {
		_ = sess.Mux().Close()
		peer.Close()
	}()
	route := pmtu.open()
	release, adopted := c.sessions.adopt(sessionName, sess, local, remote, dialed, pmtu, func() func() {
		// under the set's lock, so a reload's sweep of the set either finds this session or stored the link.mtu read here
		pmtu.start(c.config().Link.SessionMTU(), route)
		return c.speaker.AddPeer(peer).Close
	})
	defer release()
	if !adopted {
		return errSessionEstablished
	}
	// recorded once the session holds its path, so one that lost the path is recorded only as resolved
	c.events.Emit("ike.session.established", sessionName, established...)
	// without a Delete the peer sends into a dead SPI until its liveness check expires, up to seventy seconds
	defer c.tellDropped(ctx, sessionName, sess)

	var plain [][]byte
	emit := func(results []inboundDecrypted) {
		esp.CommitBatch(results)
		plain = plain[:0]
		mtu := peer.MTU()
		var dropped int
		var lastError error
		for _, result := range results {
			raw, nextHeader, err := result.Plaintext()
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			sess.NoteTraffic()
			inner, deliver, err := validateESPTunnelPayload(raw, nextHeader)
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			if deliver && !c.speaker.Receive(peer, inner) {
				// a SYN from the peer has its MSS lowered to what this session carries back to it
				c.Mesh.ClampMSS(inner, mtu)
				plain = append(plain, inner)
			}
		}
		if dropped > 0 {
			c.noteInboundDropped(sessionName, dropped, lastError)
		}
		c.countInbound(len(results) - dropped)
		c.Mesh.DeliverInboundBatch(plain, mtu)
		clear(plain)
	}
	results := make(chan sessionResult, 2)
	go func() { results <- sessionResult{"IKE control", sess.Run(ctx)} }()
	go func() {
		results <- sessionResult{"ESP receive", receiveESP(sess.Mux(), c.workers, tunnel.decryptBatch, emit)}
	}()
	first := pmtu.serve(results)
	_ = sess.Mux().Close()
	<-results
	ended := fmt.Errorf("%s session ended: %w", first.component, first.err)
	if ctx.Err() != nil {
		ended = ctx.Err()
	}
	// with the role and the SPIs its established event carried, so a reader pairs the two across a replacement
	c.events.Emit("ike.session.ended", sessionName, append(established, slog.String("err", ended.Error()))...)
	return ended
}

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
// handshakes finish in. Only when the two sessions are equally preferred,
// which is a genuine reconnect rather than a collision, does the newer one
// win.
type sessionSet struct {
	mu   sync.Mutex
	live map[string]*liveSession
	// shut refuses any further session once the node is going. A handshake
	// still in flight completes after closeAll has swept, and without this it
	// would install a session nobody is left to tell the peer about.
	shut bool

	// close is closeSession, active is (*ike.Session).Active and rekey is
	// (*ike.Session).RekeyChildProactively in production. A test drives the
	// resolution rule and the rekey verb without standing up two real SAs by
	// replacing them.
	close  func(*ike.Session)
	active func(*ike.Session) bool
	rekey  func(*ike.Session) error
	// probe is (*ike.Session).Probe in production, replaced the same way
	probe func(*ike.Session)
	// endpoint is the address a session's mux sends to in production, replaced the same way
	endpoint func(*ike.Session) string

	// events records each resolution between two sessions for one path, and each session the trust refuses
	events *events.Bus

	// trust is the trust in force, which adopt and revoke ask under mu, so a session adopted after a reload's sweep answers to the document that reload stored
	trust ike.Trust
}

type liveSession struct {
	session   *ike.Session
	preferred bool
	// the endpoints the two ends authenticated as, and revoke asks the trust about peer's node
	peer, local identity.Identity
	// pmtu is the search of the session's path MTU, which sets the MTU of its peer in the mesh
	pmtu *pathDriver
}

func newSessionSet() *sessionSet {
	return &sessionSet{
		live:     make(map[string]*liveSession),
		close:    closeSession,
		active:   (*ike.Session).Active,
		rekey:    (*ike.Session).RekeyChildProactively,
		probe:    (*ike.Session).Probe,
		endpoint: func(sess *ike.Session) string { return sess.Mux().Endpoint().String() },
	}
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
	}
}

// adopt makes sess the live session for path unless a session both ends prefer already holds it, and reports whether it did
// the rule reads only the SA's two roles, which dialed tells apart and both ends compute alike, and never whether the incumbent looks alive
// a caller told false has lost and its mux is closed, and the release it gets drops the entry only while the entry is still sess
func (s *sessionSet) adopt(path string, sess *ike.Session, local, remote identity.Identity, dialed bool, pmtu *pathDriver, attach func() func()) (func(), bool) {
	initiator, responder := remote, local
	if dialed {
		initiator, responder = local, remote
	}
	return s.adoptFor(path, sess, preferInitiator(initiator, responder), local, remote, pmtu, attach)
}

// adoptPreferred is adopt with the rule already applied and no peer identity,
// for a test that drives the resolution without two identities to derive it
// from.
func (s *sessionSet) adoptPreferred(path string, sess *ike.Session, preferred bool, attach func() func()) (func(), bool) {
	return s.adoptFor(path, sess, preferred, identity.Identity{}, identity.Identity{}, nil, attach)
}

func (s *sessionSet) adoptFor(path string, sess *ike.Session, preferred bool, local, remote identity.Identity, pmtu *pathDriver, attach func() func()) (func(), bool) {
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		// Told rather than dropped: this handshake finished after the node
		// started going, and its peer would otherwise carry the session until
		// its own dead peer detection expires, which is over a minute.
		s.close(sess)
		return func() {}, false
	}
	if err := s.refuses(remote); err != nil {
		s.mu.Unlock()
		log.Printf("peer %s: %v, closing the session", path, err)
		s.revoked(path, "handshake", sess, remote, err)
		s.close(sess)
		return func() {}, false
	}
	previous := s.live[path]
	if previous != nil && previous.session != sess && previous.preferred && !preferred {
		s.mu.Unlock()
		log.Printf("peer %s: keeping the session the other end also prefers", path)
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
	s.live[path] = &liveSession{session: sess, preferred: preferred, peer: remote, local: local, pmtu: pmtu}
	s.mu.Unlock()
	if previous != nil && previous.session != sess {
		log.Printf("peer %s: replacing the previous session", path)
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
		out = append(out, liveSessionView{path: path, session: live.session, preferred: live.preferred, peer: live.peer, local: live.local, pmtu: live.pmtu})
	}
	return out
}

// holds reports whether a session that has recently proved the peer is there
// serves this path, which lets a dialer stand down instead of opening a second
// one that would only be resolved away. A session that has stopped proving it
// does not count, so a dialer takes over from a dead one instead of waiting
// out dead peer detection behind it.
func (s *sessionSet) holds(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live[path]
	return live != nil && s.active(live.session)
}

// relink hands every live session's search the link.mtu a reload stored
func (s *sessionSet) relink(link int) {
	if s == nil {
		return // a Client built by hand in a test carries no sessions
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, live := range s.live {
		if live.pmtu != nil {
			live.pmtu.relink(link)
		}
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
// there serves, which is the same test holds applies to one path. A Client
// built by hand in a test carries no set and reports none.
func (s *sessionSet) liveCount() int {
	if s == nil {
		return 0
	}
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

// refuses is why the trust in force no longer admits remote's node, asked under mu, or nil for a session that named no peer
// it asks about the node alone, since a serial selects which endpoint a dial uses and renumbering one is a registry edit rather than a revocation
func (s *sessionSet) refuses(remote identity.Identity) error {
	if remote.IsZero() {
		return nil
	}
	_, err := s.trust.Key(remote.Node())
	return err
}

// revoke closes every live session whose peer's node the trust in force no longer admits, and reports which paths went
// a reload is the only moment this node learns a node left the mesh, and the handshake check alone refuses only the next session
func (s *sessionSet) revoke() []string {
	if s == nil {
		return nil // a Client built by hand in a test carries no sessions
	}
	type refused struct {
		path string
		live *liveSession
		err  error
	}
	s.mu.Lock()
	var gone []refused
	for path, live := range s.live {
		if err := s.refuses(live.peer); err != nil {
			gone = append(gone, refused{path, live, err})
			delete(s.live, path)
		}
	}
	s.mu.Unlock()
	paths := make([]string, 0, len(gone))
	var closing sync.WaitGroup
	for _, session := range gone {
		paths = append(paths, session.path)
		s.revoked(session.path, "reload", session.live.session, session.live.peer, session.err)
		closing.Go(func() { s.close(session.live.session) })
	}
	closing.Wait()
	slices.Sort(paths)
	return paths
}

func (s *sessionSet) revoked(path, reason string, sess *ike.Session, peer identity.Identity, err error) {
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
	if s == nil {
		return nil // a Client built by hand in a test carries no sessions
	}
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

// matching runs act on every live session naming one peer, or every session at all, and reports their paths sorted
func (s *sessionSet) matching(peer string, all bool, act func(liveSessionView)) []string {
	if s == nil {
		return nil
	}
	var paths []string
	for _, live := range s.snapshot() {
		if all || identity.Names(live.path, peer) {
			paths = append(paths, live.path)
			act(live)
		}
	}
	slices.Sort(paths)
	return paths
}

// startRekey asks one session to replace its Child SA
//
// Each exchange runs on its own and none of them is waited for. A rekey is two
// messages and a retransmit schedule against a peer that may be gone, so
// waiting would make the answer to a mesh-wide ask depend on its least
// reachable member. The new SPIs appear under Sessions as each one lands.
func (s *sessionSet) startRekey(live liveSessionView) {
	go func() {
		if err := s.rekey(live.session); err != nil {
			log.Printf("peer %s: rekey asked for on the control socket: %v", live.path, err)
		}
	}()
}

// startProbe asks one session to prove its path now, and its search to confirm the budget
// a probe never blocks, so the answer comes before any of the liveness checks it starts
func (s *sessionSet) startProbe(live liveSessionView) {
	s.probe(live.session)
	if live.pmtu != nil {
		live.pmtu.confirmNow()
	}
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
