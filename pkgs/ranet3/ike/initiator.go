// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

// PeerConfig is one peer this node dials and everything an IKEv2 SA with it takes
// raw Ed25519 pubkey auth (RFC 7427) under the DN or an ID Aliases gives, a 0.0.0.0/0::/0 tunnel-mode Child SA and forced UDP encapsulation are fixed
// Suites picks which of the transforms the package doc lists it proposes and accepts
type PeerConfig struct {
	Local           identity.Identity
	LocalPrivateKey ed25519.PrivateKey

	Remote          identity.Identity
	RemotePublicKey ed25519.PublicKey

	// Aliases gives the ID this node sends as IDi and the one it asks for in IDr
	// and the endpoint each ID the responder may send as IDr names, which has to be Remote
	Aliases Aliases

	LocalAddr  net.IP // "" => wildcard
	LocalPort  int    // 0 => ephemeral
	RemoteAddr net.IP
	RemotePort int // ranet registry endpoint port (often non-standard, e.g. 13000), the only port ever used, IKE and ESP alike
	Hub        *transport.Hub

	ChildRekeyInterval time.Duration
	IKERekeyInterval   time.Duration
	RekeyMargin        time.Duration
	RekeyJitter        time.Duration
	RekeyRetryInitial  time.Duration
	RekeyRetryMax      time.Duration

	// Suites gives the lists in force
	// the session reads them at each exchange
	// nil runs the zero Suites
	Suites func() Suites

	// Events records the session's state changes
	// nil records nothing
	Events Recorder
}

// Recorder takes one state change of a session, with the session's two ends
// both ends are zero where no peer has authenticated yet
type Recorder func(local, remote identity.Identity, kind string, attrs ...slog.Attr)

// ChildSA is the negotiated ESP keying material and parameters handed to
// the esp package after a successful handshake.
type ChildSA = esp.ChildSA

// ikeContext contains the state bound to one IKE SA's SPI pair. During an IKE
// SA rekey, Session keeps the replaced context until its transition completes.
type ikeContext struct {
	suite       SASuite
	skD         []byte
	skei        []byte
	sker        []byte
	skpi        []byte
	skpr        []byte
	spiI        uint64
	spiR        uint64
	responder   bool // local endpoint is the responder for this IKE SA
	established time.Time
	// ownDelete marks a replaced IKE SA whose Delete this end sends, and stateMu guards it
	ownDelete bool
	// answeredAuth marks the SA whose IKE_AUTH this end answered, where the peer's request at authMID+1 is the INFORMATIONAL exchange immediately following it
	answeredAuth bool
	// authMID is the Message ID of the IKE_AUTH that made the SA, one past its IKE_INTERMEDIATE exchanges, and zero for an SA a rekey made
	// RFC 9242 section 3.2: "The Message ID for the first pair of IKE_AUTH messages is one more than the value used in the last IKE_INTERMEDIATE exchange."
	authMID uint32
	sendIV  atomic.Uint64

	// localMIDMu guards nextLocalMID across the whole allocate-send-consume
	// step. Run allocates there on its own goroutine while a caller tearing
	// the session down can be sending a Delete directly, and requestMu does
	// not serialize the two: it orders callers queueing work for Run, not Run
	// itself.
	localMIDMu         sync.Mutex
	nextLocalMID       uint32 // next Message ID we allocate for a local request
	nextPeerMID        uint32 // next Message ID expected from a peer request
	lastPeerResponseID uint32
	lastPeerResponse   []byte
}

// Session is an established IKE SA: it owns the shared UDP mux and can
// still service the peer's INFORMATIONAL exchanges (DPD liveness checks,
// deletes) for as long as the ESP Child SA is in use.
type Session struct {
	mux     *transport.Mux
	stateMu sync.RWMutex
	current *ikeContext
	old     *ikeContext
	// collision retains the candidate of a simultaneous rekey that is not
	// current: the peer's while this end's own rekey has yet to settle the
	// collision, then the losing one, this end's until its own Delete of it
	// or the peer's until the peer deletes it. The normal current/old pair
	// retains the winning candidate and the SA it replaces.
	collision *ikeContext
	// oldBy and collisionBy bound how long each is kept for the Delete that
	// ends it, the peer's or this end's, as retainedUntil gives.
	oldBy         time.Time
	collisionBy   time.Time
	localRekey    *ikeRekey
	ikeRekeyNonce func([]byte) error
	// peerChain is the peer's rekey whose additional key exchanges this end answers, nil while none is open, and stateMu guards it
	peerChain *followupChain
	// stateNotFounds counts the IKE SA rekeys in a row whose IKE_FOLLOWUP_KE the peer answered STATE_NOT_FOUND, and requestMu guards it
	stateNotFounds int
	// quiet is set while this end's IKE SA rekey may run additional key exchanges, or waits for the peer's after losing a simultaneous rekey, and Run starts no request of its own meanwhile
	// strongSwan destroys an IKE SA that takes any other request while it waits for IKE_FOLLOWUP_KE (ike_rekey.c)
	quiet atomic.Bool

	requestMu sync.Mutex // IKEv2 permits only one outstanding local request.
	requests  chan *localRequest
	// probes holds at most the one probe Run has not acted on
	probes chan struct{}
	// childRekeyEnded holds at most the one end of a Child SA rekey Run has not looked at, since Run settles every one on the Child SA schedule and one running at the Child SA's lifetime decides whether the IKE SA closes
	childRekeyEnded chan struct{}
	// childSpent holds at most the one spent sequence space Run has not looked at, and spentSPI names the Child SA it belongs to by its inbound SPI
	childSpent chan struct{}
	spentSPI   atomic.Uint32
	// childFailed holds at most the one dataplane failure Run has not looked at, and one is enough to close the IKE SA
	childFailed chan error
	// suites is the configuration's lists, nil for a session whose lists never change
	suites func() Suites
	// rechecks holds at most the one change of the lists Run has not checked the SAs against
	rechecks chan struct{}
	// sendFailures counts failed IKE sends since the last that went out, and only Run's goroutine touches it
	sendFailures int
	// answeredInvalidSyntax is set once the peer answers a request on the current IKE SA with INVALID_SYNTAX, after which Run returns, and only Run's goroutine touches it
	answeredInvalidSyntax bool

	childMu          sync.RWMutex
	Child            ChildSA
	childEstablished time.Time
	// childKex is the kex entry of the key exchanges whose secrets keyed the Child SA holding its SPI
	childKex  keyedEntry
	withdrawn []uint32
	retiring  ChildSA
	// retiringEnds is where the replaced SA's lifetime ends, which its drain does not pass
	retiringEnds time.Time
	// retiringBy bounds how long the replaced SA waits for the peer's Delete.
	retiringBy       time.Time
	retiringDeleting bool
	// Run expires replaced inbound SAs after an overlap period, allowing
	// queued and reordered ESP to finish after the Delete acknowledgment.
	retired          []childRetirement
	childRetireDelay time.Duration
	// halfClosed holds the inbound SPIs of the Child SAs whose Delete the peer refused, for the life of the session
	halfClosed []uint32

	handlerMu     sync.RWMutex
	onChild       func(ChildSA) error
	onRetire      func(uint32) error
	trafficSeen   atomic.Bool
	childRekeying atomic.Bool
	childRetry    childRetry
	// serving is true while Run is draining the request queue. Nothing else
	// drains it, so a local exchange started when this is false would wait out
	// its caller's patience and send nothing.
	serving atomic.Bool
	// closing is set from the decision to close the IKE SA and never cleared, so each IKE SA current from then is one this end is trying to close
	closing atomic.Bool
	// closed is closed with closing set, for a wait that ends there, and closedMu guards it
	closedMu sync.Mutex
	closed   chan struct{}
	// started fixes the origin lastActive is measured from. It is written
	// once, before the session is handed to anyone.
	started time.Time
	// lastActive is how long after started the peer last proved it is still
	// there, in nanoseconds, plus one so that zero still reads as never: the
	// moment the SA was established, then every piece of authenticated
	// traffic and every answered exchange after it.
	//
	// An offset rather than a wall timestamp, because Active compares it
	// against a window of seconds. A wall clock that steps further than that,
	// which a laptop waking, an NTP correction at boot or a VM resuming all
	// do, would otherwise flip every session on the node at once: forward, all
	// of them read dead and tear down together. Backward, all of them read
	// alive until the clock catches up.
	lastActive atomic.Int64
	// lastPeerChildRekey is when the last peer-initiated Child SA rekey was
	// accepted, on the same clock and with the same plus-one as lastActive.
	lastPeerChildRekey atomic.Int64
	// lastPeerIKERekey is the same for the IKE SA. See minPeerIKERekeyInterval.
	lastPeerIKERekey atomic.Int64

	childRekeyInterval time.Duration
	ikeRekeyInterval   time.Duration
	rekeyMargin        time.Duration
	rekeyJitter        time.Duration
	rekeyRetryInitial  time.Duration
	rekeyRetryMax      time.Duration
	rekeyJitterSource  func(time.Duration) (time.Duration, error)
	// clock is time.Now where nil, read once for each pass of Run's loop
	clock func() time.Time
	// temporary is run's alone
	temporary temporaryStreak
	// dpdEvery overrides defaultDPDInterval, and zero means the default.
	dpdEvery time.Duration
	// retransmitAfter overrides requestTimeout for Run's requests, and zero means the default
	retransmitAfter time.Duration

	// events is the configuration's Recorder, set with the two ends before the session is handed out
	events        Recorder
	local, remote identity.Identity
}

func (s *Session) emit(kind string, attrs ...slog.Attr) {
	if s.events != nil {
		s.events(s.local, s.remote, kind, attrs...)
	}
}

type ikeRekey struct {
	old *ikeContext
	// spiI is the SPI this end drew for the SA it is creating. It goes out in
	// the request, so a peer that answers with a rekey of its own has seen it:
	// handleIKERekey refuses it for the reason given there.
	spiI              uint64
	nonce             []byte
	peerNonce         []byte
	peerResponseNonce []byte
	// chain is set once the rekey's CREATE_CHILD_SA selected additional key exchanges this end then runs, and lost once the rekey lost a simultaneous rekey and stopped
	chain, lost bool
}

func (s *Session) Mux() *transport.Mux { return s.mux }

func (s *Session) contexts() (current, old *ikeContext) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.current, s.old
}

func (s *Session) currentContext() *ikeContext {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.current
}

func (s *Session) nextPeerMessageID(ctx *ikeContext) uint32 {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return ctx.nextPeerMID
}

// retainOldLocked keeps the SA a rekey replaced reachable for the Delete that
// ends it, the peer's or this end's. It must be called with stateMu held.
// Whatever it displaces is released rather than dropped: a context held
// nowhere is one expireRetainedContexts can never reach, and its SPI stays in
// the hub's map for the life of the session.
func (s *Session) retainOldLocked(ctx *ikeContext) {
	displaced := s.old
	s.old, s.oldBy = ctx, s.retainedUntil(ctx, time.Now())
	s.releaseDisplacedLocked(displaced)
}

// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// a retained IKE SA waits for the peer's Delete no longer than its lifetime, and one this end deletes is kept for that Delete
func (s *Session) retainedUntil(ctx *ikeContext, now time.Time) time.Time {
	by := now.Add(retainedContextDeadline)
	if ends := ctx.established.Add(s.ikeRekeyInterval); s.ikeRekeyInterval > 0 && !ctx.ownDelete && ends.Before(by) {
		return ends
	}
	return by
}

// retainCollisionLocked does the same for the candidate a simultaneous rekey
// decided against. It must be called with stateMu held.
func (s *Session) retainCollisionLocked(ctx *ikeContext) {
	displaced := s.collision
	s.collision, s.collisionBy = ctx, s.retainedUntil(ctx, time.Now())
	s.releaseDisplacedLocked(displaced)
}

// releaseSPILocked stops routing an SPI no slot dispatches on any more. Every
// release goes through it, and every caller reassigns its slot first, so the
// question is asked of the state the mux is about to serve rather than the one
// it is leaving. It runs under stateMu, so a peer rekey cannot register the
// same SPI between the answer and the call. The mux takes only its own lock.
func (s *Session) releaseSPILocked(spi uint64) {
	if !s.routedLocked(spi) {
		s.mux.UnregisterIKE(spi)
	}
}

// releaseDisplacedLocked is the same for a context a second rekey displaced,
// which is the one release nothing in the session asked for.
func (s *Session) releaseDisplacedLocked(displaced *ikeContext) {
	if displaced == nil || s.routedLocked(displaced.spiI) {
		return
	}
	slog.Warn("ike dropping an IKE SA a second rekey displaced", "spi", displaced.spiI)
	s.releaseSPILocked(displaced.spiI)
}

// routedLocked reports whether any slot this session dispatches from is reached
// by spi. Unregistering one the session still routes leaves the control channel
// deaf while ESP keeps flowing, so every release consults this first. Two slots
// can hold the same context, which is why this asks about the SPI rather than
// about a pointer. It must be called with stateMu held.
func (s *Session) routedLocked(spi uint64) bool {
	for _, held := range []*ikeContext{s.current, s.old, s.collision} {
		if held != nil && held.spiI == spi {
			return true
		}
	}
	return false
}

// expireRetainedContexts drops a retained IKE SA whose Delete never arrived,
// and a replaced IKE SA whose Delete the peer owes once that SA's lifetime
// ends. Its SPI leaves the mux with it, so a later datagram naming it is
// answered the way any other unknown SA is.
func (s *Session) expireRetainedContexts(now time.Time) {
	s.stateMu.Lock()
	var dropped []*ikeContext
	// An undated context is dated here rather than dropped: the zero time
	// means the deadline has not been set yet, not that it has passed.
	for _, held := range []struct {
		ctx *ikeContext
		by  *time.Time
		out **ikeContext
	}{{s.old, &s.oldBy, &s.old}, {s.collision, &s.collisionBy, &s.collision}} {
		switch {
		case held.ctx == nil:
		case held.by.IsZero():
			*held.by = s.retainedUntil(held.ctx, now)
		case !now.Before(*held.by):
			dropped, *held.out = append(dropped, held.ctx), nil
		}
	}
	for _, ctx := range dropped {
		s.releaseSPILocked(ctx.spiI)
	}
	s.stateMu.Unlock()
	for _, ctx := range dropped {
		if s.ikeExpired(ctx) {
			slog.Warn("ike dropping a replaced IKE SA at its lifetime", "spi", ctx.spiI, "lifetime", s.ikeRekeyInterval)
			continue
		}
		slog.Warn("ike dropping an IKE SA the peer never deleted",
			"spi", ctx.spiI, "after", retainedContextDeadline)
	}
}

// nextRetainedExpiry is when the earliest retained IKE SA may be dropped, so
// the control loop can wait for it rather than poll for it.
func (s *Session) nextRetainedExpiry() (time.Time, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	var earliest time.Time
	if s.old != nil {
		earliest = s.oldBy
	}
	if s.collision != nil && !s.collisionBy.IsZero() && (earliest.IsZero() || s.collisionBy.Before(earliest)) {
		earliest = s.collisionBy
	}
	return earliest, !earliest.IsZero()
}

// removeRetainedContext drops ctx when the session retains it as a replaced or
// redundant IKE SA, and reports whether it did. Its SPI stays registered while
// another context is routed by it, since unregistering it would make that one
// deaf, which is a session that keeps sending ESP into a peer that answers
// nothing until its own liveness check expires.
func (s *Session) removeRetainedContext(ctx *ikeContext) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch {
	case s.old == ctx:
		s.old = nil
	case s.collision == ctx:
		s.collision = nil
	default:
		return false
	}
	s.releaseSPILocked(ctx.spiI)
	return true
}

// adoptCollisionOnPeerDelete is the second half of RFC 7296 section 2.8.2:
// "If the peer that did notice the simultaneous rekey gets the delete request
// from the other peer for the old IKE SA, it knows that the other peer did not
// detect the simultaneous rekey, and the first peer can forget its own rekey
// attempt." The peer's new SA is the candidate already held as the loser of a
// collision only this end saw, so it becomes current. Without this the Delete
// matches no retained context and closes a session the peer believes is fine,
// and the window is not microseconds: localRekey is set before the request
// goes out, so any exchange already pending widens it to that exchange's whole
// lifetime.
func (s *Session) adoptCollisionOnPeerDelete(ctx *ikeContext) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if ctx != s.current || s.collision == nil || s.localRekey == nil {
		return false
	}
	s.current, s.collision, s.localRekey = s.collision, nil, nil
	s.releaseSPILocked(ctx.spiI)
	return true
}

// contextRetired reports an IKE SA this session no longer holds in any role.
func (s *Session) contextRetired(ctx *ikeContext) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return ctx != s.current && ctx != s.old && ctx != s.collision
}

// SetRekeyIntervals sets the Child and IKE SA lifetimes, which each SA's
// scheduled rekey runs ahead of. Zero disables both for that SA. It must be
// called before Run.
func (s *Session) SetRekeyIntervals(child, ike time.Duration) error {
	if child < 0 || ike < 0 {
		return fmt.Errorf("ike: rekey intervals must be nonnegative when set")
	}
	if !validRekeyTiming(child, s.rekeyMargin, s.rekeyJitter) || !validRekeyTiming(ike, s.rekeyMargin, s.rekeyJitter) {
		return fmt.Errorf("ike: rekey margin plus jitter must be less than each enabled interval")
	}
	s.childRekeyInterval = child
	s.ikeRekeyInterval = ike
	return nil
}

// SetRekeyTiming configures when scheduled rekeys run relative to their
// intervals. Zero intervals remain disabled.
func (s *Session) SetRekeyTiming(margin, jitter time.Duration) error {
	if margin < 0 || jitter < 0 {
		return fmt.Errorf("ike: rekey margin and jitter must be nonnegative")
	}
	if !validRekeyTiming(s.childRekeyInterval, margin, jitter) || !validRekeyTiming(s.ikeRekeyInterval, margin, jitter) {
		return fmt.Errorf("ike: rekey margin plus jitter must be less than each enabled interval")
	}
	s.rekeyMargin = margin
	s.rekeyJitter = jitter
	return nil
}

// SetRekeyRetry configures the capped exponential backoff after a failed
// rekey, which for the Child SA holds back the next exchange whichever path
// asks for it, and zero for both leaves Run to take the defaults. It must be
// called before Run.
func (s *Session) SetRekeyRetry(initial, max time.Duration) error {
	if (initial != 0 || max != 0) && (initial <= 0 || max <= 0) {
		return fmt.Errorf("ike: rekey retry delays must be positive")
	}
	if initial > max {
		return fmt.Errorf("ike: initial rekey retry delay must not exceed maximum")
	}
	s.rekeyRetryInitial = initial
	s.rekeyRetryMax = max
	return nil
}

func validRekeyTiming(interval, margin, jitter time.Duration) bool {
	return interval == 0 || (margin < interval && jitter < interval-margin)
}

// NoteTraffic records successfully authenticated ESP traffic for the DPD
// policy. RFC 7296 section 2.4 treats it as proof that the IKE SA is alive.
// Run consumes this edge the next time it wakes, so the data plane pays an
// atomic store rather than a clock read per packet.
func (s *Session) NoteTraffic() { s.trafficSeen.Store(true) }

// RFC 7296 section 2.6 bounds a cookie to 1..64 octets.
const maxCookieLength = 64

func randUint64Nonzero() uint64 {
	for {
		var b [8]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint64(b[:])
		if v != 0 {
			return v
		}
	}
}

func randUint32Nonzero() uint32 {
	for {
		var b [4]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if v > 255 {
			return v
		}
	}
}

// Initiate runs IKE_SA_INIT, an IKE_INTERMEDIATE exchange for each
// additional key exchange of RFC 9370 the responder took, then IKE_AUTH
// against cfg.RemoteAddr:RemotePort and returns an established Session with
// one Child SA. It implements exactly RFC 7815's minimal-initiator surface
// plus those additional key exchanges and what ranet's strongSwan deployments
// require: raw Ed25519 signature auth and unconditional UDP encapsulation on
// that one explicit port. Every IKE message, from IKE_SA_INIT onward, carries
// the non-ESP marker. There is no NAT-T floating to a separate port,
// certificates, EAP, or MOBIKE.
func Initiate(cfg PeerConfig) (*Session, error) {
	return InitiateContext(context.Background(), cfg)
}

// InitiateContext cancels only the handshake's mux
// it neither closes a shared hub nor binds the established session's lifetime to ctx
// Session.Run owns that lifetime
// a cancel once IKE_AUTH is under way waits canceledAuthWait for the answer and deletes the SA an answer in that time established
func InitiateContext(ctx context.Context, cfg PeerConfig) (session *Session, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local := ""
	if cfg.LocalAddr != nil {
		local = cfg.LocalAddr.String()
	}
	local = net.JoinHostPort(local, fmt.Sprint(cfg.LocalPort))

	var mux *transport.Mux
	if cfg.Hub != nil {
		mux, err = cfg.Hub.NewMux(cfg.RemoteAddr, cfg.RemotePort)
	} else {
		mux, err = transport.Dial(local, cfg.RemoteAddr, cfg.RemotePort)
	}
	if err != nil {
		return nil, err
	}

	stopCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer func() {
		stopCancel()
		// a cancel after the session is handed over is the caller's to answer
		// so only a handshake it cut short reports it
		if session == nil && ctx.Err() != nil {
			_ = mux.Close()
			err = ctx.Err()
		}
	}()

	spiI := randUint64Nonzero()
	lists := current(cfg.Suites)
	group := lists.kexEntries()[0].group

	var (
		req     []byte
		respRaw []byte
		resp    *Message
		dh      *DHKeyPair
		ni      []byte
		offer   []Proposal
	)

	// RFC 7296 section 2.6.1: "if the responder includes the KEi payloads in cookie calculation, it will reject the request by sending a new cookie."
	// section 2.6.1: "Implementations SHOULD support this shorter exchange, but MUST NOT fail if other implementations do not support this shorter exchange."
	// the loop takes one group change and one cookie for each group it tries, so it ends whatever the far end sends
	var (
		cookie         []byte
		cookieForGroup bool
		groupRetried   bool
	)
	// hashed once, since a responder that folds the request into its cookie
	// refuses a retry whose hash moved and hands out a new cookie every time
	var fakeAddr [4]byte
	rand.Read(fakeAddr[:])
	srcHash := natDetectionHash(spiI, 0, net.IP(fakeAddr[:]), 0)
	for {
		if dh == nil {
			dh, err = GenerateDH(group)
			if err != nil {
				mux.Close()
				return nil, err
			}
		}
		if ni == nil {
			// the nonce holds for the whole exchange
			// a responder whose cookie hashes it would answer a retry under a new one with a fresh cookie every time
			ni = make([]byte, nonceLen)
			rand.Read(ni)
		}

		hdr := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
		hashAlgos := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
		offer = lists.ikeProposals(group)
		payloads := []RawPayload{
			{Type: PayloadSA, Body: EncodeSA(offer)},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		}
		if lists.asksIntermediate() {
			payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INTERMEDIATE_EXCHANGE_SUPPORTED})})
		}
		// RFC 7296 section 2.23: "The recipient of either the NAT_DETECTION_SOURCE_IP or NAT_DETECTION_DESTINATION_IP notification MAY compare the supplied value to a SHA-1 hash of the SPIs, source or recipient IP address, and port (respectively), and if they don't match, it SHOULD enable NAT traversal."
		// the source hash is of a random address, as strongSwan's force_encap makes it, and the responder then always encapsulates ESP in UDP
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: srcHash})})
		dstHash := natDetectionHash(spiI, 0, cfg.RemoteAddr, uint16(cfg.RemotePort))
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: dstHash})})

		if cookie != nil {
			// RFC 7296 section 2.6: "If the IKE_SA_INIT response includes the COOKIE notification, the initiator MUST then retry the IKE_SA_INIT request, and include the COOKIE notification containing the received data as the first payload, and all other payloads unchanged."
			payloads = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: cookie})}}, payloads...)
		}

		m := &Message{Header: hdr, Payloads: payloads}
		req = m.Encode()

		haveCookie, haveGroup := cookieForGroup, groupRetried
		refused := false
		respRaw, err = sendRecv(mux, req, func(raw []byte) bool {
			m, err := DecodeMessage(raw)
			if err != nil {
				return false
			}
			if m.find(PayloadSA) != nil {
				// RFC 7296 section 2.21.1: "In an IKE_SA_INIT exchange, any error notification causes the exchange to fail."
				// section 2.21.1: "Because all error notifications are completely unauthenticated, the recipient should continue trying for some time before giving up."
				// a notify that does not decode may be one
				_, failed, err := firstErrorNotify(m.Payloads)
				return err == nil && !failed
			}
			_, ok := usefulInitNotify(m, haveCookie, haveGroup, transformsOf(offer))
			refused = refused || carriesNotify(m, N_NO_PROPOSAL_CHOSEN)
			return ok
		})
		if err != nil {
			mux.Close()
			if refused {
				return nil, fmt.Errorf("%w, and the responder answered NO_PROPOSAL_CHOSEN", err)
			}
			return nil, err
		}
		resp, err = DecodeMessage(respRaw)
		if err != nil {
			mux.Close()
			return nil, fmt.Errorf("ike: decode IKE_SA_INIT response: %w", err)
		}
		if resp.find(PayloadSA) != nil {
			break
		}
		// sendRecv returns no notify-only answer the accept above refused
		// so this finds the one it took
		notify, _ := usefulInitNotify(resp, haveCookie, haveGroup, transformsOf(offer))
		switch notify.Type {
		case N_COOKIE:
			cookie, cookieForGroup = notify.Data, true
		case N_INVALID_KE_PAYLOAD:
			group, groupRetried, cookieForGroup, dh = binary.BigEndian.Uint16(notify.Data[:2]), true, false, nil
		}
	}
	if unsupported, found := firstUnsupportedCritical(resp.Payloads); found {
		mux.Close()
		return nil, fmt.Errorf("ike: response marks unsupported payload type %d critical", unsupported)
	}

	spiR := resp.Header.SPIResponder
	supportsIdentity, err := supportsSignatureHash(resp.Payloads, HashIdentity)
	if err != nil {
		mux.Close()
		return nil, err
	}
	if !supportsIdentity {
		mux.Close()
		return nil, fmt.Errorf("ike: responder did not advertise Ed25519 Identity hash support")
	}
	saPl := resp.find(PayloadSA)
	kePl := resp.find(PayloadKE)
	noncePl := resp.find(PayloadNonce)
	if saPl == nil || kePl == nil || noncePl == nil {
		mux.Close()
		return nil, fmt.Errorf("ike: incomplete IKE_SA_INIT response")
	}
	props, err := DecodeSA(saPl.Body)
	if err != nil || len(props) != 1 {
		mux.Close()
		return nil, fmt.Errorf("ike: bad SA in IKE_SA_INIT response: %v", err)
	}
	// RFC 9242 section 3.2: "If both peers indicated their support for the Intermediate Exchange, the initiator may use one or more these exchanges to transfer additional data."
	intermediate := lists.asksIntermediate() && carriesNotify(resp, N_INTERMEDIATE_EXCHANGE_SUPPORTED)
	suite, err := suiteFromProposal(props[0], offer, intermediate)
	if err != nil {
		mux.Close()
		return nil, err
	}
	peerGroup, peerPub, err := DecodeKE(kePl.Body)
	if err != nil || peerGroup != group || peerGroup != suite.DHGroup {
		mux.Close()
		return nil, fmt.Errorf("ike: KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	nr := DecodeNonce(noncePl.Body)
	if !validNonceFor(nr, suite.PRFID) {
		mux.Close()
		return nil, fmt.Errorf("ike: responder nonce length %d is short for the negotiated PRF", len(nr))
	}

	shared, err := dh.SharedSecret(peerPub)
	if err != nil {
		mux.Close()
		return nil, err
	}
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		mux.Close()
		return nil, err
	}

	authMID := suite.authMID()
	sess := &Session{
		started:          time.Now(),
		childRetireDelay: childRetireDelay,
		mux:              mux,
		current: &ikeContext{suite: suite,
			skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
			spiI: spiI, spiR: spiR, authMID: authMID, nextLocalMID: authMID + 1, established: time.Now()},
		requests:        make(chan *localRequest, 1),
		probes:          make(chan struct{}, 1),
		childRekeyEnded: make(chan struct{}, 1),
		childSpent:      make(chan struct{}, 1),
		childFailed:     make(chan error, 1),
		suites:          cfg.Suites,
		rechecks:        make(chan struct{}, 1),
		events:          cfg.Events, local: cfg.Local, remote: cfg.Remote,
	}
	// a cancel during IKE_INTERMEDIATE closes the mux under it, as one during IKE_SA_INIT does, since the responder holds a half-open SA alone
	chain, err := sess.runIntermediates(ni, nr)
	if err != nil {
		mux.Close()
		return nil, err
	}
	// from IKE_AUTH on the responder may hold the SA
	// so a cancel no longer closes the mux under the answer
	if !stopCancel() {
		return nil, ctx.Err()
	}
	// a cancel from here on leaves every exchange under way canceledAuthWait to end
	// the mux closes under the ones that have not
	endWait := sync.OnceFunc(func() { time.AfterFunc(canceledAuthWait, func() { _ = mux.Close() }) })
	stopWait := context.AfterFunc(ctx, endWait)
	defer stopWait()
	if err := sess.completeIKEAuth(cfg, req, respRaw, ni, nr, chain); err != nil {
		mux.Close()
		return nil, err
	}
	if err := sess.SetRekeyTiming(cfg.RekeyMargin, cfg.RekeyJitter); err != nil {
		mux.Close()
		return nil, err
	}
	if err := sess.SetRekeyIntervals(cfg.ChildRekeyInterval, cfg.IKERekeyInterval); err != nil {
		mux.Close()
		return nil, err
	}
	if err := sess.SetRekeyRetry(cfg.RekeyRetryInitial, cfg.RekeyRetryMax); err != nil {
		mux.Close()
		return nil, err
	}
	// stopped before ctx is read
	// so the wait never closes the mux of a session handed over
	stopWait()
	if ctx.Err() != nil {
		// an answer that authenticated after the cancel left the responder an SA, deleted within the wait
		endWait()
		_ = sess.deleteAuthenticatedIKE()
		mux.Close()
		return nil, ctx.Err()
	}
	sess.noteEstablished()
	return sess, nil
}

func supportsSignatureHash(payloads []RawPayload, wanted uint16) (bool, error) {
	found := false
	for _, payload := range payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return false, err
		}
		if notify.Type != N_SIGNATURE_HASH_ALGORITHMS {
			continue
		}
		if len(notify.Data) == 0 || len(notify.Data)%2 != 0 {
			return false, fmt.Errorf("ike: malformed signature hash algorithms notification")
		}
		for i := 0; i < len(notify.Data); i += 2 {
			if binary.BigEndian.Uint16(notify.Data[i:i+2]) == wanted {
				found = true
			}
		}
	}
	return found, nil
}

// suiteFromProposal reads the answer to an offer of offered, which this end built, so each proposal holds one transform of each key exchange type it names
// addke tells whether the exchange negotiated ADDKE Transform Types
// RFC 7296 section 3.3.1: "When a proposal is accepted, the proposal number in the SA payload MUST match the number on the proposal sent that was accepted."
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
// RFC 9370 section 2.2.1: "If the IKE_INTERMEDIATE exchange is not negotiated, then the peers MUST treat any ADDKE Transform Types in the IKE_SA_INIT exchange messages as unknown transform types and skip the proposals they appear in."
func suiteFromProposal(p Proposal, offered []Proposal, addke bool) (SASuite, error) {
	at := slices.IndexFunc(offered, func(proposal Proposal) bool { return proposal.Number == p.Number })
	if at < 0 || p.Protocol != ProtoIKE || len(p.SPI) != 0 {
		return SASuite{}, fmt.Errorf("ike: invalid selected IKE proposal shape")
	}
	proposal := offered[at]
	selected := make(map[TransformType]Transform, len(p.Transforms))
	for _, transform := range p.Transforms {
		known := transform.Type == TransEncr || transform.Type == TransPRF || transform.Type == TransDH || additional(transform.Type) && addke
		if !known {
			return SASuite{}, fmt.Errorf("ike: unexpected selected transform type %d", transform.Type)
		}
		if _, duplicate := selected[transform.Type]; duplicate {
			return SASuite{}, fmt.Errorf("ike: duplicate selected transform type %d", transform.Type)
		}
		if !slices.Contains(proposal.Transforms, transform) {
			return SASuite{}, fmt.Errorf("ike: responder selected unoffered transform %d/%d in proposal %d", transform.Type, transform.ID, p.Number)
		}
		selected[transform.Type] = transform
	}
	for _, transform := range proposal.Transforms {
		if _, ok := selected[transform.Type]; !ok {
			return SASuite{}, fmt.Errorf("ike: incomplete selected IKE proposal, without transform type %d", transform.Type)
		}
	}
	suite := SASuite{EncrID: selected[TransEncr].ID, EncrKeyBits: selected[TransEncr].KeyLengthBits, PRFID: selected[TransPRF].ID, DHGroup: selected[TransDH].ID}
	added := 0
	for t := TransADDKE1; t <= TransADDKE7; t++ {
		if addition, ok := selected[t]; ok && addition.ID != 0 {
			suite.Additions[added] = addition.ID
			added++
		}
	}
	return suite, nil
}

func transformsOf(proposals []Proposal) []Transform {
	var transforms []Transform
	for _, proposal := range proposals {
		transforms = append(transforms, proposal.Transforms...)
	}
	return transforms
}

func (s *Session) completeIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte, chain intAuth) error {
	authenticated, err := s.doIKEAuth(cfg, realMessage1, realMessage2, ni, nr, chain)
	if err == nil {
		return nil
	}
	if authenticated {
		// RFC 7296 section 2.21.2 on an IKE SA whose Child SA failed: "The initiator MAY, of course, for reasons of policy later delete such an IKE SA."
		// an IKE SA carries nothing here without its Child SA
		if deleteErr := s.deleteAuthenticatedIKE(); deleteErr != nil {
			return fmt.Errorf("%w; additionally failed to delete authenticated IKE SA: %v", err, deleteErr)
		}
		return err
	}
	if refusal, ok := errors.AsType[*authRefusal](err); ok {
		// RFC 7296 section 2.21.2: "If the error occurs on the initiator, the notification MAY be returned in a separate INFORMATIONAL exchange, usually with no other payloads."
		if informErr := s.informAfterAuth([]RawPayload{{Type: PayloadN, Body: EncodeNotify(refusal.notify)}}); informErr != nil {
			return fmt.Errorf("%w; additionally failed to tell the responder: %v", err, informErr)
		}
	}
	return err
}

// RFC 7296 section 2.21.2: "All errors that occur in an IKE_AUTH exchange, causing the authentication to fail for whatever reason (invalid shared secret, invalid ID, untrusted certificate issuer, revoked or expired certificate, etc.) SHOULD result in an AUTHENTICATION_FAILED notification."
type authRefusal struct {
	notify Notify
	err    error
}

func (r *authRefusal) Error() string { return r.err.Error() }
func (r *authRefusal) Unwrap() error { return r.err }

func refuse(notify NotifyType, data []byte, err error) error {
	return &authRefusal{notify: Notify{Type: notify, Data: data}, err: err}
}

func (s *Session) deleteAuthenticatedIKE() error {
	return s.informAfterAuth(deleteIKEPayloads())
}

func (s *Session) informAfterAuth(inner []RawPayload) error {
	ctx := s.current
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: ctx.nextLocalMID}
	request, err := ctx.encrypt(ctx.localEncryptionKey(), header, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build INFORMATIONAL request: %w", err)
	}
	_, response, responseInner, _, err := encryptedExchange(s.mux, ctx, request, teardownRetransmits, func(raw []byte) bool { return s.answerAfterAuth(ctx, raw) })
	// RFC 7296 section 2.25.2: "If a peer receives a request to close an IKE SA that it is currently trying to close, it SHOULD reply as usual, and forget about its own close request."
	if errors.Is(err, errOvertaken) {
		return nil
	}
	if response == nil && s.mux.IsClosed() {
		// the responder holds its SA until told, and a closed mux still sends, so the request goes out once more whether or not it left before
		// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
		_ = s.mux.SendIKE(request)
	}
	if err != nil {
		return err
	}
	if unsupported, found := firstUnsupportedCritical(response.Payloads, responseInner); found {
		return fmt.Errorf("ike: response marks unsupported payload type %d critical", unsupported)
	}
	if err := refusal("INFORMATIONAL after IKE_AUTH", responseInner); err != nil {
		return err
	}
	// RFC 7296 section 1.4.1: "The response to a request that deletes the IKE SA is an empty INFORMATIONAL response."
	// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
	// section 3.10.1: "Notify payloads with status types MAY be added to any message and MUST be ignored if not recognized."
	if slices.ContainsFunc(responseInner, func(payload RawPayload) bool { return payload.Type != PayloadN && supportedPayloadType(payload.Type) }) {
		return fmt.Errorf("ike: INFORMATIONAL response after IKE_AUTH is not empty")
	}
	return nil
}

func (s *Session) answerAfterAuth(ctx *ikeContext, raw []byte) bool {
	hdr, err := decodeHeader(raw)
	if err != nil || hdr.IsInitiator() != ctx.responder || hdr.SPIInitiator != ctx.spiI || hdr.SPIResponder != ctx.spiR {
		return false
	}
	message, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	first, plain, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, message)
	if err != nil || s.answerAgain(ctx, hdr) || hdr.MessageID != ctx.nextPeerMID {
		return false
	}
	response, ends, err := s.answerInWait(ctx, hdr, message.Payloads, first, plain)
	if err != nil {
		return false
	}
	ctx.lastPeerResponseID, ctx.lastPeerResponse = hdr.MessageID, response
	ctx.nextPeerMID++
	_ = s.mux.SendIKE(response)
	return ends
}

// the IKE SA going carries no Child SA, so an INFORMATIONAL request whose Delete payloads decode is answered empty
// RFC 7296 section 2.25.1: "If a peer receives a request to close a Child SA that does not exist, it SHOULD reply without a Delete payload."
func (s *Session) answerInWait(ctx *ikeContext, hdr *Header, cleartext []RawPayload, first PayloadType, plain []byte) ([]byte, bool, error) {
	inner, err := decodeMessagePlaintext(first, plain)
	if err != nil {
		// RFC 7296 section 2.21.3: "After the IKE SA is authenticated, all requests having errors MUST result in a response notifying the other end of the error."
		// section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
		response, err := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX)
		return response, true, err
	}
	if response, rejected, err := s.rejectUnsupportedCritical(ctx, hdr, cleartext, inner); rejected {
		return response, false, err
	}
	switch hdr.ExchangeType {
	case INFORMATIONAL:
		for _, payload := range inner {
			if payload.Type != PayloadD {
				continue
			}
			if _, err := DecodeDelete(payload.Body); err != nil {
				// as Run answers a Delete payload that does not decode, which ends the IKE SA
				response, err := s.responseNotify(ctx, hdr.MessageID, INFORMATIONAL, N_INVALID_SYNTAX)
				return response, true, err
			}
		}
		response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
		return response, deletesIKE(inner), err
	case CREATE_CHILD_SA:
		// RFC 7296 section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
		// the IKE SA going takes no new Child SA either
		response, err := s.responseNotify(ctx, hdr.MessageID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
		return response, false, err
	case IKE_FOLLOWUP_KE:
		// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
		response, err := s.responseNotify(ctx, hdr.MessageID, IKE_FOLLOWUP_KE, N_STATE_NOT_FOUND)
		return response, false, err
	}
	// as Run answers an exchange it does not take, which ends the IKE SA
	response, err := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX)
	return response, true, err
}

// RFC 7296 section 3.11: "Deletion of the IKE SA is indicated by a protocol ID of 1 (IKE) but no SPIs."
func deleteIKEPayloads() []RawPayload {
	return []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}
}

func deletesIKE(payloads []RawPayload) bool {
	return slices.ContainsFunc(payloads, func(payload RawPayload) bool {
		if payload.Type != PayloadD {
			return false
		}
		deleted, err := DecodeDelete(payload.Body)
		return err == nil && deleted.Protocol == ProtoIKE
	})
}

// RFC 7296 section 2.1: "The responder MUST never retransmit a response unless it receives a retransmission of the request. In that event, the responder MUST ignore the retransmitted request except insofar as it causes a retransmission of the response."
func (s *Session) answerAgain(ctx *ikeContext, hdr *Header) bool {
	if ctx.lastPeerResponse == nil || hdr.MessageID != ctx.lastPeerResponseID || hdr.MessageID+1 != ctx.nextPeerMID {
		return false
	}
	_ = s.mux.SendIKE(ctx.lastPeerResponse)
	return true
}

// doIKEAuth reports true once it accepts the responder's AUTH and IDr in an answer carrying none of the notifies that leave the IKE SA uncreated, and returns an *authRefusal for a decrypted answer it refuses before then, other than one failed at the responder
func (s *Session) doIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte, chain intAuth) (bool, error) {
	mySPI := randUint32Nonzero()
	spiBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBuf, mySPI)

	idiBody, err := cfg.Aliases.presented(cfg.Remote)
	if err != nil {
		return false, err
	}
	if idiBody == nil {
		if idiBody, err = encodeID(cfg.Local); err != nil {
			return false, err
		}
	}
	inner := []RawPayload{{Type: PayloadIDi, Body: idiBody}}
	// RFC 7296 section 1.2: "The optional payload IDr enables the initiator to specify to which of the responder's identities it wants to talk."
	// and "This is useful when the machine on which the responder is running is hosting multiple identities at the same IP address."
	// an IDr naming the dialed endpoint is how a responder with several endpoints in one family knows which was dialed
	// of several IDs naming it none is sent, since the responder may hold only one and refuses a wrong one
	asking, err := cfg.Aliases.Remote.naming(cfg.Remote)
	if err != nil {
		return false, err
	}
	switch len(asking) {
	case 0:
		idrBody, err := encodeID(cfg.Remote)
		if err != nil {
			return false, err
		}
		inner = append(inner, RawPayload{Type: PayloadIDr, Body: idrBody})
	case 1:
		inner = append(inner, RawPayload{Type: PayloadIDr, Body: asking[0]})
	}

	macedIDForI := prf(s.current.suite.PRFID, s.current.skpi, idiBody)
	signedOctets := concat(realMessage1, nr, macedIDForI, chain.octets(s.current.authMID))
	authBody := BuildAuth(cfg.LocalPrivateKey, signedOctets)

	offer := s.lists().espProposal(spiBuf)
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner = append(inner,
		RawPayload{Type: PayloadAUTH, Body: authBody},
		RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{offer})},
		RawPayload{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		RawPayload{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	)
	hdr := Header{SPIInitiator: s.current.spiI, SPIResponder: s.current.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: s.current.authMID}
	req, err := s.current.encrypt(s.current.skei, hdr, nil, inner)
	if err != nil {
		return false, err
	}

	resp, respInner, err := encryptedRoundTrip(s.mux, s.current, req)
	if resp == nil {
		return false, err
	}
	if err != nil {
		return false, refuse(N_INVALID_SYNTAX, nil, err)
	}
	if unsupported, found := firstUnsupportedCritical(resp.Payloads, respInner); found {
		return false, refuse(N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)},
			fmt.Errorf("ike: IKE_AUTH response marks unsupported payload type %d critical", unsupported))
	}
	notify, failed, err := firstErrorNotify(respInner)
	if err != nil {
		return false, refuse(N_INVALID_SYNTAX, nil, err)
	}
	// RFC 7296 section 2.21.2: "In an IKE_AUTH exchange, or in the INFORMATIONAL exchange immediately following it (in case an error happened when processing a response to IKE_AUTH), the UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, and AUTHENTICATION_FAILED notifications are the only ones to cause the IKE SA to be deleted or not created, without a Delete payload."
	// an answer carrying one failed at the responder, which has nothing to be told
	if failure, found := authFailure(respInner); found {
		return false, fmt.Errorf("ike: IKE_AUTH rejected inside SK: notify type %d", failure)
	}
	respMsg := &Message{Header: resp.Header, Payloads: respInner}

	idrRecv := respMsg.find(PayloadIDr)
	authRecv := respMsg.find(PayloadAUTH)
	saRecv := respMsg.find(PayloadSA)
	tsiRecv := respMsg.find(PayloadTSi)
	tsrRecv := respMsg.find(PayloadTSr)
	if idrRecv == nil || authRecv == nil {
		// an answer carrying another error and no IDr or AUTH failed at the responder too
		if failed {
			return false, fmt.Errorf("ike: IKE_AUTH rejected inside SK: notify type %d", notify.Type)
		}
		return false, refuse(N_AUTHENTICATION_FAILED, nil, fmt.Errorf("ike: incomplete IKE_AUTH response"))
	}
	macedIDForR := prf(s.current.suite.PRFID, s.current.skpr, idrRecv.Body)
	responderSigned := concat(realMessage2, ni, macedIDForR, chain.octets(s.current.authMID))
	if err := VerifyAuth(cfg.RemotePublicKey, responderSigned, authRecv.Body); err != nil {
		return false, refuse(N_AUTHENTICATION_FAILED, nil, err)
	}
	// AUTH above signed the bytes as received, and one endpoint reaches the wire in several encodings, a DN whose strings ranet and strongSwan type differently and each alias of it, which leaves the endpoint they name to check
	responder, err := cfg.Aliases.resolve(idrRecv.Body)
	if err != nil {
		return false, refuse(N_AUTHENTICATION_FAILED, nil, err)
	}
	if responder.endpoint != cfg.Remote {
		return false, refuse(N_AUTHENTICATION_FAILED, nil, fmt.Errorf("ike: the responder's IDr names %s, and this node dialed %s", responder.endpoint, cfg.Remote))
	}
	s.emit("ike.id.resolved", responder.attrs(idiBody)...)

	// RFC 7296 section 2.21.2: "a responder may include all the payloads associated with authentication (IDr, CERT, and AUTH) while sending error notifications for the piggybacked exchanges (FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, and so on), and the initiator MUST NOT fail the authentication because of this."
	// section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
	if failed {
		return true, fmt.Errorf("ike: Child SA rejected: notify type %d", notify.Type)
	}
	if saRecv == nil || tsiRecv == nil || tsrRecv == nil {
		return true, fmt.Errorf("ike: incomplete IKE_AUTH response")
	}
	if err := validateFullRangeSelectors(tsiRecv, tsrRecv); err != nil {
		return true, err
	}

	_, encr, remoteSPI, err := decodeChildProposal(saRecv.Body, offer.Transforms)
	if err != nil {
		return true, fmt.Errorf("ike: bad child SA in IKE_AUTH response: %w", err)
	}

	initKey, respKey, err := ChildSAKeymat(s.current.suite.PRFID, s.current.skD, ni, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return true, err
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: mySPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return true, err
	}
	return true, nil
}

// usefulInitNotify finds the one unauthenticated IKE_SA_INIT notify worth acting on
// RFC 7296 section 2.6: "If the IKE_SA_INIT response includes the COOKIE notification, the initiator MUST then retry the IKE_SA_INIT request, and include the COOKIE notification containing the received data as the first payload, and all other payloads unchanged."
// a COOKIE is echoed once for each group tried
// an INVALID_KE_PAYLOAD names a group of offered to retry in, once
func usefulInitNotify(m *Message, cookieUsed, groupUsed bool, offered []Transform) (Notify, bool) {
	// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
	if _, found := firstUnsupportedCritical(m.Payloads); found {
		return Notify{}, false
	}
	for _, payload := range m.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			continue
		}
		switch {
		case notify.Type == N_COOKIE && !cookieUsed:
			// RFC 7296 section 2.6: "The data associated with this notification MUST be between 1 and 64 octets in length"
			// an echo of any length turns one spoofed datagram into a retry of that length at the peer for each retransmission
			if len(notify.Data) == 0 || len(notify.Data) > maxCookieLength {
				continue
			}
			return notify, true
		case notify.Type == N_INVALID_KE_PAYLOAD && !groupUsed && len(notify.Data) >= 2:
			// a group the offer left out would end the dial
			// and no unauthenticated notify may end it
			if !slices.Contains(offered, Transform{Type: TransDH, ID: binary.BigEndian.Uint16(notify.Data[:2])}) {
				continue
			}
			return notify, true
		}
	}
	return Notify{}, false
}

func carriesNotify(m *Message, notifyType NotifyType) bool {
	for _, payload := range m.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		if notify, err := DecodeNotify(payload.Body); err == nil && notify.Type == notifyType {
			return true
		}
	}
	return false
}

// firstErrorNotify returns the first notify of an error type in payloads, and fails on a notify that does not decode
// RFC 7296 section 3.10.1: "Types in the range 0 - 16383 are intended for reporting errors."
func firstErrorNotify(payloads []RawPayload) (Notify, bool, error) {
	for _, payload := range payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return Notify{}, false, err
		}
		if notify.Type < 16384 {
			return notify, true, nil
		}
	}
	return Notify{}, false, nil
}

// refusal is the failure an answer to this end's request reports, an error notify or a notify that does not decode, and nil for an answer that reports none
// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
func refusal(exchange string, answer []RawPayload) error {
	notify, failed, err := firstErrorNotify(answer)
	if err != nil {
		return fmt.Errorf("ike: invalid %s response: %w", exchange, err)
	}
	if failed {
		return &rejectedError{exchange: exchange, notify: notify}
	}
	return nil
}

// Active reports whether this session has recently proved the peer is still
// there. A session that is merely installed proves nothing: after a peer
// reboots, the SA on this side stays in place, looking established, until dead
// peer detection reaps it a minute or more later.
//
// A freshly established SA counts as active without having carried anything
// yet, because a handshake that just completed is the same proof. Deciding
// from Run instead would make a session read as dead for as long as it takes
// its own control loop to start, and two nodes resolving a simultaneous open
// in that window could keep different sessions.
func (s *Session) Active() bool {
	last := s.lastActive.Load()
	return last != 0 && time.Since(s.started)-time.Duration(last-1) < activeDPDIntervals*s.dpdInterval()
}

// noteActive records that the peer has just proved it is still there.
func (s *Session) noteActive() { s.lastActive.Store(int64(time.Since(s.started)) + 1) }

// StartedAt is when this SA was established. It is written once, before the
// session is handed to anyone, so it needs no lock.
func (s *Session) StartedAt() time.Time { return s.started }

// Idle is how long since the peer last proved it is still there, which is the
// quantity dead peer detection acts on. It reports the session's whole age
// when nothing has arrived yet, so a session that never carried anything does
// not read as one that was busy a moment ago.
func (s *Session) Idle() time.Duration {
	age := time.Since(s.started)
	last := s.lastActive.Load()
	if last == 0 {
		return age
	}
	return age - time.Duration(last-1)
}

// ChildSPIs is the live Child SA's pair, local then remote, under the lock a
// rekey replaces it beneath. A diagnostic reading the field directly would
// race with the install that swaps it.
func (s *Session) ChildSPIs() (local, remote uint32) {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.Child.LocalSPI, s.Child.RemoteSPI
}

// allowPeerChildRekey reports whether to take on another peer-initiated Child
// SA rekey, and records it when it does.
func (s *Session) allowPeerChildRekey() bool {
	return allowPeerRekey(&s.lastPeerChildRekey, s.started, minPeerChildRekeyInterval)
}

// allowPeerIKERekey is allowPeerChildRekey for the IKE SA.
func (s *Session) allowPeerIKERekey() bool {
	return allowPeerRekey(&s.lastPeerIKERekey, s.started, minPeerIKERekeyInterval)
}

// allowPeerRekey is the shared body. The stored value is nanoseconds since the
// session started plus one, so zero still means "never", and it comes off the
// monotonic clock: on the wall clock a step backwards turns the limit off for
// the length of the step.
func allowPeerRekey(last *atomic.Int64, started time.Time, interval time.Duration) bool {
	now := int64(time.Since(started))
	if previous := last.Load(); previous != 0 && now-(previous-1) < int64(interval) {
		return false
	}
	last.Store(now + 1)
	return true
}

// noteEstablished starts the liveness clock at the end of the handshake.
func (s *Session) noteEstablished() { s.noteActive() }
