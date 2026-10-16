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

// PeerConfig describes one peer this node dials and everything establishing an
// IKEv2 SA with it takes, raw Ed25519 pubkey auth (RFC 7427) under the DN or
// an ID Aliases gives, a 0.0.0.0/0::/0 tunnel-mode Child SA and forced UDP
// encapsulation. The package doc lists the transforms this offers, which are
// the only ones it proposes or accepts.
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
	// answeredAuth marks the SA whose IKE_AUTH this end answered, where the peer's request at Message ID 2 is the INFORMATIONAL exchange immediately following it
	answeredAuth bool
	sendIV       atomic.Uint64

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
	// collision retains a peer-initiated candidate that a simultaneous rekey
	// decided against: the losing one until the local rekey exchange can
	// delete it, or the peer's own losing one until the peer deletes it. The
	// normal current/old pair retains the winning candidate and the SA it
	// replaces.
	collision *ikeContext
	// oldBy and collisionBy bound how long each waits for the peer's Delete.
	oldBy         time.Time
	collisionBy   time.Time
	localRekey    *ikeRekey
	ikeRekeyNonce func([]byte) error

	requestMu sync.Mutex // IKEv2 permits only one outstanding local request.
	requests  chan *localRequest
	// probes holds at most the one probe Run has not acted on
	probes chan struct{}
	// childRekeyEnded holds at most the one end of a Child SA rekey Run has not looked at, since Run settles every one on the Child SA schedule and one running at the Child SA's lifetime decides whether the IKE SA closes
	childRekeyEnded chan struct{}
	// childFailed holds at most the one dataplane failure Run has not looked at, and one is enough to close the IKE SA
	childFailed chan error
	// sendFailures counts failed IKE sends since the last that went out, and only Run's goroutine touches it
	sendFailures int

	childMu          sync.RWMutex
	Child            ChildSA
	childEstablished time.Time
	withdrawn        []uint32
	retiring         ChildSA
	// retiringEnds is where the replaced SA's lifetime ends, which its drain does not pass
	retiringEnds time.Time
	// retiringBy bounds how long the replaced SA waits for the peer's Delete.
	retiringBy       time.Time
	retiringDeleting bool
	// Run expires replaced inbound SAs after an overlap period, allowing
	// queued and reordered ESP to finish after the Delete acknowledgment.
	retired          []childRetirement
	childRetireDelay time.Duration

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
// and one the peer owes a Delete at its lifetime. Its SPI leaves the mux with
// it, so a later datagram naming it is answered the way any other unknown SA
// is.
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

// removeRetainedContext drops a retained SA the peer has deleted, and reports
// whether its SPI may be unregistered: another context routed by the same SPI
// would be made deaf by that, which is a session that keeps sending ESP into a
// peer that answers nothing until its own liveness check expires.
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

// ikeProposal is the single modern-crypto-only IKE SA proposal we offer:
// AES-256/128-GCM or ChaCha20-Poly1305, PRF-HMAC-SHA-384/256, and
// Curve25519/P-384/P-256. No legacy transforms, no separate integrity
// transform (all offered ciphers are AEAD).
func ikeProposal() Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoIKE,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransDH, ID: DH_CURVE25519},
			{Type: TransDH, ID: DH_ECP_384},
			{Type: TransDH, ID: DH_ECP_256},
		},
	}
}

func espProposal(spi []byte) Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoESP,
		SPI:      spi,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransESN, ID: ESN_NO},
		},
	}
}

// espRekeyProposal offers only the cipher the SA being replaced already uses.
// decodeChildProposal holds a rekey answer to that cipher, so offering the
// other two asks a question this end refuses the answer to: RFC 7296 section
// 2.7 lets the responder take any of them, and a third party whose preference
// order changed between the initial exchange and the rekey would be turned
// down for answering within the offer. ikeRekeyProposal pins the PRF across a
// rekey for the same kind of reason.
func espRekeyProposal(spi []byte, old ChildSA) Proposal {
	p := espProposal(spi)
	// Both sides are canonicalized before they are compared. espProposal
	// spells ChaCha20-Poly1305 with no Key Length attribute, which RFC 7296
	// section 3.3.5 requires of a fixed-length-key transform, while the
	// installed SA records the 256 bits the key has. Comparing those raw
	// matches nothing and leaves an offer of ESN alone, which section 3.3.6
	// has every responder refuse for "missing a mandatory Transform Type".
	want, err := canonicalChildCipher(old)
	if err != nil {
		return p
	}
	keep := p.Transforms[:0]
	for _, transform := range p.Transforms {
		if transform.Type != TransEncr {
			keep = append(keep, transform)
			continue
		}
		canonical, err := canonicalEncryptionTransform(transform)
		if err == nil && canonical.ID == want.ID && canonical.KeyLengthBits == want.KeyLengthBits {
			keep = append(keep, transform)
		}
	}
	p.Transforms = keep
	return p
}

// Initiate runs IKE_SA_INIT then IKE_AUTH against cfg.RemoteAddr:RemotePort
// and returns an established Session with one Child SA. It implements
// exactly RFC 7815's minimal-initiator surface plus what ranet's
// strongSwan deployments require: raw Ed25519 signature auth and
// unconditional UDP encapsulation on that one explicit port. Every IKE
// message, from IKE_SA_INIT onward, carries the non-ESP marker. There is
// no NAT-T floating to a separate port, certificates, EAP, or MOBIKE.
func Initiate(cfg PeerConfig) (*Session, error) {
	return InitiateContext(context.Background(), cfg)
}

// InitiateContext cancels only the handshake's mux. It does not close a shared
// hub or bind the established session's lifetime to ctx. Session.Run owns that.
// A cancel once IKE_AUTH is under way waits canceledAuthWait for the answer
// and deletes the SA an answer in that time established.
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
		// a cancel after the session is handed over is the caller's to answer, so only a handshake it cut short reports it
		if session == nil && ctx.Err() != nil {
			_ = mux.Close()
			err = ctx.Err()
		}
	}()

	spiI := randUint64Nonzero()
	group := uint16(DH_CURVE25519)

	var (
		req     []byte
		respRaw []byte
		resp    *Message
		dh      *DHKeyPair
		ni      []byte
	)

	// Two unauthenticated responses can send us round again. The responder may
	// reject our preferred DH group with N(INVALID_KE_PAYLOAD, desired-group),
	// and under load it may answer N(COOKIE) instead of allocating state
	// (RFC 7296 section 2.6). Each is allowed once, so the loop is bounded whatever
	// the far end does.
	var (
		cookie        []byte
		cookieRetried bool
		groupRetried  bool
	)
	// Hashed once, outside the loop. RFC 7296 section 2.6 requires a cookie
	// retry to carry "all other payloads unchanged", and a responder that
	// folds the request into its cookie rejects a retry that moved this,
	// handing out a fresh challenge every time.
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
			// The nonce stays fixed for the whole exchange. A cookie is a
			// keyed hash of it together with our SPI and address, so a retry
			// that regenerated it would be handed a fresh challenge forever.
			ni = make([]byte, nonceLen)
			rand.Read(ni)
		}

		hdr := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
		hashAlgos := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
		payloads := []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		}
		// RFC 7296 section 2.23 NAT detection hashes a random source, as strongSwan's force_encap does, so the responder always encapsulates ESP in UDP
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: srcHash})})
		dstHash := natDetectionHash(spiI, 0, cfg.RemoteAddr, uint16(cfg.RemotePort))
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: dstHash})})

		if cookie != nil {
			// RFC 7296 section 2.6: "include the COOKIE notification containing the
			// received data as the first payload, and all other payloads
			// unchanged".
			payloads = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: cookie})}}, payloads...)
		}

		m := &Message{Header: hdr, Payloads: payloads}
		req = m.Encode()

		// A bare notify-only response is only worth stopping for when it's
		// N_INVALID_KE_PAYLOAD on the first attempt, the one legitimate
		// signal that lets us make progress by switching Diffie-Hellman
		// group. Anything else unauthenticated (see sendRecv's doc comment)
		// is rejected here, which makes sendRecv keep retransmitting/
		// waiting for the real response instead of surfacing a possibly
		// forged error.
		haveCookie, haveGroup := cookieRetried, groupRetried
		respRaw, err = sendRecv(mux, req, func(raw []byte) bool {
			m, err := DecodeMessage(raw)
			if err != nil {
				return false
			}
			if m.find(PayloadSA) != nil {
				return true
			}
			_, ok := usefulInitNotify(m, haveCookie, haveGroup)
			return ok
		})
		if err != nil {
			mux.Close()
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
		// Only reachable for the notify accept() just validated.
		notify, _ := usefulInitNotify(resp, haveCookie, haveGroup)
		switch notify.Type {
		case N_COOKIE:
			// Everything else about the request stays as it was, so dh and ni
			// are deliberately not regenerated here.
			cookie, cookieRetried = notify.Data, true
		case N_INVALID_KE_PAYLOAD:
			group, groupRetried, dh = binary.BigEndian.Uint16(notify.Data[:2]), true, nil
		}
	}
	if err := validateResponseCriticalFlags(resp.Payloads); err != nil {
		mux.Close()
		return nil, err
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
	suite, err := suiteFromProposal(props[0])
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

	sess := &Session{
		started:          time.Now(),
		childRetireDelay: childRetireDelay,
		mux:              mux,
		current: &ikeContext{suite: suite,
			skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
			spiI: spiI, spiR: spiR, nextLocalMID: 2, established: time.Now()},
		requests:        make(chan *localRequest, 1),
		probes:          make(chan struct{}, 1),
		childRekeyEnded: make(chan struct{}, 1),
		childFailed:     make(chan error, 1),
		events:          cfg.Events, local: cfg.Local, remote: cfg.Remote,
	}
	// from IKE_AUTH on the responder may hold the SA, so a cancel no longer closes the mux under the answer
	if !stopCancel() {
		return nil, ctx.Err()
	}
	// a cancel from here on leaves every exchange under way canceledAuthWait to end, and the mux closes under the ones that have not
	endWait := sync.OnceFunc(func() { time.AfterFunc(canceledAuthWait, func() { _ = mux.Close() }) })
	stopWait := context.AfterFunc(ctx, endWait)
	defer stopWait()
	if err := sess.completeIKEAuth(cfg, req, respRaw, ni, nr); err != nil {
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
	// stopped before ctx is read, so the wait never closes the mux of a session handed over
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

func suiteFromProposal(p Proposal) (SASuite, error) {
	// The answer to this end's own offer, which RFC 7296 section 2.7 makes a
	// subset of it: "The responder MUST choose a single suite, which may be
	// any subset of the SA proposal", with "exactly one transform of each type
	// included in the proposal". ikeProposal names three types, so a
	// conforming answer carries three, and section 3.3.6 has the initiator
	// terminate an exchange whose answer is not consistent with what it
	// proposed. See decodeChildProposal for why an unoffered type is refused
	// even where it could not change the suite.
	//
	// As in decodeChildProposal, the count states the shape and the checks
	// below enforce it: the type test, the duplicate test and the
	// completeness test leave nothing for it to catch on its own.
	if p.Number != 1 || p.Protocol != ProtoIKE || len(p.SPI) != 0 || len(p.Transforms) != 3 {
		return SASuite{}, fmt.Errorf("ike: invalid selected IKE proposal shape")
	}
	offered := ikeProposal().Transforms
	selected := make(map[TransformType]Transform, 3)
	for _, transform := range p.Transforms {
		if transform.Type != TransEncr && transform.Type != TransPRF && transform.Type != TransDH {
			return SASuite{}, fmt.Errorf("ike: unexpected selected transform type %d", transform.Type)
		}
		if _, duplicate := selected[transform.Type]; duplicate {
			return SASuite{}, fmt.Errorf("ike: duplicate selected transform type %d", transform.Type)
		}
		if !slices.Contains(offered, transform) {
			return SASuite{}, fmt.Errorf("ike: responder selected unoffered transform %d/%d", transform.Type, transform.ID)
		}
		selected[transform.Type] = transform
	}
	encr, encrOK := selected[TransEncr]
	prfT, prfOK := selected[TransPRF]
	dhT, dhOK := selected[TransDH]
	if !encrOK || !prfOK || !dhOK {
		return SASuite{}, fmt.Errorf("ike: incomplete selected IKE proposal")
	}
	// The key length is the transform's own: ChaCha20-Poly1305 carries no
	// KEY_LENGTH attribute, which canonicalEncryptionTransform enforces, and
	// aeadParams reads its fixed 32 bytes from the cipher rather than from
	// here. Substituting 256 named a number the wire never carried.
	return SASuite{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, PRFID: prfT.ID, DHGroup: dhT.ID}, nil
}

func (s *Session) completeIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte) error {
	authenticated, err := s.doIKEAuth(cfg, realMessage1, realMessage2, ni, nr)
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

func refuseCritical(payloads []RawPayload, err error) error {
	for _, payload := range payloads {
		if payload.Critical && payload.Type != PayloadSK && !supportedPayloadType(payload.Type) {
			return refuse(N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(payload.Type)}, err)
		}
	}
	return refuse(N_INVALID_SYNTAX, nil, err)
}

func (s *Session) deleteAuthenticatedIKE() error {
	return s.informAfterAuth([]RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
}

func (s *Session) informAfterAuth(inner []RawPayload) error {
	ctx := s.current
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: ctx.nextLocalMID}
	request, err := ctx.encrypt(ctx.localEncryptionKey(), header, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build INFORMATIONAL request: %w", err)
	}
	response, responseInner, err := encryptedRoundTripWithin(s.mux, ctx, request, teardownRetransmits)
	if response == nil && s.mux.IsClosed() {
		// the responder holds its SA until told, and a closed mux still sends, so the request goes out once more whether or not it left before
		// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
		_ = s.mux.SendIKE(request)
	}
	if err != nil {
		return err
	}
	if err := validateResponseCriticalFlags(response.Payloads); err != nil {
		return err
	}
	if err := validateResponseCriticalFlags(responseInner); err != nil {
		return err
	}
	if len(responseInner) != 0 {
		return fmt.Errorf("ike: INFORMATIONAL response after IKE_AUTH is not empty")
	}
	return nil
}

// doIKEAuth reports true once it accepts the responder's AUTH and IDr, and returns an *authRefusal for a decrypted answer it refuses before then, other than one carrying the responder's own error notify
func (s *Session) doIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte) (bool, error) {
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
	signedOctets := concat(realMessage1, nr, macedIDForI)
	authBody := BuildAuth(cfg.LocalPrivateKey, signedOctets)

	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner = append(inner,
		RawPayload{Type: PayloadAUTH, Body: authBody},
		RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spiBuf)})},
		RawPayload{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		RawPayload{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	)
	hdr := Header{SPIInitiator: s.current.spiI, SPIResponder: s.current.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
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
	if err := validateResponseCriticalFlags(resp.Payloads); err != nil {
		return false, refuseCritical(resp.Payloads, err)
	}
	if err := validateResponseCriticalFlags(respInner); err != nil {
		return false, refuseCritical(respInner, err)
	}
	respMsg := &Message{Header: resp.Header, Payloads: respInner}

	idrRecv := respMsg.find(PayloadIDr)
	authRecv := respMsg.find(PayloadAUTH)
	saRecv := respMsg.find(PayloadSA)
	tsiRecv := respMsg.find(PayloadTSi)
	tsrRecv := respMsg.find(PayloadTSr)
	if idrRecv == nil || authRecv == nil {
		for _, payload := range respInner {
			if payload.Type != PayloadN {
				continue
			}
			notify, err := DecodeNotify(payload.Body)
			if err != nil {
				return false, refuse(N_INVALID_SYNTAX, nil, err)
			}
			// RFC 7296 section 3.10.1: "Types in the range 0 - 16383 are intended for reporting errors."
			// an IKE_AUTH answered with one failed at the responder, which has nothing to be told
			if notify.Type < 16384 {
				return false, fmt.Errorf("ike: IKE_AUTH rejected inside SK: notify type %d", notify.Type)
			}
		}
		return false, refuse(N_AUTHENTICATION_FAILED, nil, fmt.Errorf("ike: incomplete IKE_AUTH response"))
	}
	macedIDForR := prf(s.current.suite.PRFID, s.current.skpr, idrRecv.Body)
	responderSigned := concat(realMessage2, ni, macedIDForR)
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
	if saRecv == nil {
		if n := respMsg.find(PayloadN); n != nil {
			nt, err := DecodeNotify(n.Body)
			if err != nil {
				return true, err
			}
			return true, fmt.Errorf("ike: Child SA rejected: notify type %d", nt.Type)
		}
	}
	if saRecv == nil || tsiRecv == nil || tsrRecv == nil {
		return true, fmt.Errorf("ike: incomplete IKE_AUTH response")
	}
	if err := validateFullRangeSelectors(tsiRecv, tsrRecv); err != nil {
		return true, err
	}

	_, encr, remoteSPI, err := decodeChildProposal(saRecv.Body, nil)
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

// usefulInitNotify finds the one unauthenticated IKE_SA_INIT notify worth
// acting on. Only two let the exchange make progress, each once: N(COOKIE)
// asks us to prove return routability (RFC 7296 section 2.6) and
// N(INVALID_KE_PAYLOAD) names a Diffie-Hellman group the responder will take
// (section 1.2). Everything else unauthenticated is ignored, so sendRecv keeps
// waiting for the real response rather than letting anyone who can spoof our
// SPI abort the handshake.
func usefulInitNotify(m *Message, cookieUsed, groupUsed bool) (Notify, bool) {
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
			// RFC 7296 section 2.6: "The data associated with this
			// notification MUST be between 1 and 64 octets in length". Echoing
			// whatever arrives would let anyone who can see our SPI turn one
			// spoofed datagram into five oversized ones aimed at our peer.
			if len(notify.Data) == 0 || len(notify.Data) > maxCookieLength {
				continue
			}
			return notify, true
		case notify.Type == N_INVALID_KE_PAYLOAD && !groupUsed && len(notify.Data) >= 2:
			// A group we cannot generate aborts the dial with no retry, so an
			// unauthenticated notify naming one would end the handshake.
			if !supportedIKEGroup(binary.BigEndian.Uint16(notify.Data[:2])) {
				continue
			}
			return notify, true
		}
	}
	return Notify{}, false
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
