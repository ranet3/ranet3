// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

// encodeID is the IDi or IDr payload body naming the endpoint id by its DN
func encodeID(id identity.Identity) ([]byte, error) {
	dn, err := id.DN()
	if err != nil {
		return nil, err
	}
	return EncodeID(ID_DER_ASN1_DN, dn), nil
}

// Family is the address family an endpoint dials and is dialed in
// an endpoint dials only endpoints of its own family
type Family uint8

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func (f Family) String() string {
	switch f {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return "none"
}

// familyOf reads an IPv4-mapped address as IPv4, as a dual-stack socket reports an IPv4 peer
func familyOf(address netip.Addr) Family {
	if address.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

// Trust decides who may join the mesh and which key authenticates them
type Trust interface {
	// Key is the key that must verify the AUTH of a peer asserting id and the family of its endpoint, or why id may not join
	// an id naming a node without an endpoint asks about the node alone, which has no family
	// several handshakes call it at once, and one call reads one version of the trust
	Key(id identity.Identity) (ed25519.PublicKey, Family, error)
}

// ResponderConfig carries what answering an unsolicited peer needs, against
// PeerConfig, which describes one peer this node dials. A responder does not know who
// is calling until IDi arrives, so the peer's key and the local endpoint
// identity are both resolved during the exchange rather than configured.
type ResponderConfig struct {
	Hub *transport.Hub

	// Local is every endpoint we answer as, with its family
	Local           map[identity.Identity]Family
	LocalPrivateKey ed25519.PrivateKey

	// Trust gives the key that must verify an initiator's AUTH, asked after an IDi naming our own node is refused
	Trust Trust

	// Aliases gives the auth.aliases in force, asked once for each handshake, which lets a reload reach the next one
	// nil gives none
	Aliases func() Aliases

	// HandshakeTimeout bounds one exchange from the first datagram to an
	// established SA. Zero uses handshakeTimeout.
	HandshakeTimeout time.Duration

	ChildRekeyInterval time.Duration
	IKERekeyInterval   time.Duration
	RekeyMargin        time.Duration
	RekeyJitter        time.Duration
	RekeyRetryInitial  time.Duration
	RekeyRetryMax      time.Duration

	// Suites gives the lists in force
	// each handshake and each answered session read them at each exchange
	// nil runs the zero Suites
	Suites func() Suites

	// Events records each answered session's state changes and the handshakes it refuses
	// nil records nothing
	Events Recorder
}

// Accepted names both ends of an SA a peer opened to us. The local identity
// is the endpoint the initiator's IDr named. Where IDr is absent or an ID
// auth.aliases.local presents, it is our one endpoint of the family the
// request arrived in. The pair identifies one path through the mesh the same
// way a dialed session does, rather than just naming the peer.
type Accepted struct {
	Peer  identity.Identity
	Local identity.Identity
	// Key verified the peer's AUTH
	Key ed25519.PublicKey
}

// Responder accepts IKE SAs that peers initiate to us on a shared hub. One
// Responder serves every peer. There is no per-peer state until IDi is
// authenticated, because until then there is no peer, only a datagram.
type Responder struct {
	cfg ResponderConfig
	// local is the IDr body of each endpoint we answer as
	local map[identity.Identity][]byte

	// started is the monotonic base for the failure record below.
	started time.Time

	failureMu sync.Mutex
	// failureReported is when each source was last said out loud and
	// failureSaid when any source was. See failureIsDue.
	failureReported map[netip.Addr]time.Duration
	failureSaid     time.Duration

	mu       sync.Mutex
	halfOpen int
	// halfOpenBySource is how many of those one address is holding.
	halfOpenBySource map[netip.Addr]int
	cookieSecret     [cookieSecretLen]byte
	// previousSecret is the secret one rotation back, and previousValid says
	// whether there has been a rotation at all. A cookie is issued and echoed
	// a round trip apart, so rotating without keeping the old one refuses
	// every cookie in flight at that moment. The initiator accepts one COOKIE
	// per dial, so it then retransmits a cookie that can never be accepted
	// until its whole budget runs out. One generation back is all it takes,
	// because a cookie older than that is older than cookieLifetime.
	previousSecret [cookieSecretLen]byte
	previousValid  bool
	cookieVersion  uint8
	cookieRotated  time.Time
}

func NewResponder(cfg ResponderConfig) (*Responder, error) {
	if cfg.Hub == nil {
		return nil, fmt.Errorf("ike: responder needs a hub")
	}
	if len(cfg.LocalPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ike: responder needs an Ed25519 private key")
	}
	if len(cfg.Local) == 0 {
		return nil, fmt.Errorf("ike: responder needs at least one local identity")
	}
	if cfg.Trust == nil {
		return nil, fmt.Errorf("ike: responder needs a trust")
	}
	r := &Responder{cfg: cfg, local: make(map[identity.Identity][]byte, len(cfg.Local)), started: time.Now(),
		failureReported: make(map[netip.Addr]time.Duration, handshakeFailureSources),
		// One floor in the past, so the first failure of this node's life is
		// said rather than spaced against a zero that means "never said".
		failureSaid: -handshakeFloor}
	for id, family := range cfg.Local {
		if family != IPv4 && family != IPv6 {
			return nil, fmt.Errorf("ike: responder endpoint %s needs a family", id)
		}
		body, err := encodeID(id)
		if err != nil {
			return nil, err
		}
		r.local[id] = body
	}
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		return nil, err
	}
	r.cookieRotated = time.Now()
	return r, nil
}

// Serve reads unclaimed IKE datagrams and runs one handshake per initiator,
// calling onSession for each SA that reaches IKE_AUTH. Handshakes run
// concurrently: a peer that stalls halfway must not delay any other peer.
//
// It returns when ctx is canceled or the hub's socket is gone, after every
// in-flight handshake has finished.
func (r *Responder) Serve(ctx context.Context, onSession func(*Session, Accepted)) error {
	unclaimed := r.cfg.Hub.Listen()
	var running sync.WaitGroup
	defer running.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.cfg.Hub.Done():
			return fmt.Errorf("ike: responder hub closed")
		case datagram := <-unclaimed:
			// RFC 7296 section 2.21.4: "If the message is marked as a response, the node ... MUST NOT respond."
			if header, err := decodeHeader(datagram.Raw); err == nil && header.IsResponse() {
				slog.Debug("ike responder dropped a response no exchange waits for", "peer", datagram.Endpoint,
					"exchange", header.ExchangeType, "message_id", header.MessageID)
				continue
			}
			running.Go(func() {
				session, accepted, err := r.handshake(ctx, datagram)
				if err != nil {
					// warn rather than debug, since this is the whole responder side of a peer that cannot connect, and rate limited, since anyone who can reach the port can drive it
					r.noteHandshakeFailure(datagram.Endpoint, err)
					return
				}
				onSession(session, accepted)
			})
		}
	}
}

// handshake runs IKE_SA_INIT and IKE_AUTH from the responder side for one initiator
// a failure before the mux exists is answered statelessly or not at all
// one after it closes the mux
// so nothing survives a rejected exchange
func (r *Responder) handshake(ctx context.Context, datagram transport.Unclaimed) (_ *Session, _ Accepted, err error) {
	timeout := r.cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	if header, err := decodeHeader(datagram.Raw); err == nil && higherVersion(r.cfg.Hub.SendIKETo, header, datagram.Endpoint) {
		return nil, Accepted{}, fmt.Errorf("ike: unclaimed request at major version %d", header.MajorVersion)
	}
	request, err := DecodeMessage(datagram.Raw)
	if err != nil {
		return nil, Accepted{}, fmt.Errorf("ike: decode IKE_SA_INIT request: %w", err)
	}
	header := request.Header
	if header.ExchangeType != IKE_SA_INIT || !header.IsInitiator() ||
		header.MessageID != 0 || header.SPIResponder != 0 || header.SPIInitiator == 0 ||
		header.MajorVersion != 2 || header.Length != uint32(len(datagram.Raw)) {
		return nil, Accepted{}, fmt.Errorf("ike: unclaimed datagram is not an IKE_SA_INIT request")
	}
	spiI := header.SPIInitiator

	saPayload, kePayload, noncePayload := request.find(PayloadSA), request.find(PayloadKE), request.find(PayloadNonce)
	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return nil, Accepted{}, fmt.Errorf("ike: incomplete IKE_SA_INIT request")
	}
	ni := DecodeNonce(noncePayload.Body)
	if !validNonce(ni) {
		return nil, Accepted{}, fmt.Errorf("ike: initiator nonce length %d is outside 16..256", len(ni))
	}
	// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected and the response to the IKE request containing that payload MUST include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an unsupported critical payload was included."
	if unsupported, found := firstUnsupportedCritical(request.Payloads); found {
		r.sendStatelessNotify(datagram, &header, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)})
		return nil, Accepted{}, fmt.Errorf("ike: IKE_SA_INIT request marks payload type %d critical", unsupported)
	}

	// RFC 7296 section 2.6: "These attacks can be made less effective if a responder uses minimal CPU and commits no state to an SA until it knows the initiator can receive packets at the address from which it claims to be sending them."
	if required, err := r.cookieRequired(request, ni, spiI, datagram.Endpoint); err != nil {
		return nil, Accepted{}, err
	} else if required {
		return nil, Accepted{}, fmt.Errorf("ike: cookie challenge sent")
	}

	// the slot is taken before the key exchange, the first cost an unauthenticated datagram imposes
	// and it is the pressure cookieThreshold reads
	source := datagram.Endpoint.AddrPort().Addr()
	if !r.enterHalfOpen(source) {
		return nil, Accepted{}, fmt.Errorf("ike: too many half-open SAs")
	}
	defer r.leaveHalfOpen(source)

	supportsIdentity, err := supportsSignatureHash(request.Payloads, HashIdentity)
	if err != nil {
		return nil, Accepted{}, err
	}
	if !supportsIdentity {
		// RFC 7296 section 3.10.1 on AUTHENTICATION_FAILED: "Sent in the response to an IKE_AUTH message when, for some reason, the authentication failed."
		// and on NO_PROPOSAL_CHOSEN: "This can be sent in any case where the offered proposals (including but not limited to SA payload values, USE_TRANSPORT_MODE notify, IPCOMP_SUPPORTED notify) are not acceptable for the responder."
		// an initiator that advertises no hash this end signs under offers nothing it can accept
		r.sendStatelessNotify(datagram, &header, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, fmt.Errorf("ike: initiator did not advertise Ed25519 Identity hash support")
	}

	peerGroup, peerPublic, err := DecodeKE(kePayload.Body)
	if err != nil {
		return nil, Accepted{}, fmt.Errorf("ike: decode KE: %w", err)
	}
	proposal, suite, err := selectIKEProposal(saPayload.Body, peerGroup, current(r.cfg.Suites))
	if err != nil {
		if wrongGroup, ok := errors.AsType[*invalidKEError](err); ok {
			// outside statelessErrors, as COOKIE is
			_ = r.cfg.Hub.SendIKETo(statelessNotify(&header, N_INVALID_KE_PAYLOAD, invalidKENotifyData(wrongGroup.group)), datagram.Endpoint)
			return nil, Accepted{}, err
		}
		r.sendStatelessNotify(datagram, &header, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, err
	}

	// RFC 7296 section 2.10: a nonce "MUST be at least half the key size of the negotiated pseudorandom function", known once the proposal is chosen
	if !validNonceFor(ni, suite.PRFID) {
		r.sendStatelessNotify(datagram, &header, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, fmt.Errorf("ike: initiator nonce length %d is short for the negotiated PRF", len(ni))
	}

	dh, err := GenerateDH(suite.DHGroup)
	if err != nil {
		return nil, Accepted{}, err
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return nil, Accepted{}, err
	}
	nr := make([]byte, nonceLen)
	if _, err := rand.Read(nr); err != nil {
		return nil, Accepted{}, err
	}
	spiR := randUint64Nonzero()
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		return nil, Accepted{}, err
	}

	// the half-open slot above bounds how many of these exist at once
	mux, err := r.cfg.Hub.NewMuxTo(datagram.Endpoint)
	if err != nil {
		return nil, Accepted{}, err
	}
	defer func() {
		if err != nil {
			_ = mux.Close()
		}
	}()
	stopCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stopCancel()
	// registered before the response goes out
	// so the initiator's IKE_AUTH cannot land in the unclaimed queue
	if err := mux.RegisterIKE(spiI); err != nil {
		return nil, Accepted{}, err
	}
	defer func() {
		if err != nil {
			mux.UnregisterIKE(spiI)
		}
	}()

	response, err := r.buildSAInitResponse(spiI, spiR, proposal, suite, dh, nr, datagram.Endpoint)
	if err != nil {
		return nil, Accepted{}, err
	}
	if err := mux.SendIKE(response); err != nil {
		return nil, Accepted{}, err
	}

	session := &Session{
		started:          time.Now(),
		childRetireDelay: childRetireDelay,
		mux:              mux,
		current: &ikeContext{
			suite: suite,
			skD:   keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
			spiI: spiI, spiR: spiR, responder: true, answeredAuth: true, established: time.Now(),
			// RFC 7296 section 2.2: "Thus, the first pair of IKE_AUTH messages will have an ID of 1, the second (when EAP is used) will be 2, and so on."
			// with no EAP the initiator's next request is at 2, and this end has made no request of its own
			nextPeerMID: 2, nextLocalMID: 0,
		},
		requests:        make(chan *localRequest, 1),
		probes:          make(chan struct{}, 1),
		childRekeyEnded: make(chan struct{}, 1),
		childSpent:      make(chan struct{}, 1),
		childFailed:     make(chan error, 1),
		suites:          r.cfg.Suites,
		rechecks:        make(chan struct{}, 1),
	}

	accepted, created, err := session.completeResponderAuth(r, datagram.Raw, response, ni, nr, deadline)
	if err != nil {
		if created {
			// RFC 7296 section 1.2: "If creating the Child SA during the IKE_AUTH exchange fails for some reason, the IKE SA is still created as usual."
			// an IKE SA carries nothing here without its Child SA, so the IKE SA goes with a Delete
			_ = session.run(ctx, err)
		}
		return nil, Accepted{}, err
	}
	if err := session.SetRekeyTiming(r.cfg.RekeyMargin, r.cfg.RekeyJitter); err != nil {
		return nil, Accepted{}, err
	}
	if err := session.SetRekeyIntervals(r.cfg.ChildRekeyInterval, r.cfg.IKERekeyInterval); err != nil {
		return nil, Accepted{}, err
	}
	if err := session.SetRekeyRetry(r.cfg.RekeyRetryInitial, r.cfg.RekeyRetryMax); err != nil {
		return nil, Accepted{}, err
	}
	session.events, session.local, session.remote = r.cfg.Events, accepted.Local, accepted.Peer
	session.noteEstablished()
	return session, accepted, nil
}

// buildSAInitResponse mirrors the initiator's IKE_SA_INIT, including the
// deliberately wrong NAT_DETECTION_SOURCE_IP. ranet3's transport accepts
// UDP-encapsulated ESP only, so the initiator has to conclude that we are
// behind a NAT: hashing a random address guarantees the mismatch that makes
// it, exactly as strongSwan's own force_encap does (ike_natd.c).
//
// Both notifies have to be present. strongSwan enables NAT traversal only
// when it has seen a source and a destination notify, and treats one alone as
// a peer that does not implement RFC 7296 section 2.23 at all, so sending the
// mismatching source on its own leaves it building raw ESP that no userspace
// transport ever sees. The destination hash is the honest one, over the
// address this datagram actually came from.
//
// It follows that the peer must be reachable on the port it already knows.
// RFC 7296 section 2.23 obliges a conformant initiator that sees the mismatch
// to move everything to UDP 4500, and nothing here binds 4500 separately, so
// the registry port has to be the port both ends keep using. strongSwan does
// that when charon.port_nat_t is set to it, which the fleet and the
// integration test both configure, and a peer left on the default would float
// away to a socket that is not listening. Config rejects port 500 outright for
// the related reason that the non-ESP marker cannot be used there.
func (r *Responder) buildSAInitResponse(spiI, spiR uint64, proposal Proposal, suite SASuite, dh *DHKeyPair, nr []byte, endpoint transport.Endpoint) ([]byte, error) {
	hashAlgos := make([]byte, 2)
	binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
	var fakeAddr [4]byte
	if _, err := rand.Read(fakeAddr[:]); err != nil {
		return nil, err
	}
	peer := endpoint.AddrPort()
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		{Type: PayloadN, Body: EncodeNotify(Notify{
			Type: N_NAT_DETECTION_SOURCE_IP,
			Data: natDetectionHash(spiI, spiR, net.IP(fakeAddr[:]), 0),
		})},
		{Type: PayloadN, Body: EncodeNotify(Notify{
			Type: N_NAT_DETECTION_DESTINATION_IP,
			Data: natDetectionHash(spiI, spiR, net.IP(peer.Addr().AsSlice()), peer.Port()),
		})},
	}
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0}
	return (&Message{Header: header, Payloads: payloads}).Encode(), nil
}

// completeResponderAuth waits for IKE_AUTH, authenticates the initiator and
// answers with our own AUTH and the selected Child SA. A duplicate
// IKE_SA_INIT while waiting is answered with the identical response.
// created, with an error, reports an answer carrying our AUTH and the Child SA's error, which leaves the IKE SA established
func (s *Session) completeResponderAuth(r *Responder, realMessage1, realMessage2, ni, nr []byte, deadline time.Time) (_ Accepted, created bool, _ error) {
	ctx := s.current
	got, err := s.awaitAuthRequest(realMessage1, realMessage2, deadline)
	if err != nil {
		return Accepted{}, false, err
	}
	outer, source := got.outer, got.source
	// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
	// only an authenticated request moves where this end sends, and the decryption above authenticated this one whether or not its payloads parse
	s.mux.AdoptEndpoint(source)
	inner, err := decodeMessagePlaintext(got.innerFirst, got.plaintext)
	if err != nil {
		// RFC 7296 section 2.21.2: "request messages that contain an unsupported critical payload, or where the whole message is malformed (rather than just bad payload contents), MUST be rejected in their entirety, and MUST only lead to an UNSUPPORTED_CRITICAL_PAYLOAD or INVALID_SYNTAX Notification sent as a response."
		return Accepted{}, false, s.rejectAuth(N_INVALID_SYNTAX, nil, fmt.Errorf("ike: malformed IKE_AUTH request: %w", err))
	}

	// RFC 7296 section 2.5: "In that Notify payload, the Notification Data contains the one-octet payload type."
	if unsupported, found := firstUnsupportedCritical(outer.Payloads, inner); found {
		return Accepted{}, false, s.rejectAuth(N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)},
			fmt.Errorf("ike: IKE_AUTH request marks payload type %d critical", unsupported))
	}

	request := &Message{Header: outer.Header, Payloads: inner}
	idiPayload, authPayload := request.find(PayloadIDi), request.find(PayloadAUTH)
	if idiPayload == nil || authPayload == nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, fmt.Errorf("ike: IKE_AUTH request has no IDi or AUTH"))
	}
	aliases := r.aliases()
	peer, err := aliases.resolve(idiPayload.Body)
	if err != nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, err)
	}
	peerID := peer.endpoint
	// with a key its organization shares, another node of it could otherwise claim our name
	for local := range r.cfg.Local {
		if local.Node() == peerID.Node() {
			return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, fmt.Errorf("ike: IDi names our own node %s", peerID.Node()))
		}
	}
	peerKey, peerFamily, err := r.cfg.Trust.Key(peerID)
	if err != nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, err)
	}
	macedIDForI := prf(ctx.suite.PRFID, ctx.skpi, idiPayload.Body)
	if err := VerifyAuth(peerKey, concat(realMessage1, nr, macedIDForI), authPayload.Body); err != nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, err)
	}
	// RFC 7296 section 3.5 has the identity "used for policy lookup" and "to perform access control decisions"
	// an IDi naming an endpoint of another family names one that did not dial, as an endpoint dials in its own family alone
	// the endpoint's family is compared, never an address the ID holds
	arrived := familyOf(source.AddrPort().Addr())
	if peerFamily != arrived {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil,
			fmt.Errorf("ike: IDi names %s, an endpoint of the %s family, and the request arrived in %s", peerID, peerFamily, arrived))
	}

	presented, err := aliases.presented(peerID)
	if err != nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, err)
	}
	localID, idrBody, err := r.localIdentity(aliases, request.find(PayloadIDr), presented, arrived)
	if err != nil {
		return Accepted{}, false, s.rejectAuth(N_AUTHENTICATION_FAILED, nil, err)
	}
	if r.cfg.Events != nil {
		r.cfg.Events(localID, peerID, "ike.id.resolved", peer.attrs(idrBody)...)
	}
	macedIDForR := prf(ctx.suite.PRFID, ctx.skpr, idrBody)
	authBody := BuildAuth(r.cfg.LocalPrivateKey, concat(realMessage2, ni, macedIDForR))

	// RFC 7296 section 2.21.2: "If authentication has succeeded in the IKE_AUTH exchange, the IKE SA is established"
	// and: "Specifically, a responder may include all the payloads associated with authentication (IDr, CERT, and AUTH) while sending error notifications for the piggybacked exchanges (FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, and so on), and the initiator MUST NOT fail the authentication because of this."
	child, err := s.selectResponderChild(request, ni, nr)
	if err != nil {
		// no KE payload follows in IKE_AUTH, so no INVALID_KE_PAYLOAD could be acted on
		response, buildErr := s.response(ctx, 1, IKE_AUTH, []RawPayload{
			{Type: PayloadIDr, Body: idrBody},
			{Type: PayloadAUTH, Body: authBody},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})},
		})
		if buildErr != nil {
			return Accepted{}, false, err
		}
		// retained before it is sent, since an IKE_AUTH retransmitted while the IKE SA's Delete is outstanding is answered from it
		s.stateMu.Lock()
		ctx.lastPeerResponseID, ctx.lastPeerResponse = 1, response
		s.stateMu.Unlock()
		_ = s.mux.SendIKE(response)
		return Accepted{}, true, err
	}

	localSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(localSPI, child.sa.LocalSPI)
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	response, err := s.response(ctx, 1, IKE_AUTH, []RawPayload{
		{Type: PayloadIDr, Body: idrBody},
		{Type: PayloadAUTH, Body: authBody},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{child.proposal(localSPI)})},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	})
	if err != nil {
		return Accepted{}, false, err
	}
	if err := s.replaceChild(child.sa); err != nil {
		return Accepted{}, false, err
	}
	// Retain the response before sending it: Session.Run answers a
	// retransmitted IKE_AUTH from here, and the initiator may retransmit
	// before we ever reach Run.
	s.stateMu.Lock()
	ctx.lastPeerResponseID, ctx.lastPeerResponse = 1, response
	s.stateMu.Unlock()
	if err := s.mux.SendIKE(response); err != nil {
		return Accepted{}, false, err
	}
	return Accepted{Peer: peerID, Local: localID, Key: peerKey}, true, nil
}

// authRequest is the first IKE_AUTH request that decrypted under this
// half-open SA's keys, with the pieces that proved it.
type authRequest struct {
	raw        []byte
	outer      *Message
	innerFirst PayloadType
	plaintext  []byte
	source     transport.Endpoint
}

// awaitAuthRequest waits for the initiator's IKE_AUTH, answering a repeat of
// the IKE_SA_INIT request with the identical response we already sent.
//
// RFC 7296 section 2.1: "It is not sufficient to use the initiator's SPI and/or IP address to differentiate between these three cases because two different peers behind a single NAT could choose the same initiator SPI."
// so a repeat is matched on the whole packet, which also keeps a bare header naming a live SPIi, which anyone who opened one knows, from drawing the response at whatever source it claims
func (s *Session) awaitAuthRequest(saInitRequest, saInitResponse []byte, deadline time.Time) (*authRequest, error) {
	ctx := s.current
	for {
		raw, source, err := s.mux.RecvIKEFromUntil(deadline)
		if err != nil {
			return nil, fmt.Errorf("ike: waiting for IKE_AUTH: %w", err)
		}
		header, err := decodeHeader(raw)
		if err == nil && higherVersion(s.mux.SendIKETo, header, source) {
			continue
		}
		if err != nil || header.MajorVersion != 2 || header.Length != uint32(len(raw)) ||
			header.SPIInitiator != ctx.spiI || header.IsResponse() || !header.IsInitiator() {
			continue
		}
		if header.ExchangeType == IKE_SA_INIT && header.MessageID == 0 && header.SPIResponder == 0 {
			if !bytes.Equal(raw, saInitRequest) {
				continue
			}
			if err := s.mux.SendIKETo(saInitResponse, source); err != nil {
				return nil, err
			}
			continue
		}
		if header.ExchangeType != IKE_AUTH || header.MessageID != 1 || header.SPIResponder != ctx.spiR {
			continue
		}
		// a datagram with the right header that does not authenticate is one more to wait past, since anyone who sees the responder SPI can send one
		// and acting on it would end a handshake this end has paid for
		outer, err := DecodeMessage(raw)
		if err != nil {
			continue
		}
		innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
		if err != nil {
			continue
		}
		return &authRequest{raw: raw, outer: outer, innerFirst: innerFirst, plaintext: plaintext, source: source}, nil
	}
}

func (r *Responder) noteHandshakeFailure(endpoint transport.Endpoint, err error) {
	if !r.failureIsDue(endpoint) {
		slog.Debug("ike responder handshake failed", "peer", endpoint, "err", err)
		return
	}
	slog.Warn("ike responder handshake failed", "peer", endpoint, "err", err)
	// recorded where it is said, so a source that fails over and over costs the record what it costs the log
	if r.cfg.Events != nil {
		r.cfg.Events(identity.Identity{}, identity.Identity{}, "ike.handshake.failed", slog.String("from", endpoint.String()), slog.String("err", err.Error()))
	}
}

// failureIsDue reports whether this source's failure is the one to say out
// loud. Both limits are needed: the per-source one alone is a line per address
// to a host holding a range of them, and the floor alone hides every peer
// behind whichever one is failing fastest. The record is emptied rather than
// swept when it fills, so it cannot grow, and a source arriving to a full one
// meets the floor rather than silence.
func (r *Responder) failureIsDue(endpoint transport.Endpoint) bool {
	source := endpoint.AddrPort().Addr().Unmap()
	now := time.Since(r.started)
	r.failureMu.Lock()
	defer r.failureMu.Unlock()
	if reported, seen := r.failureReported[source]; seen && now-reported < handshakeFailureInterval {
		return false
	}
	if now-r.failureSaid < handshakeFloor {
		return false
	}
	if len(r.failureReported) >= handshakeFailureSources {
		clear(r.failureReported)
	}
	r.failureReported[source], r.failureSaid = now, now
	return true
}

// rejectAuth answers a refused IKE_AUTH request inside the SK payload, which
// the initiator can decrypt, and returns the underlying reason unchanged. An
// authentication failure is deliberately uninformative: which of identity, key
// or signature failed is not the peer's business.
func (s *Session) rejectAuth(notify NotifyType, data []byte, cause error) error {
	response, err := s.responseNotifyData(s.current, 1, IKE_AUTH, notify, data)
	if err == nil {
		_ = s.mux.SendIKE(response)
	}
	return cause
}

// responderChild is the Child SA selected from an IKE_AUTH request, kept
// together with the transform that has to be echoed in the response.
type responderChild struct {
	sa         ChildSA
	number     uint8
	encryption Transform
	dh         Transform
	integ      Transform
}

func (c responderChild) proposal(spi []byte) Proposal {
	encryption := c.encryption
	if encryption.ID == ENCR_CHACHA20_POLY1305 {
		// selectChildRequestProposal normalizes the key length so keymat has
		// one, but RFC 7296 section 3.3.5 forbids the Key Length attribute on a
		// fixed-key transform and section 3.3.6 requires the attributes of a selected
		// transform to come back unchanged. The offer carried none, so neither
		// may the answer. child_rekey.go does the same for CREATE_CHILD_SA.
		encryption.KeyLengthBits = 0
	}
	transforms := []Transform{encryption, {Type: TransESN, ID: ESN_NO}}
	// A proposal that spelled out DH NONE or INTEG NONE gets it back: section
	// 2.7 wants one transform of every type the offer carried.
	if c.dh.Type != 0 {
		transforms = append(transforms, c.dh)
	}
	if c.integ.Type != 0 {
		transforms = append(transforms, c.integ)
	}
	return Proposal{
		// RFC 7296 section 3.3.1: "the proposal number in the SA payload MUST match
		// the number on the proposal sent that was accepted". A peer whose
		// second proposal we took has to see that number back.
		Number:     c.number,
		Protocol:   ProtoESP,
		SPI:        spi,
		Transforms: transforms,
	}
}

func (s *Session) selectResponderChild(request *Message, ni, nr []byte) (responderChild, error) {
	ctx := s.current
	saPayload := request.find(PayloadSA)
	tsi, tsr := request.find(PayloadTSi), request.find(PayloadTSr)
	if saPayload == nil || tsi == nil || tsr == nil {
		return responderChild{}, fmt.Errorf("ike: IKE_AUTH request has no Child SA")
	}
	if err := validateFullRangeSelectors(tsi, tsr); err != nil {
		return responderChild{}, err
	}
	// RFC 7296 section 1.2: "Thus, the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE."
	// so no group is taken here, and a proposal offering only groups is unacceptable
	selection, err := selectChildRequestProposal(saPayload.Body, s.lists().espCiphers(), nil, 0, groupOptional)
	if err != nil {
		return responderChild{}, err
	}
	initiatorKey, responderKey, err := ChildSAKeymat(ctx.suite.PRFID, ctx.skD, ni, nr, selection.encryption.ID, selection.encryption.KeyLengthBits)
	if err != nil {
		return responderChild{}, err
	}
	return responderChild{
		sa: ChildSA{
			EncrID: selection.encryption.ID, EncrKeyBits: selection.encryption.KeyLengthBits,
			LocalSPI: randUint32Nonzero(), RemoteSPI: selection.remoteSPI,
			InboundKey: initiatorKey, OutboundKey: responderKey,
		},
		number:     selection.proposal.Number,
		encryption: selection.encryption,
		dh:         selection.dh,
		integ:      selection.integ,
	}, nil
}

func (r *Responder) aliases() Aliases {
	if r.cfg.Aliases == nil {
		return Aliases{}
	}
	return r.cfg.Aliases()
}

// localIdentity is the endpoint we answer as and the IDr body we answer with
// presented is the body auth.aliases.local gives toward the caller, or nil for the DN
// RFC 7296 section 1.2 lets a responder "use some other IDr to finish the exchange", which this one never does
// our AUTH signs the IDr we send, and the initiator verifies it over the IDr it receives
// an IDr asked for is answered with its type and data in our own encoding, since RFC 7296 section 3.5 has RESERVED "MUST be sent as zero"
func (r *Responder) localIdentity(aliases Aliases, idr *RawPayload, presented []byte, arrived Family) (identity.Identity, []byte, error) {
	if idr == nil {
		local, err := r.answering(arrived)
		if err != nil {
			return identity.Identity{}, nil, err
		}
		if presented == nil {
			presented = r.local[local]
		}
		return local, presented, nil
	}
	idType, data, err := DecodeID(idr.Body)
	if err != nil {
		return identity.Identity{}, nil, err
	}
	asked, err := aliases.resolve(idr.Body)
	switch {
	case err == nil:
		family, ours := r.cfg.Local[asked.endpoint]
		switch {
		case !ours:
			return identity.Identity{}, nil, fmt.Errorf("ike: IKE_AUTH request names %s, which we do not answer as", asked.endpoint)
		case family != arrived:
			// the request did not reach it, as an endpoint is dialed in its own family alone
			return identity.Identity{}, nil, fmt.Errorf("ike: IKE_AUTH request names our %s, an endpoint of the %s family, and arrived in %s", asked.endpoint, family, arrived)
		case idType == ID_DER_ASN1_DN:
			return asked.endpoint, r.local[asked.endpoint], nil
		}
		return asked.endpoint, EncodeID(idType, data), nil
	case idType == ID_DER_ASN1_DN:
		return identity.Identity{}, nil, err
	case !aliases.presents(idr.Body):
		return identity.Identity{}, nil, fmt.Errorf("ike: IKE_AUTH request names %s ID %q, which we do not answer to", idType, idText(idType, data))
	}
	local, err := r.answering(arrived)
	return local, EncodeID(idType, data), err
}

// answering is the endpoint of the family the request arrived in, which answers a request whose IDr names none of ours
// RFC 7296 section 1.2 has IDr name "to which of the responder's identities it wants to talk"
// an alias names the node, and an endpoint is dialed in its own family alone
// none or two in that family leave the endpoint it reached unknown, which is refused rather than guessed, our only endpoint included
func (r *Responder) answering(arrived Family) (identity.Identity, error) {
	var in []identity.Identity
	for local, family := range r.cfg.Local {
		if family == arrived {
			in = append(in, local)
		}
	}
	if len(in) != 1 {
		return identity.Identity{}, fmt.Errorf("ike: IKE_AUTH request names none of our endpoints, and %d of our %d are of the %s family it arrived in", len(in), len(r.cfg.Local), arrived)
	}
	return in[0], nil
}

func sameID(received, presented []byte) bool {
	idType, data, err := DecodeID(received)
	if err != nil {
		return false
	}
	theirs, err := matchKey(idType, data)
	if err != nil {
		return false
	}
	ours, err := matchKey(IDType(presented[0]), presented[4:])
	return err == nil && theirs == ours
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// and: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
func firstUnsupportedCritical(lists ...[]RawPayload) (PayloadType, bool) {
	for _, payloads := range lists {
		for _, payload := range payloads {
			if payload.Critical && !supportedPayloadType(payload.Type) {
				return payload.Type, true
			}
		}
	}
	return 0, false
}

func (r *Responder) enterHalfOpen(source netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.halfOpen >= halfOpenLimit || r.halfOpenBySource[source] >= halfOpenPerSource {
		return false
	}
	if r.halfOpenBySource == nil {
		r.halfOpenBySource = make(map[netip.Addr]int)
	}
	r.halfOpen++
	r.halfOpenBySource[source]++
	return true
}

func (r *Responder) leaveHalfOpen(source netip.Addr) {
	r.mu.Lock()
	// Floored, because a count that went negative would disable the cookie
	// threshold and the cap together and nothing would ever bring it back.
	if r.halfOpen > 0 {
		r.halfOpen--
	}
	if r.halfOpenBySource[source] <= 1 {
		delete(r.halfOpenBySource, source)
	} else {
		r.halfOpenBySource[source]--
	}
	r.mu.Unlock()
}

// cookieRequired reports whether request, under pressure on the half-open count or on this address's share of it, was answered with a cookie, and the caller then stops without allocating
// RFC 7296 section 2.6: "When a responder detects a large number of half-open IKE SAs, it SHOULD reply to IKE_SA_INIT requests with a response containing the COOKIE notification."
func (r *Responder) cookieRequired(request *Message, ni []byte, spiI uint64, endpoint transport.Endpoint) (bool, error) {
	source := endpoint.AddrPort().Addr()
	r.mu.Lock()
	// the share one address may hold without a cookie stops an off-path spoofer spending a named peer's whole share while the node is idle
	pressure := r.halfOpen >= cookieThreshold ||
		r.halfOpenBySource[source] >= halfOpenPerSourceWithoutCookie
	// the secret rotates on its age alone, so a node that takes IKE_SA_INITs without reaching pressure still rotates it
	if time.Since(r.cookieRotated) > cookieLifetime {
		var next [cookieSecretLen]byte
		if _, err := rand.Read(next[:]); err != nil {
			r.mu.Unlock()
			return false, err
		}
		r.previousSecret, r.previousValid = r.cookieSecret, true
		r.cookieSecret = next
		r.cookieVersion++
		r.cookieRotated = time.Now()
	}
	secret, version := r.cookieSecret, r.cookieVersion
	previous, havePrevious := r.previousSecret, r.previousValid
	r.mu.Unlock()
	if !pressure {
		return false, nil
	}
	expected := cookieValue(secret, version, ni, spiI, endpoint)
	accepted := [][]byte{expected}
	if havePrevious {
		accepted = append(accepted, cookieValue(previous, version-1, ni, spiI, endpoint))
	}
	for _, payload := range request.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil || notify.Type != N_COOKIE {
			continue
		}
		for _, candidate := range accepted {
			if hmac.Equal(notify.Data, candidate) {
				return false, nil
			}
		}
	}
	_ = r.cfg.Hub.SendIKETo(statelessNotify(&request.Header, N_COOKIE, expected), endpoint)
	return true, nil
}

// cookieValue is the version octet followed by a keyed hash over everything
// that identifies this attempt, so the cookie is bound to the nonce, the SPI
// and the address it was sent to and cannot be replayed for another.
func cookieValue(secret [cookieSecretLen]byte, version uint8, ni []byte, spiI uint64, endpoint transport.Endpoint) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(ni)
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], spiI)
	mac.Write(spi[:])
	mac.Write([]byte(endpoint.String()))
	return append([]byte{version}, mac.Sum(nil)...)
}

// sendStatelessNotify answers an IKE_SA_INIT request we will not carry
// forward, whose zero responder SPI the answer keeps since no SA was created.
func (r *Responder) sendStatelessNotify(datagram transport.Unclaimed, request *Header, notify NotifyType, data []byte) {
	if statelessErrors.take() {
		_ = r.cfg.Hub.SendIKETo(statelessNotify(request, notify, data), datagram.Endpoint)
	}
}

// selectIKEProposal answers an IKE_SA_INIT offer from lists
// a KE payload in another group than the one chosen draws INVALID_KE_PAYLOAD naming that group
func selectIKEProposal(body []byte, keGroup uint16, lists Suites) (Proposal, SASuite, error) {
	proposals, err := DecodeSA(body)
	if err != nil {
		return Proposal{}, SASuite{}, fmt.Errorf("ike: invalid IKE SA proposal: %w", err)
	}
	proposals = slices.DeleteFunc(proposals, func(proposal Proposal) bool {
		return proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 0
	})
	chosen, retry, ok := chooseIKE(proposals, lists.ikeCiphers(), lists.ikePRFs(), lists.kexGroups(), keGroup)
	if retry != 0 {
		return Proposal{}, SASuite{}, &invalidKEError{retry}
	}
	if !ok {
		return Proposal{}, SASuite{}, fmt.Errorf("ike: no acceptable IKE SA proposal")
	}
	return Proposal{Number: chosen.offered.Number, Protocol: ProtoIKE, Transforms: chosen.transforms}, chosen.suite, nil
}

// ikeChoice is the answer to an IKE SA offer
type ikeChoice struct {
	// offered is the proposal it answers
	offered Proposal
	// transforms holds one of each type offered includes
	transforms []Transform
	suite      SASuite
}

// chooseIKE answers the proposals of an IKE SA offer from ciphers, prfs and groups, each in this end's order
// chooseGroup picks the proposal and its group among those the lists meet in every other type
// and in each other type the proposal takes the first of the list it holds
// retry is the group to ask for in INVALID_KE_PAYLOAD
// RFC 7296 section 3.3: "If there is more than one, they MUST be ordered from most preferred to least preferred."
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
// RFC 7296 section 3.3.6: "If the responder receives a proposal that contains a Transform Type it does not understand, or a proposal that is missing a mandatory Transform Type, it MUST consider this proposal unacceptable" and "other proposals in the same SA payload are processed as usual."
func chooseIKE(proposals []Proposal, ciphers, prfs, groups []Transform, keGroup uint16) (ikeChoice, uint16, bool) {
	var met []ikeChoice
	var offers [][]Transform
	for _, proposal := range proposals {
		known := true
		var integ *Transform
		offeredInteg := false
		for i := range proposal.Transforms {
			transform := proposal.Transforms[i]
			switch transform.Type {
			case TransEncr, TransPRF, TransDH:
			case TransInteg:
				// RFC 7296 section 3.3: "Combined-mode ciphers include both integrity and encryption in a single encryption algorithm, and MUST either offer no integrity algorithm or a single integrity algorithm of "NONE", with no integrity algorithm being the RECOMMENDED method."
				// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable" and "other transforms with the same Transform Type are processed as usual."
				offeredInteg = true
				if integ == nil && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
					integ = &transform
				}
			default:
				known = false
			}
		}
		encr, haveEncr := choose(ciphers, proposal.Transforms)
		prfT, havePRF := choose(prfs, proposal.Transforms)
		if !known || offeredInteg && integ == nil || !haveEncr || !havePRF {
			continue
		}
		// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
		transforms := []Transform{encr, prfT}
		if integ != nil {
			transforms = append(transforms, *integ)
		}
		met = append(met, ikeChoice{offered: proposal, transforms: transforms, suite: SASuite{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, PRFID: prfT.ID}})
		offers = append(offers, proposal.Transforms)
	}
	at, group, retry, ok := chooseGroup(offers, groups, keGroup, groupRequired)
	if !ok {
		return ikeChoice{}, retry, false
	}
	chosen := met[at]
	chosen.transforms = slices.Insert(chosen.transforms, 2, group)
	chosen.suite.DHGroup = group.ID
	return chosen, 0, true
}
