// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import "time"

// the rekey timings the Crypto accessors fill in, which a node runs with when cap.crypto is absent
const (
	DefaultChildRekey  = time.Hour
	DefaultIKERekey    = 3 * time.Hour
	DefaultRekeyMargin = 5 * time.Minute
	DefaultRekeyJitter = time.Minute
	DefaultRetryFirst  = 5 * time.Second
	DefaultRetryMax    = 5 * time.Minute
)

const (
	// RFC 7296 section 2.10 asks for at least half the key of the negotiated PRF, and PRF_HMAC_SHA2_384 is the largest offered
	nonceLen             = 32
	payloadChainCapacity = 256

	requestTimeout = 2 * time.Second
	maxRetransmits = 5
	// maxRetransmitsWhileBusy bounds an exchange the peer keeps alive with other traffic and never answers
	maxRetransmitsWhileBusy = 20
	// a dial that sends the INFORMATIONAL after IKE_AUTH fails whatever its answer, which only the responder's state depends on
	teardownRetransmits = 2
	// a responder that answered IKE_AUTH holds the SA until told, so a canceled initiator gives the answer one request's timeout
	canceledAuthWait = requestTimeout

	defaultDPDInterval = 10 * time.Second
	// one interval of silence draws a probe, and the second leaves the probe time to be answered
	activeDPDIntervals = 2

	// the peer's packets sent before it switched still arrive under the replaced Child SA
	childRetireDelay = 5 * time.Second
	// a replaced Child SA refuses every rekey until the peer's Delete, which RFC 7296 section 2.8 cannot make a peer send
	retirementDeadline = 30 * time.Second
	// a replaced IKE SA refuses every peer rekey until the peer's Delete, as a replaced Child SA does
	// it exceeds the retransmission budget of an exchange the peer does not answer, so a Delete still in flight finds its SA
	retainedContextDeadline = 2 * time.Minute
	// a peer-initiated Child SA rekey retains the SA it replaces, and a legitimate one is minutes apart
	minPeerChildRekeyInterval = time.Second
	// a peer-initiated IKE SA rekey costs a key exchange on the goroutine that runs the session, and a legitimate one is minutes apart
	minPeerIKERekeyInterval = time.Second

	// handshakeTimeout bounds a responder's whole handshake, the life of the cheapest state an unauthenticated peer can make it hold
	handshakeTimeout = 30 * time.Second
	// cookieThreshold is the half-open SAs at which IKE_SA_INIT is answered with a COOKIE, RFC 7296 section 2.6
	cookieThreshold = 32
	// a cookie proves only return routability, so the half-open SAs are bounded with cookies too
	halfOpenLimit = 256
	// one address cannot hold every slot, and more mesh nodes than this restarting at once behind one NAT are refused
	halfOpenPerSource = 16
	// a peer with two local endpoints dials one address twice
	halfOpenPerSourceWithoutCookie = 2
	cookieLifetime                 = 2 * time.Minute
	// RFC 2104 section 3 asks for a key at least as long as the HMAC-SHA-256 output
	cookieSecretLen = 32

	// peers that never act on INVALID_KE_PAYLOAD redial every 30 to 90 seconds
	handshakeFailureInterval = 10 * time.Minute
	// anyone who reaches the port can fail a handshake
	handshakeFailureSources = 256
	handshakeFloor          = time.Second
)
