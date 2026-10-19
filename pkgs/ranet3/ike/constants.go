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
	// the end giving an IKE SA up fails or ends whatever the answer, and a peer that holds the SA answers at once, so the budget covers one lost datagram
	teardownRetransmits = 2
	// RFC 7296 section 2.25: "If a peer continues to receive TEMPORARY_FAILURE on the same IKE SA after several minutes, it SHOULD conclude that the state information is out of sync and close the IKE SA."
	temporaryFailureSpan = 5 * time.Minute
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
	// requestBudget is the sends of one cut of a request, the time this end resends it under one threshold to a silent peer before it deems the IKE SA failed
	// a request that steps to its family's floor starts its waits over at the step, as one cut again for a path MTU that fell does, so its sends run past the budget
	// the sends of a step and of one or two falls still come within it, and a chain of falls can carry the last past it
	requestBudget = requestTimeout * (1<<maxRetransmits - 1)
	// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
	// this end's own IKE_FOLLOWUP_KE is resent as any request is, and a STATE_NOT_FOUND answering a send past the wait from the answer before, where a chain of falls carried it, fails the rekey without counting toward stateNotFoundLimit, and the rekey is retried on its schedule with the IKE SA kept
	followupWait = requestBudget
	// RFC 9370 section 2.2.4: "If the initiator continues to receive STATE_NOT_FOUND notifications after several retries, it MUST treat this situation as a fatal error and delete the IKE SA by sending a DELETE payload."
	// a series and two retries of it
	stateNotFoundLimit = 3
	// a link is drawn at random for each response, so an IKE_FOLLOWUP_KE that did not read it matches it only by guessing it
	followupLinkLen = 8

	// RFC 7383 section 5: "It is NOT RECOMMENDED for this value to exceed 64 KB because any IKE message before fragmentation would likely be shorter than that."
	// it bounds the datagrams one message's fragments arrive in, which hold more than their content, and leaves the largest message a peer sends room at the IPv4 floor
	reassemblyLimit = 16 << 10
	// RFC 7383 section 2.6: "It is RECOMMENDED that the reassembling timeout for the responder be equal to the time interval that the implementation waits before completely giving up when acting as the initiator of an exchange."
	// and: "Implementations can use a shorter timeout to conserve memory."
	// it is the sends of one cut, each new cut starting the queue over at its larger Total Fragments, and a half-open SA takes its fragments with it at handshakeTimeout, which comes first
	reassemblyTimeout = requestBudget
	// movedCredits bounds the credits an exchange keeps for addresses other than the origin that repeat its request, and with them the repeats in fragments it gathers, each within reassemblyLimit
	// a newcomer past them takes the place of the address whose last datagram arrived least recently
	// what an address draws spends its own credit alone, so a replay from fresh sources holds a moved peer only while more than movedCredits-1 of them arrive between every two of the peer's datagrams, for as long as the exchange runs, where a table that refused newcomers would hold it for the whole exchange once replays filled it before the peer moved
	movedCredits = 4
	// RFC 7383 section 2.5.2: "Performing a few retries within several seconds for each probe seems appropriate, but different environments may require different rules."
	// the backoff's sends under the path's threshold then span its first two intervals, and one lost datagram moves no threshold
	// a send that comes after them, the backoff's or a probe's, steps the request and starts the backoff over
	stepDownSends = 2

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
	// the error notifies sent in the clear answer a fleet's redial after an outage, up to halfOpenLimit dials, and the rate refills them within internal/client's 10 second reconnect delay
	statelessErrorBurst      = halfOpenLimit
	statelessErrorsPerSecond = 32
	// a flood of requests the limit holds back costs one line a minute
	statelessHeldReport = time.Minute

	// peers that never act on INVALID_KE_PAYLOAD redial every 30 to 90 seconds
	handshakeFailureInterval = 10 * time.Minute
	// anyone who reaches the port can fail a handshake
	handshakeFailureSources = 256
	handshakeFloor          = time.Second
)
