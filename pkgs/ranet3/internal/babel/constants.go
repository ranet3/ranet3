// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"math"
	"time"

	"ranet3.com/pkgs/ranet3/srv6"
)

// defaultPacketSize is the most one babel packet carries when the runtime names no size, its four-byte header included
// with its IPv6 and UDP headers it makes an inner packet of the IPv6 minimum MTU
// every session carries a packet that large whatever its path
// no babel packet is then larger than the session it leaves through carries
const defaultPacketSize = srv6.MinimumIPv6MTU - ipv6HeaderLen - udpHeaderLen

// defaultMargin is cap.babel.margin where the file leaves it out
const defaultMargin = 4

// refusalLogInterval is the least time between two warnings of one kind of refusal, each with the count since the one before
// a neighbor past a bound is refused for every update it repeats, and a spaced line says the bound still holds it without the refusals flooding the log
const refusalLogInterval = time.Minute

// maxTriggerPace is the longest triggerPace spaces two triggered updates to one neighbor
const maxTriggerPace = time.Second

// probeInterval is the Interval a probe's Ack Request names, the longest the field holds
// a receiver answers before it elapses, RFC 8966 section 4.6.3
// the caller of Speaker.Probe counts a probe lost on a timer of its own
const probeInterval = maxInterval

// seqnoLimitAhead is how far past the seqno in use the saved limit runs
// a start resumes one past the limit
// the seqno then moves on by at most this many and one
// RFC 8966 section 3.2.1 orders two seqnos less than 32768 apart, room for 127 such starts
// a feasibility distance a far node kept from before them still reads as older than the seqno after them
// each raise past the limit waits on a write and a directory sync under s.mu
// one write covers this many raises
const seqnoLimitAhead = 256

// maxFragmentedDatagrams is the most datagrams one neighbor's reassembly keeps a place for, under way, read or dropped
// a full table at maxRouteKeys, each prefix a /128 behind a Router-Id of its own, takes a few packets of the largest size RFC 8966 section 4 allows
// the stack that cuts them sends one packet's fragments together, so 16 places hold a whole burst of them under way at once
// each place holds 1280 octets of bookkeeping as the Go allocator sizes it
// a newer datagram reuses the bookkeeping of the one whose place it takes
// a place is allocated anew only once its datagram expired, at most 16 every maxFragmentAge
// each place goes to at most one datagram not read every minFragmentAge
// maxFragmentOctets says what that allocates
const maxFragmentedDatagrams = 16

// maxFragmentOctets bounds the storage one neighbor's datagrams under way hold, each in a power of two the Go allocator holds as it is
// it holds four packets of the largest size under way at once, where a burst sends them one after another
// it stays under the neighbor's control queue and a small share of its data budget, see controlQueueSize and peerDataBudget
// a datagram grows its storage in powers of two up to the largest packet, allocating under twice that in all
// a neighbor flooding datagrams that never complete has the node allocate under that for each place every minFragmentAge
// a place goes to at most one such datagram in that time
// a datagram read allocated under four times the octets its fragments carried
const maxFragmentOctets = 4 * (math.MaxUint16 + 1)

// minFragmentAge is how long a datagram not read keeps its place, and one under way its storage, against the neighbor's newer datagrams
// a packet's fragments leave the neighbor back to back and cross one session together
// at 1 Mbit/s a session carries even the largest Babel packet within a second
// a datagram still under way after that has lost a fragment
// a newer datagram that finds every place, or the storage it needs, held by younger ones is refused
// each place thus goes to at most one datagram not read in this time
// that bounds what a flooding neighbor has the node allocate
const minFragmentAge = time.Second

// maxFragmentAge is how long a datagram waits for its fragments after its first arrived, where RFC 8200 section 4.5 allows 60 seconds
// a packet's fragments leave the neighbor together and cross one session, which carries even the largest within a second at 1 Mbit/s
// one still missing after an update interval, 16 seconds at the defaults BIRD and babeld share, is lost, and the neighbor's next periodic dump repeats what it carried before the routes it announced expire
// a datagram read or dropped stays as long unless a newer one takes its place
// while it stays a fragment of it still to come goes with it
// while it stays a copy of one read is not read twice
const maxFragmentAge = 16 * time.Second

// seqnoForwardExpiry is how long a seqno request this node forwarded is kept, so the new seqno that answers it is sent on as a triggered update, RFC 8966 section 3.8.1.2
// the answer comes back one hop at a time, each in a triggered update the hop before it sent, so it can arrive well after the seqnoRequestSuppress in which a repeat is redundant
// it is BIRD's BABEL_SEQNO_FORWARD_EXPIRY
const seqnoForwardExpiry = 10 * time.Second

// seqnoRequestSuppress is the request timeout RFC 8966 Appendix B suggests. A
// request for the same source within this window is redundant
// (section 3.8.1.2) and is dropped instead of forwarded.
const seqnoRequestSuppress = 2 * time.Second

// seqnoRequestHopCount is the hop count of a locally originated seqno request:
// "64 is a suitable default value", RFC 8966 section 3.8.2.1.
const seqnoRequestHopCount = 64

// sourceGCTime is the source GC time RFC 8966 Appendix B suggests.
const sourceGCTime = 3 * time.Minute

// maxPendingSeqno bounds the table of pending seqno requests, and
// maxPendingSeqnoPerNeighbor bounds what any one neighbor can spend of it. An
// entry is only ever created for a prefix this node has a route for, which
// bounds one half of the index. The other half is the router id the requester
// wrote into the packet, which nothing bounds, and many seqno requests fit in a
// single packet. Past a cap the request is not forwarded, as the suppression
// within seqnoRequestSuppress does with a redundant one, and is the list of
// recently forwarded requests RFC 8966 section 3.8.1.2 asks a node to keep.
//
// The per-neighbor share keeps one of them from turning forwarding off for
// the rest: a flood that filled a single global table would stop every
// other neighbor's requests being relayed, and a prefix that starves behind
// this node would stop recovering until the flood did.
const (
	maxPendingSeqno            = 1 << 12
	maxPendingSeqnoPerNeighbor = 1 << 10
)

// maxStarveRetries bounds the prefixes this node is repeating a seqno request
// for, and maxStarveRetriesPerNeighbor is one neighbor's share of that. The
// index carries a router id a neighbor writes into a packet, so nothing else
// bounds it, and every entry is walked under s.mu on each wake of the run
// loop. Without the share one neighbor fills the table from the ordinary route
// acquisition path, and RFC 8966 section 3.8.2.1's "repeat such a request a
// small number of times" then stops happening for every other neighbor, so a
// lost request or a lost reply is never covered.
const (
	maxStarveRetries            = 1 << 12
	maxStarveRetriesPerNeighbor = 1 << 10
)

// seqnoRequestRetries and seqnoRetryInitial are how often and after how long
// this node repeats a seqno request, since RFC 8966 section 3.8.2.1 says a node
// "SHOULD repeat such a request a small number of times if no route becomes
// feasible within a short time". One request is not enough: losing it, or its
// reply, leaves the prefix starved for as long as the unfeasible route keeps
// being refreshed, and the unfeasible route pins the feasibility distance so
// that never expires either. BIRD repeats four times, doubling the delay. The
// first delay is longer than seqnoRequestSuppress so a retry is not dropped as
// redundant by our own suppression table.
const (
	seqnoRequestRetries = 4
	seqnoRetryInitial   = 3 * time.Second
)

// routeLogInterval bounds how often a selection change is said out loud at
// info. One neighbor alternating an update and a retraction for one prefix
// drives a change per TLV, many to one packet, each a synchronous write on the
// goroutine holding s.mu. Every change is still written at debug, where it
// costs a level comparison unless somebody asked for it, and the info line
// carries how many it stands for.
//
// Kept at or below a second so an operator watching a flapping mesh still sees
// it move. TestSelectionChangesAreNotOneLogLineEach holds that bound.
const routeLogInterval = time.Second

// maxSources bounds the source table and maxOriginsPerPrefix bounds what any
// one prefix can spend of it. The index is a prefix and a router id: this
// node's route table bounds the prefixes, nothing bounds the router ids, and a
// neighbor that names a new origin for one prefix on every packet adds an
// entry on every packet that lives for sourceGCTime.
//
// Past a cap an origin this node has never advertised is unfeasible. Refusing
// a route can never close a loop, so routes already selected keep working and
// the prefixes this node originates still record their distance. The
// per-prefix share keeps the damage local: a global cap alone is first
// come, so one neighbor churning the origin of one prefix would stop this node
// learning any new origin anywhere, including a peer that restarted and drew a
// new router id, which a node that lost its sequence number state does.
//
// The numbers sit far above what a legitimate prefix or a restarting neighbor
// produces and far below what a flood needs.
const (
	maxSources          = 1 << 16
	maxOriginsPerPrefix = 1 << 10
	// maxOriginsPerPrefixPerNeighbor is one neighbor's share of one prefix's
	// budget, and maxSourcesPerNeighbor is its share of the whole table. The
	// first stops one neighbor denying another the same prefix, and the second
	// stops one neighbor spending the global budget and denying every other
	// neighbor every prefix.
	//
	// Both are far above what a restart produces. A ranet3 node without a
	// usable state file, BIRD with randomize router id set and babeld with a
	// random id and no state file draw a new router id every time they start,
	// which makes each of their restarts a new origin for every prefix they
	// announce, charged to whichever neighbor this node reaches it through. A
	// cap that refuses an origin refuses a route, so it has to sit above
	// anything a supervisor restarting a peer can produce.
	maxOriginsPerPrefixPerNeighbor = 1 << 8
	maxSourcesPerNeighbor          = 1 << 13
)

// maxRouteKeys caps how many distinct prefixes this node will hold at once.
// It is well above any plausible mesh, which announces a few prefixes from
// each node, and a full internet table is not something a Babel mesh
// carries. It exists so the number is ours rather than a peer's.
const maxRouteKeys = 16384

// rttTimestampHorizon is the largest gap between two timestamps of one clock, this node's or the neighbor's, that an RTT sample is taken from
const rttTimestampHorizon = 3 * time.Minute

// betaWindow is how many recent entries the reception probability is computed
// over. RFC 8966 Appendix A.2.2 suggests "a small number (say, 6)", and the
// whole vector is chosen instead because BIRD popcounts hello_map over
// hello_cnt, its whole vector. At six the two ends disagree on the same loss,
// and a steady one-in-sixteen loss makes this end's advertised cost a square
// wave while the other end reads it as flat.
const betaWindow = historyDepth

// defaultRTTMax and defaultRTTWeight are rtt-max and max-rtt-penalty, which
// depart from RFC 9616 section 4.2, for the reason the protocol deviations page
// gives under Sending and link cost.
const (
	defaultRTTMax    = 1024 * time.Millisecond
	defaultRTTWeight = 1024
)

// sendAheadShare is the share of its interval by which the next Hello and the next periodic update go ahead of the time the last one named
// it is the margin RFC 8966 section 3.1 asks of such a TLV, "to allow for propagation delays", and section 3.4.1 lets a scheduled Hello go ahead of time
// a share rather than a fixed time keeps the margin under every interval Config.Validate accepts
const sendAheadShare = 16

// hysteresisHellos is the small multiple of the Hello interval RFC 8966 Appendix A.3 recommends as the hysteresis time constant
const hysteresisHellos = 3

// sendRetriesPerHello is how many times a pass that could not send everything it built retries inside one hello interval
// a refused Hello thus gets several attempts inside the three and a half intervals that withdraw the routes through the neighbor, each costing a pass rather than a packet
// at the shortest interval Config.Validate accepts, the first retry still comes before the neighbor's dead timeout
// minSendRetry is the least time between two such retries
const (
	sendRetriesPerHello = 4
	minSendRetry        = time.Millisecond
)
