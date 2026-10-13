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
// a full table at maxRouteKeys, each prefix a /128 behind a Router-Id of its own, takes eleven packets of the largest size RFC 8966 section 4 allows
// the stack that cuts them sends one packet's fragments together, so 16 places hold a whole burst of them under way at once
// each place holds 1280 octets of bookkeeping as the Go allocator sizes it, 20 KiB for the neighbor
// a newer datagram reuses the bookkeeping of the one whose place it takes
// a place is allocated anew only once its datagram expired, at most 16 every maxFragmentAge
// each place goes to at most one datagram not read every minFragmentAge
// maxFragmentOctets says what that allocates
const maxFragmentedDatagrams = 16

// maxFragmentOctets bounds the storage one neighbor's datagrams under way hold, each in a power of two the Go allocator holds as it is
// it holds four packets of the largest size under way at once, 64 KiB each, where a burst sends them one after another, and a packet of the 1443 UDP octets the field sends takes 2 KiB of it
// 256 KiB stays under the megabyte the neighbor's control queue may hold, and under 2 percent of the 18 MB its data budget may hold with its sealed copies, see controlQueueSize and peerDataBudget
// a datagram grows its storage in powers of two up to 64 KiB, allocating under 128 KiB in all
// a neighbor flooding datagrams that never complete has the node allocate under 2 MiB of storage every minFragmentAge
// that is under 128 KiB for each place
// a place goes to at most one such datagram in that time
// a datagram read allocated under four times the octets its fragments carried
const maxFragmentOctets = 4 * (math.MaxUint16 + 1)

// minFragmentAge is how long a datagram not read keeps its place, and one under way its storage, against the neighbor's newer datagrams
// a packet's fragments leave the neighbor back to back and cross one session together
// at 1 Mbit/s a session carries the 1443 UDP octets the field sends in 12 milliseconds and even the largest Babel packet within a second
// a datagram still under way after that has lost a fragment
// a newer datagram that finds every place, or the storage it needs, held by younger ones is refused
// each place thus goes to at most one datagram not read in this time
// that bounds what a flooding neighbor has the node allocate
const minFragmentAge = time.Second

// maxFragmentAge is how long a datagram waits for its fragments after its first arrived, where RFC 8200 section 4.5 allows 60 seconds
// a packet's fragments leave the neighbor together and cross one session, which carries even the largest within a second at 1 Mbit/s
// one still missing after an update interval, 16 seconds at the defaults BIRD and babeld share, is lost, and the neighbor's next periodic dump repeats what it carried before the routes it announced expire after 56 seconds
// a datagram read or dropped stays as long unless a newer one takes its place
// while it stays a fragment of it still to come goes with it
// while it stays a copy of one read is not read twice
const maxFragmentAge = 16 * time.Second
