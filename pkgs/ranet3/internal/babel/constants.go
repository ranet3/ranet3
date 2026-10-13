// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import "ranet3.com/pkgs/ranet3/srv6"

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
