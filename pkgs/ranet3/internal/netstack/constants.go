// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import "time"

// DefaultMTU is link.mtu where the file leaves it out, the largest inner packet a session carries
// a 1500 byte path carries it in one ESP-in-UDP datagram over IPv4 and over IPv6
const DefaultMTU = 1400

const (
	// outboundSlabSize is the bytes one read off the tun lays its packets out in, the slab wireguard-go's own device reads into
	// it holds every segment of the largest GSO frame a tun whose gso_max_segs is the read batch hands over, ReadPacketSpacing around each, as TestSlabHoldsTheLargestGSOFrame computes
	// so it holds a packet of 65535 bytes whatever the device's MTU
	outboundSlabSize = 2 * 65535
	// inboundWriteBatchSize is the most packets one write to the mesh tun carries
	// wireguard-go's tun write sizes its GRO tables for that many
	inboundWriteBatchSize = 128
	// inboundWriteQueueSize is the batches one inbound writer lane queues before a delivery to it waits
	// a busy writer merges the ones ready into its next tun write
	inboundWriteQueueSize = 64
	// inboundPendingBatches is how many write batches a lane's pending list holds before it grows
	// collectReadyInbound stops once one batch is pending, and the second leaves room for the entry that crossed it
	inboundPendingBatches = 2
	// outboundJobsPerWorker is the read batches queued for each crypto worker
	// one waits while the worker encrypts another
	outboundJobsPerWorker = 2
	// utunName asks darwin's utun control for its next free unit
	// followed by a unit number it asks for that unit
	// the control creates no other name
	utunName = "utun"
)

// TUNHeadroom is the space in front of each packet a Device.Write is handed, the offset wireguard-go's own device writes at
// darwin and the BSDs write the four-byte address family header a tun frame carries into it and refuse an offset under four
// linux refuses an offset under its ten-byte virtio-net header, which it sends from a buffer of its own
// it is as many bytes as the ESP header and IV every suite puts in front of a packet, so a packet decrypted in place has it in its own datagram, as TestHeadroomIsTheFramingOfEverySuite holds
// a read needs none, the device laying out the slab it reads into
const TUNHeadroom = 16

// reportInterval is the least time between two reports of one reportedCount, a read cut short, a frame the device refused, an ICMP error a limit withheld or a packet the forwarding decision dropped
// the counter keeps the exact count, and the report only has to point at it
const reportInterval = 30 * time.Second

// peerDataBudget is the bytes one peer may hold from their reservation until the transmit that carried them returns
// a full budget drains in about codelTarget at 9.7 Gbit/s, the most one peer was measured to carry, so a peer that drains slower is bounded by the delay control and a faster one by the budget
// both see only the delay after the tun read, and a backlog in the tun's own ring is out of their reach
// one sender drains each peer, so the budget does not grow with the cores
const peerDataBudget = 4096 * 1400

// leastPacketBytes is the least a data packet holds of its peer's budget, however few bytes it carries
// so the budget holds at most peerDataBudget / leastPacketBytes batches, which the sender's queue is sized for
// and as many packets, but for one share charged the whole budget and admitted alone, whose fragments can number more
const leastPacketBytes = 1400

// codelTarget is the delay a peer's sender holds its queue to, and codelInterval how long the delay may stay above it before the sender starts dropping
// both are the defaults RFC 8289 gives and the kernel's CoDel uses
// the interval is long enough that one late ticket, which delays every batch behind it at once, drops nothing
const (
	codelTarget   = 5 * time.Millisecond
	codelInterval = 100 * time.Millisecond
)

// transmitBatchSize is the most packets a peer's sender merges into one transmit
// the transport hands its socket at most espSendBatch datagrams per send, so one merge fills one send
const transmitBatchSize = 128

// controlQueueSize is how many control packets one peer may have in flight.
// It has to hold a whole periodic dump, which is one packet per thirty-eight
// plain prefixes or thirty-one source-specific ones, or the dump is truncated
// and the rest waits for the next interval.
//
// A full queue carries fewer prefixes than maxRouteKeys, so a table at its own
// limit still truncates, and because the dump walks maps each one carries a
// different subset: a prefix missed four dumps running expires at the
// neighbor. A table that large needs a dump that resumes where the last one
// stopped, and this one samples afresh each time.
const controlQueueSize = 256

// defaultCloseGrace bounds how long Close waits for the ordered sender.
//
// Closing a Mux does not interrupt a send already in the socket: Mux.Close
// consults its done channel once on entry and then loops on the hub's bind,
// which only Hub.Close closes and which carries no write deadline. Process
// shutdown reaches Hub.Close and so always finishes. One session's teardown,
// a dialer a reload dropped or the loser of a session replacement, leaves
// the hub open, and an unbounded wait there holds the client's peer group for
// as long as the socket stays unwritable, which the next clean shutdown then
// waits behind.
//
// Giving up leaves the sender running. It writes only to the transport and to
// batches it owns, both of which outlive it, so this is a goroutine that
// outlives Close rather than a use after free.
const defaultCloseGrace = 5 * time.Second

// sendErrReportInterval bounds how often a batch the transport refused is said
// out loud. See Peer.sendErrReported.
const sendErrReportInterval = 10 * time.Second

// segmentDropInterval bounds how often a refused segment is reported. A peer
// choosing to send malformed headers should cost this node a counter, not a
// log line per packet.
const segmentDropInterval = 30 * time.Second

// egressPairs is how many source and destination pairs a batch keeps the egress check's answers for, each pair past them looked up again
// a batch carries a few flows, and a search of the kept pairs costs less than the lookup it saves only while they are few
const egressPairs = 8

// the intervals, the burst and the cap of the ICMP error limits are the Linux kernel's defaults, and the bound on the sources held and their shards are this node's own
const (
	// icmpSourceInterval4 and icmpSourceInterval6 are the cost of one answer to a source's bucket, net.ipv4.icmp_ratelimit and net.ipv6.icmp.ratelimit
	icmpSourceInterval4 = time.Second
	icmpSourceInterval6 = 100 * time.Millisecond
	// icmpSourceBurst is the answers a full source's bucket holds, XRLIM_BURST_FACTOR
	icmpSourceBurst = 6
	// icmpSources is the most sources the limit holds a bucket for, 96 in each shard
	// 4096 sources at random put about 64 in a shard with a deviation of 8, and up to about 88 in the fullest of 64
	// so a shard of 96 holds them all, and its first eviction comes near 4800, where a shard of 64 began evicting near 3000
	icmpSources = 6144
	// icmpShards is how many shards the sources lie in, more than the emitters drawing at once so draws for distinct sources rarely wait on one lock
	icmpShards = 64
	// icmpNodeRate and icmpNodeBurst are the cap over every answer, icmp_msgs_per_sec and icmp_msgs_burst
	icmpNodeRate  = 10000
	icmpNodeBurst = 10000
	// icmpNodeCost is the time the cap takes to earn one answer back
	icmpNodeCost = time.Second / icmpNodeRate
)

// linePad is the padding on each side of the ICMP limit's cap and after each of its shards, 128 bytes less the 8 bytes a word is aligned to
// 128 bytes are a cache line of Apple's M-series and the pair of 64-byte lines Intel's adjacent-line prefetcher fetches together
// so neither shares a line with another field on any target, wherever the allocator puts the Mesh, since every draw reads the cap and writes its shard
const linePad = 128 - 8
