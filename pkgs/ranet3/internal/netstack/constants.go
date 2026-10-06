// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import "time"

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

const (
	// outboundPacketBufferSize is the least bytes an outbound read buffer holds past tunOffset
	// a device the mesh attaches to keeps its own MTU, which can be larger than the one asked for
	outboundPacketBufferSize = 2048
	// inboundWriteBatchSize is the most packets one tun write carries
	// wireguard-go's tun write sizes its GRO tables for that many
	inboundWriteBatchSize = 128
	// inboundWriteQueueSize is the batches one inbound writer lane queues before a delivery to it waits
	// a busy writer merges the ones ready into its next tun write
	inboundWriteQueueSize = 64
	// inboundPendingBatches is how many write batches a lane's pending list holds before it grows
	// collectReadyInbound stops once one batch is pending, and the second leaves room for the entry that crossed it
	inboundPendingBatches = 2
	// inboundPacketBufferSize leaves enough tail capacity for the TUN
	// backend to merge adjacent TCP packets into a single GSO frame before
	// writing it. Exact-capacity packet buffers silently disable that GRO.
	inboundPacketBufferSize = tunOffset + 65535
	// outboundJobsPerWorker is the read batches queued for each crypto worker
	// one waits while the worker encrypts another
	outboundJobsPerWorker = 2
	// utunName asks darwin's utun control for its next free unit
	// followed by a unit number it asks for that unit
	// the control creates no other name
	utunName = "utun"
)

// tunOffset is how much leading space every Device.Read and Device.Write
// needs in each buffer, the same offset wireguard-go's own device code uses
// (device.MessageTransportOffsetContent), and for the same reasons. A backend
// slices backwards from it to reach its own framing: linux prepends a
// virtio-net header (the tun package always requests IFF_VNET_HDR), darwin
// prepends the four-byte address family header a utun frame carries. Offset 0
// doesn't just lose performance, it fails outright, and on darwin it fails
// before the first packet arrives: tun_darwin.go's Read evaluates
// bufs[0][offset-4:] on entry, so offset 0 panics the reader goroutine and
// takes the process down with it.
//
// The contract on the way back is that a read leaves packet i at
// bufs[i][tunOffset : tunOffset+sizes[i]], which is where linux puts each
// packet it splits out of one GRO'd read as well.
const tunOffset = 16

// truncatedReadInterval is the least time between two warnings about tun reads cut short
// the counter keeps the exact count, and the line only has to point at it
const truncatedReadInterval = 30 * time.Second

// peerDataBudget is the packets one peer may hold from their reservation until the transmit that carried them returns
// 5.7 MB of 1400-byte packets, which last 4.7 milliseconds at 9.7 Gbit/s and 15 milliseconds at 3 Gbit/s
// their sealed storage stays under twice that, about 12 MB, since a batch reuses only storage grown by at most twice its packets
// one sender drains each peer, so the budget does not grow with the cores
const peerDataBudget = 4096

// transmitBatchSize is the most packets a peer's sender merges into one transmit
// the transport hands its socket at most espSendBatch datagrams per send, so one merge fills one send
const transmitBatchSize = 128

// controlQueueSize is how many control packets one peer may have in flight.
// It has to hold a whole periodic dump, which is one packet per forty plain
// prefixes or thirty-four source-specific ones, or the dump is truncated and
// the rest waits for the next interval. Two hundred and fifty-six covers about
// ten thousand plain prefixes and costs under a megabyte per peer at the link
// MTU, counting the packet and the sealer's copy of it.
//
// That is below maxRouteKeys, so a table at its own limit still truncates, and
// because the dump walks maps each one carries a different subset: a prefix
// missed four dumps running expires at the neighbor. A table that large needs
// the dump to resume where the last one stopped rather than resample, which is
// not what this does.
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

// icmpBurst and icmpRefill bound the ICMP errors this node answers refused
// packets with. A traceroute sends three probes per hop, so the burst carries
// two hops' worth without waiting, and the refill bounds what a peer sending
// refused headers in a loop gets out of this node.
const (
	icmpBurst  = 8
	icmpRefill = 250 * time.Millisecond
)
