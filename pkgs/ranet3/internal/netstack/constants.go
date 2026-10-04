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
	// inboundPacketBufferSize leaves enough tail capacity for the TUN
	// backend to merge adjacent TCP packets into a single GSO frame before
	// writing it. Exact-capacity packet buffers silently disable that GRO.
	inboundPacketBufferSize = tunOffset + 65535
	// outboundJobsPerWorker is the read batches queued for each crypto worker
	// one waits while the worker encrypts another
	outboundJobsPerWorker = 2
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
