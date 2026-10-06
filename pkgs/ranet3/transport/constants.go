// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import "time"

const (
	// readBufferSize is the bytes of one receive buffer
	// the largest UDP datagram fits, and so does a GRO read, which the kernel keeps under 64 KiB
	readBufferSize = 65536
	// espSendBatch is the most datagrams one send call writes and one receive call reads
	// a tun read returns at most that many packets, wireguard-go's conn.IdealBatchSize
	espSendBatch = 128
	// espChanSize is the batches one mux's ESP receive queue holds, which absorbs a burst before the session's workers drain it
	// a batch is one datagram on darwin, whose backend reads one at a time
	// a half-open SA carries the queue while its handshake runs, 40 KiB at this size
	espChanSize = 1024
	// espQueueBytes is the bytes one mux's ESP receive queue holds, the bound that holds it
	// espChanSize batches of the largest datagrams would be 8.6 GB
	// the queue fills before anything is authenticated, from an SPI anyone who saw one packet can aim at it
	espQueueBytes = 8 << 20
	// ikeQueueSize is the IKE datagrams one mux queues for its session
	// IKE keeps one request in flight each way, so a few hold a burst of retransmissions and answers
	ikeQueueSize = 16
	// unclaimedQueueSize is the IKE datagrams no mux claimed that wait for the responder
	// a full queue refuses the next one, which costs its sender a retransmission
	unclaimedQueueSize = 64
	// dropReportInterval is the least time between two log lines about a full receive queue
	// the counter keeps the exact count, and the line only has to point at it
	dropReportInterval = 10 * time.Second
	// socketBufferSize is the bytes asked for as each socket's send and receive buffer
	// the most a default macOS takes, the size wireguard-go asks for, which linux grants past its mem_max sysctls only with CAP_NET_ADMIN
	socketBufferSize = 7 << 20
	// ephemeralPortRetries is how many ports a hub asked for any port tries
	// the port the IPv4 bind gets may be taken for IPv6, and each try draws another
	ephemeralPortRetries = 10
	// linkSettle is how long a hub waits for a burst of routing changes to end before it moves its socket
	// a link coming up is several messages, and answering the first costs a rebind the last would redo
	linkSettle = 250 * time.Millisecond
)
