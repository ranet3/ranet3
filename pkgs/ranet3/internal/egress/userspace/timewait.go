// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"slices"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// timeWait frees a leaf-side endpoint in TIME_WAIT for a new connection on
// its four-tuple, which the stack reflects to no forwarder. A lane records
// each leaf flow's FIN as it passes, and on a bare SYN aborts the endpoint
// where it waits in TIME_WAIT and the SYN's sequence number comes after the
// FIN's plus one, as reuses judges it, before the SYN is delivered. Every
// packet of one four-tuple passes one lane, so the FIN is recorded before the
// SYN that reuses its ports is judged.
type timeWait struct {
	mu sync.Mutex
	// fins holds each flow's FIN sequence number, the oldest dropped past
	// limit, in the order order keeps
	fins  map[stack.TransportEndpointID]uint32
	order []stack.TransportEndpointID
	limit int
}

func newTimeWait(limit int) *timeWait {
	return &timeWait{fins: map[stack.TransportEndpointID]uint32{}, limit: limit}
}

// segment is the four-tuple, flags and sequence numbers of raw, a TCP
// segment in an unfragmented packet with no IPv6 extension header, and false
// for any other packet
func segment(raw []byte) (id stack.TransportEndpointID, network tcpip.NetworkProtocolNumber, flags header.TCPFlags, seq, fin uint32, ok bool) {
	var body []byte
	switch {
	case len(raw) >= header.IPv4MinimumSize && raw[0]>>4 == 4:
		ihl := int(raw[0]&0x0f) * 4
		if raw[9] != 6 || binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 || len(raw) < ihl {
			return id, 0, 0, 0, 0, false
		}
		id.RemoteAddress, id.LocalAddress = tcpip.AddrFrom4([4]byte(raw[12:16])), tcpip.AddrFrom4([4]byte(raw[16:20]))
		network, body = header.IPv4ProtocolNumber, raw[ihl:]
	case len(raw) >= header.IPv6MinimumSize && raw[0]>>4 == 6:
		if raw[6] != 6 {
			return id, 0, 0, 0, 0, false
		}
		id.RemoteAddress, id.LocalAddress = tcpip.AddrFrom16([16]byte(raw[8:24])), tcpip.AddrFrom16([16]byte(raw[24:40]))
		network, body = header.IPv6ProtocolNumber, raw[40:]
	default:
		return id, 0, 0, 0, 0, false
	}
	if len(body) < header.TCPMinimumSize || len(body) < int(body[12]>>4)*4 {
		return id, 0, 0, 0, 0, false
	}
	tcp := header.TCP(body)
	id.RemotePort, id.LocalPort = tcp.SourcePort(), tcp.DestinationPort()
	seq = tcp.SequenceNumber()
	return id, network, tcp.Flags(), seq, seq + uint32(len(body)-int(tcp.DataOffset())), true
}

// see runs on the lane goroutine before raw reaches the stack: it records a
// leaf's FIN, and for a bare SYN aborts the endpoint its four-tuple waits in
// TIME_WAIT on where the SYN opens a new incarnation, reporting whether it did
func (w *timeWait) see(s *stack.Stack, raw []byte) bool {
	id, network, flags, seq, fin, ok := segment(raw)
	switch {
	case !ok:
		return false
	case flags&header.TCPFlagFin != 0:
		w.record(id, fin)
		return false
	case flags&(header.TCPFlagSyn|header.TCPFlagAck|header.TCPFlagRst) != header.TCPFlagSyn:
		return false
	}
	w.mu.Lock()
	last, recorded := w.fins[id]
	w.mu.Unlock()
	if !recorded || !reuses(last, seq) {
		return false
	}
	ep, isTCP := s.FindTransportEndpoint(network, tcp.ProtocolNumber, id, nicID).(*tcp.Endpoint)
	if !isTCP || ep.EndpointState() != tcp.StateTimeWait {
		return false
	}
	ep.Abort()
	return true
}

// record keeps fin as id's FIN, the oldest record dropped past the limit
func (w *timeWait) record(id stack.TransportEndpointID, fin uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.fins[id]; !ok {
		w.order = append(w.order, id)
	}
	w.fins[id] = fin
	for len(w.order) > w.limit {
		delete(w.fins, w.order[0])
		w.order = w.order[1:]
	}
}

// reuses is the remote-sequence rule gVisor's TIME_WAIT applies to a SYN
// that reopens its connection (RcvNxt < segSeq): the leaf's SYN after
// RCV.NXT, its FIN's plus one, in sequence space. It checks nothing of the
// ISN the stack gives the new connection, which RFC 1122 section 4.2.2.13's
// condition (1) asks of.
func reuses(fin, syn uint32) bool { return int32(syn-(fin+1)) > 0 }

// closedEndpoints holds the leaf-side endpoints the exit closed, oldest
// first, until the stack frees them, aborting the oldest past limit, so the
// endpoints in TIME_WAIT never number more than limit
type closedEndpoints struct {
	mu    sync.Mutex
	queue []*tcp.Endpoint
	limit int
}

// add holds ep, which the exit just closed, and reports the endpoints it
// aborted to stay within the limit
func (c *closedEndpoints) add(ep *tcp.Endpoint) int {
	c.mu.Lock()
	c.queue = append(c.queue, ep)
	if len(c.queue) > c.limit {
		c.queue = slices.DeleteFunc(c.queue, freed)
	}
	var aborted []*tcp.Endpoint
	if over := len(c.queue) - c.limit; over > 0 {
		aborted = slices.Clone(c.queue[:over])
		c.queue = slices.Delete(c.queue, 0, over)
	}
	c.mu.Unlock()
	for _, ep := range aborted {
		ep.Abort()
	}
	return len(aborted)
}

// freed is an endpoint the stack holds no more
func freed(ep *tcp.Endpoint) bool {
	switch ep.EndpointState() {
	case tcp.StateClose, tcp.StateError:
		return true
	}
	return false
}
