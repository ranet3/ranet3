// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// link is the stack's one NIC. A packet the exit delivers enters the stack as
// a packet off a wire, and every packet the stack sends waits in one queue,
// bounded in bytes, for the pump that lays it into a lane.
//
// It claims no receive checksum offload, so gVisor checks each TCP segment's
// checksum itself. It offers segmentation offload, so a TCP flow's segments
// leave as one frame the pump cuts as a tun read is cut.
type link struct {
	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	// icmp and other count what the stack sent that was no TCP segment, which
	// tcpOnly dropped: ICMP and ICMPv6 messages, and anything else
	icmp, other atomic.Uint64

	// limit is the bytes the queue holds at most, and held the bytes it
	// holds now, from a packet's write until the pump releases it
	limit int64
	held  atomic.Int64
	queue chan *stack.PacketBuffer
	// closing is closed by Close, after which the link takes and holds nothing
	closing   chan struct{}
	closeOnce sync.Once
	// dropped counts the packets the stack wrote past the queue's bound
	dropped atomic.Uint64
}

var (
	_ stack.LinkEndpoint = (*link)(nil)
	_ stack.GSOEndpoint  = (*link)(nil)
)

// newLink is a link whose queue holds limit bytes
func newLink(limit int64) *link {
	return &link{limit: limit, queue: make(chan *stack.PacketBuffer, linkQueuePackets), closing: make(chan struct{})}
}

// deliver hands raw, one IP packet, to the stack as a packet off the wire,
// copying it, and reports false where the link is not attached or raw is no
// IP packet
func (l *link) deliver(raw []byte) bool {
	var number tcpip.NetworkProtocolNumber
	switch header.IPVersion(raw) {
	case header.IPv4Version:
		number = header.IPv4ProtocolNumber
	case header.IPv6Version:
		number = header.IPv6ProtocolNumber
	default:
		return false
	}
	l.mu.RLock()
	dispatcher := l.dispatcher
	l.mu.RUnlock()
	if dispatcher == nil {
		return false
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	dispatcher.DeliverNetworkPacket(number, pkt)
	pkt.DecRef()
	return true
}

// WritePackets queues each packet for the pump, and drops and counts one past
// the queue's bound, which it reports as a full device queue does
func (l *link) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n, full := 0, false
	for _, pkt := range pkts.AsSlice() {
		select {
		case <-l.closing:
			if n == 0 {
				return 0, &tcpip.ErrClosedForSend{}
			}
			return n, nil
		default:
		}
		size := int64(pkt.Size())
		if l.held.Add(size) > l.limit {
			l.held.Add(-size)
			l.dropped.Add(1)
			full = true
			continue
		}
		select {
		case l.queue <- pkt.IncRef():
			n++
		default:
			pkt.DecRef()
			l.held.Add(-size)
			l.dropped.Add(1)
			full = true
		}
	}
	if full {
		return n, &tcpip.ErrNoBufferSpace{}
	}
	return n, nil
}

// send queues raw, an IP packet the exit built itself, for the pump within
// the queue's bound, and reports whether it was queued
func (l *link) send(raw []byte) bool {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	n, _ := l.WritePackets(list)
	return n == 1
}

// next is the next packet the stack sent, waiting for one until stop or done
// closes or the link does, and nil then
func (l *link) next(stop, done <-chan struct{}) *stack.PacketBuffer {
	select {
	case pkt := <-l.queue:
		return pkt
	case <-stop:
		return nil
	case <-done:
		return nil
	case <-l.closing:
		return nil
	}
}

// poll is the next packet the stack sent where one is queued, nil otherwise
func (l *link) poll() *stack.PacketBuffer {
	select {
	case pkt := <-l.queue:
		return pkt
	default:
		return nil
	}
}

// release gives back a packet next or poll returned, and its bytes to the
// queue's bound
func (l *link) release(pkt *stack.PacketBuffer) {
	l.held.Add(-int64(pkt.Size()))
	pkt.DecRef()
}

// Close detaches the stack and drops what the queue holds
func (l *link) Close() {
	l.closeOnce.Do(func() {
		close(l.closing)
		l.mu.Lock()
		l.dispatcher = nil
		l.mu.Unlock()
		for {
			select {
			case pkt := <-l.queue:
				l.release(pkt)
			default:
				return
			}
		}
	})
}

func (l *link) Attach(dispatcher stack.NetworkDispatcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dispatcher = dispatcher
}

func (l *link) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dispatcher != nil
}

// Capabilities claims no offload: the stack checks what it receives and
// computes what it sends, but for a segmentation offload frame's segments,
// whose checksums the pump's cut computes
func (*link) Capabilities() stack.LinkEndpointCapabilities { return 0 }

func (*link) MTU() uint32                             { return linkMTU }
func (*link) SetMTU(uint32)                           {}
func (*link) GSOMaxSize() uint32                      { return linkGSOMaxSize }
func (*link) SupportedGSO() stack.SupportedGSO        { return stack.HostGSOSupported }
func (*link) MaxHeaderLength() uint16                 { return 0 }
func (*link) LinkAddress() tcpip.LinkAddress          { return "" }
func (*link) SetLinkAddress(tcpip.LinkAddress)        {}
func (*link) Wait()                                   {}
func (*link) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*link) AddHeader(*stack.PacketBuffer)           {}
func (*link) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (*link) SetOnCloseAction(func())                 {}

// tcpOnly is the link as the stack writes to it, which queues the stack's TCP
// segments and drops and counts anything else the stack sends. The stack ends
// each leaf's TCP connection as the destination the leaf named, so anything
// else it sends goes as a destination that never sent it: a Parameter Problem
// for IPv4 options or an IPv6 option it refuses, a Neighbor Advertisement for
// a solicitation behind a destination options header, a Time Exceeded for a
// reassembly that timed out. What the exit sends itself goes through
// link.send, which this leaves alone.
type tcpOnly struct{ *link }

// WritePackets queues pkts' TCP segments and drops and counts the rest,
// reporting those dropped among the written, as a NIC that sent them would
func (t tcpOnly) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	all := pkts.AsSlice()
	dropped := 0
	for _, pkt := range all {
		switch transportOf(pkt) {
		case header.TCPProtocolNumber:
		case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
			t.icmp.Add(1)
			dropped++
		default:
			t.other.Add(1)
			dropped++
		}
	}
	if dropped == 0 {
		return t.link.WritePackets(pkts)
	}
	var segments stack.PacketBufferList
	for _, pkt := range all {
		if transportOf(pkt) == header.TCPProtocolNumber {
			segments.PushBack(pkt)
		}
	}
	n, err := t.link.WritePackets(segments)
	return n + dropped, err
}

// transportOf is the protocol pkt, a packet the stack sends, carries as its
// network header names it, IPv6's first next header, since the stack puts no
// extension header before a TCP segment, and zero where it has no network
// header of either family
func transportOf(pkt *stack.PacketBuffer) tcpip.TransportProtocolNumber {
	network := pkt.NetworkHeader().Slice()
	switch {
	case len(network) >= header.IPv4MinimumSize && header.IPVersion(network) == header.IPv4Version:
		return tcpip.TransportProtocolNumber(header.IPv4(network).Protocol())
	case len(network) >= header.IPv6MinimumSize && header.IPVersion(network) == header.IPv6Version:
		return tcpip.TransportProtocolNumber(header.IPv6(network).NextHeader())
	}
	return 0
}
