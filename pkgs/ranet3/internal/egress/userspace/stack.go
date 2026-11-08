// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// stackHandlers is where the stack hands the exit what reaches no endpoint of
// its own, each of them called with every such packet, reassembled where it
// came in fragments
type stackHandlers struct {
	// udp takes every UDP datagram, its checksum unchecked by gVisor, so the
	// stack answers none with a port unreachable
	udp func(stack.TransportEndpointID, *stack.PacketBuffer)
	// icmp takes every ICMP and ICMPv6 message the stack hands its ICMP
	// transport, an echo request among them, so the stack answers no echo for
	// any destination. gVisor hands it an IPv4 message whose checksum fails.
	icmp func(stack.TransportEndpointID, *stack.PacketBuffer)
}

// newStack is the stack the exit ends each leaf's TCP connection in: TCP,
// UDP, ICMP and ICMPv6, one NIC on l that passes only the TCP segments the
// stack sends, promiscuous and spoofing so a flow runs whole from the
// destination it was sent to while the stack holds no address, and a default
// route of each family to it. Each TCP buffer starts at window and grows no
// larger. handlers takes what reaches no endpoint.
func newStack(l *link, window int, handlers stackHandlers) (*stack.Stack, error) {
	return newStackOn(nil, l, window, handlers)
}

// newStackOn is newStack on clock, the host's where nil, which a test moves
// to run the stack's timers
func newStackOn(clock tcpip.Clock, l *link, window int, handlers stackHandlers) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		Clock:              clock,
	})
	fail := func(what string, err tcpip.Error) (*stack.Stack, error) {
		s.Close()
		s.Wait()
		return nil, fmt.Errorf("userspace: the stack's %s: %s", what, err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail("selective acknowledgment", err)
	}
	received := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: window, Max: window}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &received); err != nil {
		return fail("receive buffer", err)
	}
	sent := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: window, Max: window}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sent); err != nil {
		return fail("send buffer", err)
	}
	if err := s.CreateNIC(nicID, tcpOnly{l}); err != nil {
		return fail("nic", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fail("promiscuous mode", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fail("spoofing", err)
	}
	every4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	every6, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	s.SetRouteTable([]tcpip.Route{{Destination: every4, NIC: nicID}, {Destination: every6, NIC: nicID}})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, taking(handlers.udp))
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, taking(handlers.icmp))
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, taking(handlers.icmp))
	return s, nil
}

// taking is a default handler that hands handle every packet and reports each
// one taken, so the stack sends nothing about it
func taking(handle func(stack.TransportEndpointID, *stack.PacketBuffer)) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		handle(id, pkt)
		return true
	}
}

// reassembled is pkt, a packet the stack hands a default handler, one the lane
// passed in fragments or behind an IPv6 extension header and the stack
// reassembled or parsed, written again as one packet of protocol with no
// fragment or extension header, false where its network header is of neither
// family
func reassembled(pkt *stack.PacketBuffer, protocol byte) ([]byte, bool) {
	network := pkt.NetworkHeader().Slice()
	transport := pkt.TransportHeader().Slice()
	data := pkt.Data().AsRange().ToSlice()
	var raw []byte
	switch {
	case len(network) >= 20 && network[0]>>4 == 4:
		header := int(network[0]&0x0f) * 4
		raw = append(append([]byte(nil), network[:header]...), transport...)
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)+len(data)))
		raw[6] &= 0x40
		raw[7] = 0
		binary.BigEndian.PutUint16(raw[10:12], 0)
		binary.BigEndian.PutUint16(raw[10:12], ^uint16(packet.Sum(0, raw[:header])))
	case len(network) >= 40 && network[0]>>4 == 6:
		raw = append(append([]byte(nil), network[:40]...), transport...)
		raw[6] = protocol
		binary.BigEndian.PutUint16(raw[4:6], uint16(len(transport)+len(data)))
	default:
		return nil, false
	}
	return append(raw, data...), true
}

// addrOf is a stack's address as the rest of the node writes it
func addrOf(address tcpip.Address) netip.Addr {
	switch address.Len() {
	case 4:
		return netip.AddrFrom4(address.As4())
	case 16:
		return netip.AddrFrom16(address.As16()).Unmap()
	}
	return netip.Addr{}
}
