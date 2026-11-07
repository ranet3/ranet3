// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// stackWait bounds every wait for the stack, whose forwarder answers a
	// SYN on a goroutine of its own
	stackWait = 2 * time.Second
	// stackSettle is how long a test watches the link for anything more
	// once what it waited for has come
	stackSettle = 200 * time.Millisecond
	// stackWindow is the tests' TCP buffer
	stackWindow = 64 << 10
)

// stackHarness is a stack as newStack builds it, with what its default
// handlers took and what it sent
type stackHarness struct {
	stack *stack.Stack
	link  *link
	mu    sync.Mutex
	// icmp is each message the ICMP handler took, udp each datagram the UDP
	// handler took
	icmp, udp []sent
	// written is every packet the stack sent so far, in order
	written []sent
}

func newStackHarness(t *testing.T) *stackHarness {
	t.Helper()
	return newStackHarnessOn(t, nil)
}

// newStackHarnessOn is a stack harness on clock, the host's where nil
func newStackHarnessOn(t *testing.T, clock tcpip.Clock) *stackHarness {
	t.Helper()
	h := &stackHarness{link: newLink(1 << 20)}
	// on the host's clock the stack is built as the exit builds it
	build := newStack
	if clock != nil {
		build = func(l *link, window int, handlers stackHandlers) (*stack.Stack, error) {
			return newStackOn(clock, l, window, handlers)
		}
	}
	s, err := build(h.link, stackWindow, stackHandlers{
		udp:  func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) { h.took(&h.udp, protoUDP, id, pkt) },
		icmp: func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) { h.took(&h.icmp, 0, id, pkt) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.stack = s
	t.Cleanup(func() {
		h.link.Close()
		s.Close()
		s.Wait()
	})
	return h
}

// took records a packet a default handler took, from the handler's id and the
// first bytes of its transport message
func (h *stackHarness) took(into *[]sent, protocol byte, id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	message := append(bytes.Clone(pkt.TransportHeader().Slice()), pkt.Data().AsRange().ToSlice()...)
	p := sent{src: addrOf(id.RemoteAddress), dst: addrOf(id.LocalAddress), protocol: protocol, payload: len(message)}
	if protocol == 0 && len(message) >= 2 {
		p.protocol, p.kind, p.code = icmpProtocol(p.src), message[0], message[1]
	}
	h.mu.Lock()
	*into = append(*into, p)
	h.mu.Unlock()
}

// inject hands the stack each packet as the exit's lanes do
func (h *stackHarness) inject(t *testing.T, packets ...[]byte) {
	t.Helper()
	for _, raw := range packets {
		if !h.link.deliver(raw) {
			t.Fatalf("the link refused a packet of %d bytes", len(raw))
		}
	}
}

// drain reads every packet the link holds into written
func (h *stackHarness) drain() {
	for pkt := h.link.poll(); pkt != nil; pkt = h.link.poll() {
		view := pkt.ToView()
		p, ok := parse(view.AsSlice())
		view.Release()
		h.link.release(pkt)
		if !ok {
			p = sent{protocol: 255}
		}
		h.mu.Lock()
		h.written = append(h.written, p)
		h.mu.Unlock()
	}
}

// waitSent waits for a packet the stack sent that match picks, and reports it
func (h *stackHarness) waitSent(t *testing.T, what string, match func(sent) bool) sent {
	t.Helper()
	deadline := time.Now().Add(stackWait)
	for {
		h.drain()
		h.mu.Lock()
		for _, p := range h.written {
			if match(p) {
				h.mu.Unlock()
				return p
			}
		}
		h.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("the stack sent no %s within %s, only %v", what, stackWait, h.sentSoFar())
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *stackHarness) sentSoFar() []sent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sent(nil), h.written...)
}

func (h *stackHarness) icmpTaken() []sent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sent(nil), h.icmp...)
}

// forward has every SYN reach an endpoint the test receives, as the exit's
// forwarder hands one to its dial
func (h *stackHarness) forward() <-chan tcpip.Endpoint {
	endpoints := make(chan tcpip.Endpoint, 4)
	forwarder := tcp.NewForwarder(h.stack, 0, 16, func(r *tcp.ForwarderRequest) {
		var queue waiter.Queue
		ep, err := r.CreateEndpoint(&queue)
		r.Complete(err != nil)
		if err == nil {
			endpoints <- ep
		}
	})
	h.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	return endpoints
}

// open runs a TCP flow from leaf to server through the stack, the handshake
// and then data both ways, and leaves it established
func (h *stackHarness) open(t *testing.T, endpoints <-chan tcpip.Endpoint, leaf, server netip.AddrPort) tcpip.Endpoint {
	t.Helper()
	h.inject(t, tcpSegment(leaf, server, 1000, 0, tcpSYN, nil))
	synAck := h.waitSent(t, "syn-ack", func(p sent) bool {
		return p.protocol == protoTCP && p.flags == tcpSYN|tcpACK && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	ack := synAck.seq + 1
	h.inject(t, tcpSegment(leaf, server, 1001, ack, tcpACK, nil))
	var ep tcpip.Endpoint
	select {
	case ep = <-endpoints:
	case <-time.After(stackWait):
		t.Fatalf("no endpoint for %s > %s within %s", leaf, server, stackWait)
	}
	t.Cleanup(ep.Abort)
	if _, err := ep.Write(bytes.NewReader(bytes.Repeat([]byte{'x'}, 100)), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("the endpoint's write: %s", err)
	}
	h.waitSent(t, "data toward the leaf", func(p sent) bool {
		return p.protocol == protoTCP && p.payload > 0 && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	h.inject(t, tcpSegment(leaf, server, 1001, ack+100, tcpACK|tcpPSH, bytes.Repeat([]byte{'y'}, 50)))
	deadline := time.Now().Add(stackWait)
	for {
		var read bytes.Buffer
		result, err := ep.Read(&read, tcpip.ReadOptions{})
		if err == nil && result.Count == 50 {
			return ep
		}
		if time.Now().After(deadline) {
			t.Fatalf("the endpoint read %d bytes of the leaf's 50 within %s (%v)", result.Count, stackWait, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// The stack answers no echo for any destination, whole or fragmented, with a
// TCP flow open to it or not, and as a destination sends only the flow's own
// segments and a reset to a segment no endpoint holds, never the protocol
// unreachable a packet of an uncarried protocol may draw, which the lane
// exists to keep from the stack. Every echo reaches the ICMP handler once.
func TestStackAnswersNoEchoAndSendsOnlyTCP(t *testing.T) {
	for _, family := range []struct {
		name                string
		leaf, server, other netip.Addr
	}{
		{"ipv4", leaf4, server4, other4},
		{"ipv6", leaf6, server6, other6},
	} {
		t.Run(family.name, func(t *testing.T) {
			h := newStackHarness(t)
			endpoints := h.forward()
			leaf, server := netip.AddrPortFrom(family.leaf, 40000), netip.AddrPortFrom(family.server, 80)
			h.open(t, endpoints, leaf, server)

			protocol := icmpProtocol(family.leaf)
			echoes := 0
			for _, destination := range []netip.Addr{family.server, family.other} {
				for i, size := range []int{64, 3000} {
					echoes++
					id := uint16(0x100 + echoes)
					message := echoRequest(family.leaf, destination, id, uint16(i), bytes.Repeat([]byte{byte(echoes)}, size))
					if size > 1200 {
						h.inject(t, fragments(family.leaf, destination, protocol, id, message, 1200)...)
					} else {
						h.inject(t, ipPacket(family.leaf, destination, protocol, message))
					}
				}
			}
			unheld := netip.AddrPortFrom(family.leaf, 41000)
			h.inject(t, tcpSegment(unheld, netip.AddrPortFrom(family.server, 81), 5000, 1, tcpACK, nil))
			h.inject(t, ipPacket(family.leaf, family.server, protoUncarried, make([]byte, 8)))

			h.waitSent(t, "reset to the segment no endpoint holds", func(p sent) bool {
				return p.protocol == protoTCP && p.flags&tcpRST != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == unheld
			})
			time.Sleep(stackSettle)
			h.drain()

			for _, p := range h.sentSoFar() {
				t.Logf("sent: %s", p)
				switch {
				case p.protocol == protoTCP && netip.AddrPortFrom(p.src, p.srcPort) == server && netip.AddrPortFrom(p.dst, p.dstPort) == leaf:
				case p.protocol == protoTCP && p.flags&tcpRST != 0 && p.srcPort == 81 && netip.AddrPortFrom(p.dst, p.dstPort) == unheld:
				default:
					t.Errorf("the stack sent %s, which no flow and no unheld segment asks for", p)
				}
			}
			t.Logf("ICMP messages the stack sent, dropped: %d", h.link.icmp.Load())

			taken := 0
			for _, p := range h.icmpTaken() {
				t.Logf("taken by the icmp handler: %s", p)
				if p.kind == 8 || p.kind == 128 {
					taken++
				}
			}
			if taken != echoes {
				t.Errorf("the icmp handler took %d echo requests of the %d sent", taken, echoes)
			}
		})
	}
}

// Toward a leaf the stack sends only TCP. What else it would send as the
// destination a leaf's packet named is dropped and counted as ICMP, once for
// each trigger, once the timers the stack runs of itself have run: a
// Parameter Problem for a SYN whose IPv4 options repeat a router alert, and
// for one behind a destination option of action 10, a Neighbor Advertisement
// for a solicitation behind a destination options header, and a Time Exceeded
// in each family for a reassembly whose first fragment came and timed out on
// the stack's clock. A SYN no endpoint holds still draws its reset.
func TestStackSendsTowardALeafOnlyTCP(t *testing.T) {
	clock := faketime.NewManualClock()
	h := newStackHarnessOn(t, clock)
	clock.Advance(ipv6.ReassembleTimeout)
	h.drain()
	before := h.link.icmp.Load()
	from4, from6 := netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(leaf6, 40000)
	syn4 := tcpSegment(from4, netip.AddrPortFrom(server4, 80), 1000, 0, tcpSYN, nil)
	syn6 := tcpSegment(from6, netip.AddrPortFrom(server6, 80), 1000, 0, tcpSYN, nil)
	routerAlert := []byte{0x94, 4, 0, 0}
	refused := []byte{protoTCP, 0, 0x80, 4, 0, 0, 0, 0}
	padded := []byte{protoICMPv6, 0, 1, 4, 0, 0, 0, 0}
	// a first fragment's transport header is never read before reassembly
	datagram := make([]byte, 8+3000)
	triggers := [][]byte{
		ip4Options(leaf4, server4, protoTCP, append(slices.Clone(routerAlert), routerAlert...), syn4[20:]),
		ip6(leaf6, server6, ipv6DestinationOptions, 64, append(refused, syn6[40:]...)),
		ip6(leaf6, server6, ipv6DestinationOptions, 255, append(padded, neighborSolicitation(leaf6, server6, server6)...)),
		fragments(leaf4, server4, protoUDP, 7, datagram, 1200)[0],
		fragments(leaf6, server6, protoUDP, 7, datagram, 1200)[0],
	}
	h.inject(t, triggers...)
	clock.Advance(ipv6.ReassembleTimeout + time.Second)
	unheld := netip.AddrPortFrom(leaf4, 40001)
	h.inject(t, tcpSegment(unheld, netip.AddrPortFrom(server4, 81), 1000, 0, tcpSYN, nil))
	h.waitSent(t, "reset to the SYN no endpoint holds", func(p sent) bool {
		return p.protocol == protoTCP && p.flags&tcpRST != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == unheld
	})
	deadline := time.Now().Add(stackWait)
	for h.link.icmp.Load()-before < uint64(len(triggers)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(stackSettle)
	h.drain()
	for _, p := range h.sentSoFar() {
		if p.protocol != protoTCP {
			t.Errorf("the stack sent %s toward a leaf", p)
		}
	}
	if counted := h.link.icmp.Load() - before; counted != uint64(len(triggers)) || h.link.other.Load() != 0 {
		t.Errorf("counted %d ICMP messages the stack sent and %d other packets, want one ICMP message for each of the %d triggers", counted, h.link.other.Load(), len(triggers))
	}
}

// ip4Options is an IPv4 packet whose header carries options, its checksum set
func ip4Options(src, dst netip.Addr, protocol byte, options, payload []byte) []byte {
	b := append(ip4(src, dst, protocol, 1, 0, 64, nil), options...)
	b[0] = 4<<4 | byte(len(b)/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+len(payload)))
	binary.BigEndian.PutUint16(b[10:12], 0)
	binary.BigEndian.PutUint16(b[10:12], fold(sum(0, b)))
	return append(b, payload...)
}

// neighborSolicitation is an ICMPv6 Neighbor Solicitation from src to dst for
// target, its checksum set, unwrapped
func neighborSolicitation(src, dst, target netip.Addr) []byte {
	b := make([]byte, 24)
	b[0] = 135
	copy(b[8:], target.AsSlice())
	binary.BigEndian.PutUint16(b[2:4], fold(sum(pseudo(src, dst, protoICMPv6, len(b)), b)))
	return b
}

// The link claims no receive checksum offload, so gVisor checks a TCP
// segment's checksum: a SYN whose checksum fails draws nothing and reaches no
// forwarder, and the same SYN whole draws a SYN-ACK
func TestStackDropsTCPSegmentWithBadChecksum(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{
		{"ipv4", leaf4, server4},
		{"ipv6", leaf6, server6},
	} {
		t.Run(family.name, func(t *testing.T) {
			h := newStackHarness(t)
			if capabilities := h.link.Capabilities(); capabilities&stack.CapabilityRXChecksumOffload != 0 {
				t.Errorf("the link claims receive checksum offload, capabilities %#x", capabilities)
			}
			endpoints := h.forward()
			leaf, server := netip.AddrPortFrom(family.leaf, 40000), netip.AddrPortFrom(family.server, 80)
			bad := tcpSegment(leaf, server, 1000, 0, tcpSYN, nil)
			bad[len(bad)-4] ^= 0x5a
			h.inject(t, bad)
			time.Sleep(stackSettle)
			h.drain()
			if written := h.sentSoFar(); len(written) != 0 {
				t.Errorf("a SYN whose checksum fails drew %v", written)
			}
			select {
			case <-endpoints:
				t.Error("a SYN whose checksum fails reached the forwarder")
			default:
			}
			h.inject(t, tcpSegment(leaf, server, 1000, 0, tcpSYN, nil))
			h.waitSent(t, "syn-ack to the whole SYN", func(p sent) bool {
				return p.protocol == protoTCP && p.flags == tcpSYN|tcpACK && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
			})
		})
	}
}
