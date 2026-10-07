// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const defaultPathMTU = 1500

// fakeKernel answers sendmmsg as linux does from the addresses, interfaces and path MTUs it holds
type fakeKernel struct {
	mu sync.Mutex
	// local maps each address the host holds to its interface
	local   map[netip.Addr]int
	links   map[int]bool
	pathMTU map[netip.Addr]int
	// gsoErrno is EINVAL or EMSGSIZE by kernel version, or EIO from a device that cannot segment
	gsoErrno unix.Errno
	// pinnedErrno refuses every pinned message where it is set
	pinnedErrno unix.Errno
	// once refuses the next message where it is set, as a route rewritten between two sends does
	once  unix.Errno
	sent  []sentDatagram
	tried []triedMessage
	// together, where set, holds the first two writes until both have arrived
	// so two sends have both read their endpoint before either falls back
	together *sync.WaitGroup
	arrived  atomic.Int32
	// releasing, where valid, goes once releaseAfter more messages have been handed over
	// as an address that expires while a send is under way does
	// releasedAt is how many datagrams had gone out when it went
	releasing    netip.Addr
	releaseAfter int
	releasedAt   int
}

type sentDatagram struct {
	to                netip.AddrPort
	from              netip.Addr
	pinned, segmented bool
	payload           []byte
}

type triedMessage struct {
	to      netip.AddrPort
	pinned  bool
	segment int
	errno   unix.Errno
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{local: map[netip.Addr]int{}, links: map[int]bool{}, pathMTU: map[netip.Addr]int{}, gsoErrno: unix.EINVAL}
}

func (k *fakeKernel) hold(address string, index int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.local[netip.MustParseAddr(address)] = index
	k.links[index] = true
}

func (k *fakeKernel) release(address string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.local, netip.MustParseAddr(address))
}

func (k *fakeKernel) unplug(index int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.links, index)
	for address, on := range k.local {
		if on == index {
			delete(k.local, address)
		}
	}
}

func (k *fakeKernel) datagrams() []sentDatagram {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.sent)
}

func (k *fakeKernel) messages() []triedMessage {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.tried)
}

// choose stands in for the kernel's source selection with the lowest address of the family
func (k *fakeKernel) choose(ipv4 bool) (netip.Addr, bool) {
	var chosen netip.Addr
	for address := range k.local {
		if address.Is4() == ipv4 && (!chosen.IsValid() || address.Less(chosen)) {
			chosen = address
		}
	}
	return chosen, chosen.IsValid()
}

// write answers as sendmmsg does, -1 when the first message is refused and a short count when a later one is
func (k *fakeKernel) write(messages []ipv4.Message) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range messages {
		if k.releasing.IsValid() {
			if k.releaseAfter == 0 {
				delete(k.local, k.releasing)
				k.releasing, k.releasedAt = netip.Addr{}, len(k.sent)
			}
			k.releaseAfter--
		}
		if errno := k.deliver(&messages[i]); errno != 0 {
			if i == 0 {
				return -1, os.NewSyscallError("sendmmsg", errno)
			}
			return i, nil
		}
	}
	return len(messages), nil
}

// deliver records the datagrams of a message route lets through
func (k *fakeKernel) deliver(m *ipv4.Message) unix.Errno {
	to := m.Addr.(*net.UDPAddr).AddrPort()
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	source, index, pinned, segment := parseSendControl(m.OOB)
	tried := triedMessage{to: to, pinned: pinned, segment: segment}
	errno := k.route(to.Addr(), source, index, pinned, segment)
	if k.once != 0 {
		errno, k.once = k.once, 0
	}
	tried.errno = errno
	k.tried = append(k.tried, tried)
	if errno != 0 {
		return errno
	}
	from := source
	if !pinned {
		from, _ = k.choose(to.Addr().Is4())
	}
	payload := m.Buffers[0]
	if segment == 0 {
		segment = max(len(payload), 1)
	}
	for offset := 0; offset < len(payload) || offset == 0; offset += segment {
		end := min(offset+segment, len(payload))
		k.sent = append(k.sent, sentDatagram{to: to, from: from, pinned: pinned, segmented: tried.segment > 0,
			payload: slices.Clone(payload[offset:end])})
		if end == len(payload) {
			break
		}
	}
	return 0
}

func (k *fakeKernel) route(to, source netip.Addr, index int, pinned bool, segment int) unix.Errno {
	if pinned {
		if k.pinnedErrno != 0 {
			return k.pinnedErrno
		}
		if errno := k.pinRefusal(to, source, index); errno != 0 {
			return errno
		}
	} else if _, ok := k.choose(to.Is4()); !ok {
		return unix.ENETUNREACH
	}
	if segment > 0 {
		header := 20 + 8
		if !to.Is4() {
			header = 40 + 8
		}
		// udp_send_skb refuses a gso_size whose packets exceed the path's fragment size
		if header+segment > k.mtu(to) {
			return k.gsoErrno
		}
	}
	return 0
}

// pinRefusal is how linux refuses a send pinned to source at interface index, and zero where the pin works
// it checks an IPv4 source before its interface and an IPv6 one after, as udp_sendmsg and ip6_datagram_send_ctl do
func (k *fakeKernel) pinRefusal(to, source netip.Addr, index int) unix.Errno {
	_, local := k.local[source]
	linked := index == 0 || k.links[index]
	switch {
	case to.Is4() && !local:
		return unix.ENETUNREACH
	case !linked:
		return unix.ENODEV
	case !local:
		return unix.EINVAL
	}
	return 0
}

func (k *fakeKernel) mtu(to netip.Addr) int {
	if mtu, ok := k.pathMTU[to]; ok {
		return mtu
	}
	return defaultPathMTU
}

// parseSendControl reads the source from ipi_spec_dst for IPv4 and from ipi6_addr for IPv6, as linux does
func parseSendControl(oob []byte) (source netip.Addr, index int, pinned bool, segment int) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		panic(fmt.Sprintf("a send carried a control message that will not parse: %v", err))
	}
	for _, c := range messages {
		switch {
		case c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_PKTINFO:
			index = int(int32(binary.NativeEndian.Uint32(c.Data[0:4])))
			source, pinned = netip.AddrFrom4([4]byte(c.Data[4:8])), true
		case c.Header.Level == unix.IPPROTO_IPV6 && c.Header.Type == unix.IPV6_PKTINFO:
			source, pinned = netip.AddrFrom16([16]byte(c.Data[0:16])), true
			index = int(binary.NativeEndian.Uint32(c.Data[16:20]))
		case c.Header.Level == unix.IPPROTO_UDP && c.Header.Type == unix.UDP_SEGMENT:
			segment = int(binary.NativeEndian.Uint16(c.Data))
		}
	}
	return source, index, pinned, segment
}

type kernelConn struct{ kernel *fakeKernel }

func (c kernelConn) ReadBatch([]ipv4.Message, int) (int, error) {
	return 0, errors.New("the fake kernel receives nothing")
}
func (c kernelConn) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	if c.kernel.together != nil && c.kernel.arrived.Add(1) <= 2 {
		c.kernel.together.Done()
		c.kernel.together.Wait()
	}
	return c.kernel.write(messages)
}

// atOnce runs send twice at once, the first write of each held until both have arrived
func atOnce(kernel *fakeKernel, send func()) {
	kernel.together = new(sync.WaitGroup)
	kernel.together.Add(2)
	var sends sync.WaitGroup
	sends.Go(send)
	sends.Go(send)
	sends.Wait()
}

type eventLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *eventLog) record(kind string, attrs ...slog.Attr) {
	line := []string{kind}
	for _, attr := range attrs {
		line = append(line, attr.String())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, strings.Join(line, " "))
}

func (l *eventLog) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

func kernelBind(kernel *fakeKernel, events *eventLog) *udpBind {
	socket := func(ipv6 bool) *udpSocket {
		s := &udpSocket{pc: kernelConn{kernel}, ipv6: ipv6}
		s.send.New = func() any { return newUDPSendBatch() }
		return s
	}
	return &udpBind{v4: socket(false), v6: socket(true), events: events.record, started: time.Now()}
}

func kernelHub(kernel *fakeKernel, events *eventLog) *Hub {
	h := &Hub{bind: kernelBind(kernel, events), ike: make(map[uint64]*Mux), esp: make(map[uint32]*Mux),
		muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now()}
	h.reported.Store(-int64(dropReportInterval))
	return h
}

// arrivedFrom is the endpoint a datagram from peer makes arriving on local at interface index
func arrivedFrom(peer, local string, index int) *udpEndpoint {
	from := netip.MustParseAddrPort(peer)
	at := netip.MustParseAddr(local)
	return pinnedEndpoint(net.UDPAddrFromAddrPort(from), at.AsSlice(), index, !at.Is4())
}

func dialed(peer string) *udpEndpoint {
	return &udpEndpoint{addr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort(peer))}
}

// numbered cuts numbered packets from one allocation, so a send may segment them
func numbered(count, size int) [][]byte {
	storage := make([]byte, count*size)
	packets := make([][]byte, count)
	for i := range packets {
		packets[i] = storage[i*size : (i+1)*size]
		binary.BigEndian.PutUint32(packets[i], uint32(i))
	}
	return packets
}

func numbers(sent []sentDatagram) []uint32 {
	out := make([]uint32, len(sent))
	for i, datagram := range sent {
		out[i] = binary.BigEndian.Uint32(datagram.payload)
	}
	return out
}

func sequence(count int) []uint32 {
	out := make([]uint32, count)
	for i := range out {
		out[i] = uint32(i)
	}
	return out
}

func TestSendFromAGoneSourceFallsBackAndStaysOff(t *testing.T) {
	for name, test := range map[string]struct {
		peer, arrival string
		index         int
		pinnedErrno   unix.Errno
		want          string
	}{
		"an IPv4 address the host no longer holds": {peer: "198.51.100.7:4500", arrival: "192.0.2.99", index: 2, want: "ENETUNREACH"},
		"an IPv6 address the host no longer holds": {peer: "[2001:db8:7::7]:4500", arrival: "2001:db8::99", index: 2, want: "EINVAL"},
		"an interface that is gone":                {peer: "198.51.100.7:4500", arrival: "192.0.2.10", index: 9, want: "ENODEV"},
		"an IPv6 interface that is gone":           {peer: "[2001:db8:7::7]:4500", arrival: "2001:db8::10", index: 9, want: "ENODEV"},
		"an address linux will not send from":      {peer: "198.51.100.7:4500", arrival: "192.0.2.10", index: 2, pinnedErrno: unix.EADDRNOTAVAIL, want: "EADDRNOTAVAIL"},
	} {
		t.Run(name, func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.hold("2001:db8::10", 2)
			kernel.pinnedErrno = test.pinnedErrno
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			ep := arrivedFrom(test.peer, test.arrival, test.index)

			// datagrams that cannot share a message, so nothing is segmented
			first := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 2}}
			if err := bind.Send(first, ep); err != nil {
				t.Fatalf("a send with somewhere else to go from failed: %v", err)
			}
			sent := kernel.datagrams()
			if got := numbers(sent); !slices.Equal(got, sequence(3)) {
				t.Fatalf("the datagrams went out as %v, want each once in order", got)
			}
			for _, datagram := range sent {
				if datagram.pinned {
					t.Errorf("a datagram went out from the gone source %s", datagram.from)
				}
			}
			tried := len(kernel.messages())
			if err := bind.Send([][]byte{{0, 0, 0, 3}}, ep); err != nil {
				t.Fatal(err)
			}
			if later := kernel.messages()[tried:]; len(later) != 1 || later[0].pinned {
				t.Errorf("the next send was handed to the kernel as %+v, want once and unpinned", later)
			}
			if !ep.unpinned.Load() {
				t.Error("the endpoint still names the source that refused it")
			}
			want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=%s", ep, test.want)
			if got := events.recorded(); !slices.Equal(got, []string{want}) {
				t.Errorf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

// the arrival address goes after the first of three messages
// and the kernel's choice carries only the two the pinned send left
func TestFallbackSendsOnlyWhatThePinnedSendLeft(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.hold("192.0.2.20", 3)
	kernel.releasing, kernel.releaseAfter = netip.MustParseAddr("192.0.2.20"), 1
	events := &eventLog{}
	ep := arrivedFrom("198.51.100.7:4500", "192.0.2.20", 3)
	// datagrams that cannot share a message, each a message of its own
	if err := kernelBind(kernel, events).Send([][]byte{{0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 2}}, ep); err != nil {
		t.Fatalf("a send with somewhere else to go from failed: %v", err)
	}
	sent := kernel.datagrams()
	if got := numbers(sent); !slices.Equal(got, sequence(3)) {
		t.Fatalf("the datagrams went out as %v, want each once in order", got)
	}
	for i, datagram := range sent {
		want := netip.MustParseAddr("192.0.2.10")
		if i == 0 {
			want = netip.MustParseAddr("192.0.2.20")
		}
		if datagram.pinned != (i == 0) || datagram.from != want {
			t.Errorf("datagram %d went from %s pinned %v, want from %s", i, datagram.from, datagram.pinned, want)
		}
	}
	want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=ENETUNREACH", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("the bind recorded %q, want %q", got, want)
	}
}

// a host with no network for a moment keeps the arrival address its peer expects replies from
func TestSendKeepsItsSourceWhereFallingBackDoesNotHelp(t *testing.T) {
	t.Run("a refusal that is not about the source", func(t *testing.T) {
		kernel := newFakeKernel()
		kernel.hold("192.0.2.10", 2)
		kernel.pinnedErrno = unix.EPERM
		events := &eventLog{}
		ep := arrivedFrom("198.51.100.7:4500", "192.0.2.10", 2)
		if err := kernelBind(kernel, events).Send([][]byte{{1}}, ep); !errors.Is(err, unix.EPERM) {
			t.Fatalf("the send answered %v, want the EPERM the kernel gave", err)
		}
		for _, message := range kernel.messages() {
			if !message.pinned {
				t.Error("a refusal that names no source was answered by dropping the source")
			}
		}
		if ep.unpinned.Load() || len(events.recorded()) != 0 {
			t.Errorf("the endpoint was unpinned with %q recorded", events.recorded())
		}
	})
	t.Run("nowhere to send from at all", func(t *testing.T) {
		kernel := newFakeKernel()
		events := &eventLog{}
		ep := arrivedFrom("198.51.100.7:4500", "192.0.2.10", 2)
		err := kernelBind(kernel, events).Send(numbered(8, 1400), ep)
		if !errors.Is(err, unix.ENETUNREACH) {
			t.Fatalf("the send answered %v, want ENETUNREACH", err)
		}
		if len(kernel.datagrams()) != 0 {
			t.Errorf("%d datagrams went out of a host with no address", len(kernel.datagrams()))
		}
		if ep.unpinned.Load() || ep.unsegmentedUntil.Load() != 0 || len(events.recorded()) != 0 {
			t.Errorf("a send nothing could carry changed the endpoint, unpinned %v, unsegmented until %d, recorded %q",
				ep.unpinned.Load(), ep.unsegmentedUntil.Load(), events.recorded())
		}
	})
}

// a pinned endpoint keeps its source, although EINVAL is also how linux refuses a source that is gone
func TestSegmentationStopsOnlyForTheEndpointThatRefusedIt(t *testing.T) {
	for _, test := range []struct {
		errno  unix.Errno
		narrow *udpEndpoint
	}{
		{unix.EINVAL, dialed("198.51.100.1:4500")},
		{unix.EMSGSIZE, dialed("198.51.100.1:4500")},
		{unix.EIO, dialed("198.51.100.1:4500")},
		{unix.EINVAL, arrivedFrom("198.51.100.1:4500", "192.0.2.10", 2)},
	} {
		narrow := test.narrow
		t.Run(fmt.Sprintf("%s pinned %v", unix.ErrnoName(test.errno), narrow.control != nil), func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.gsoErrno = test.errno
			kernel.pathMTU[netip.MustParseAddr("198.51.100.1")] = 1280
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			wide := dialed("198.51.100.2:4500")

			if err := bind.Send(numbered(8, 1400), narrow); err != nil {
				t.Fatalf("a batch the path carries one at a time failed: %v", err)
			}
			sent := kernel.datagrams()
			if got := numbers(sent); !slices.Equal(got, sequence(8)) {
				t.Fatalf("the datagrams went out as %v, want each once in order", got)
			}
			for _, datagram := range sent {
				if datagram.pinned != (narrow.control != nil) {
					t.Fatalf("a datagram went out pinned %v from an endpoint whose source was never refused", datagram.pinned)
				}
			}
			if narrow.unsegmentedUntil.Load() == 0 {
				t.Fatal("the endpoint whose path refused a segment still segments")
			}
			if narrow.unpinned.Load() {
				t.Fatal("a refused segment cost the endpoint its source")
			}
			tried := len(kernel.messages())
			if err := bind.Send(numbered(8, 1400), narrow); err != nil {
				t.Fatal(err)
			}
			for _, message := range kernel.messages()[tried:] {
				if message.segment != 0 {
					t.Fatalf("a later send to the narrow path segmented again: %+v", message)
				}
			}

			tried = len(kernel.messages())
			if err := bind.Send(numbered(8, 1400), wide); err != nil {
				t.Fatal(err)
			}
			if later := kernel.messages()[tried:]; len(later) != 1 || later[0].segment != 1400 || later[0].errno != 0 {
				t.Errorf("the send to another endpoint was handed over as %+v, want one segmented message", later)
			}
			if wide.unsegmentedUntil.Load() != 0 {
				t.Error("another endpoint stopped segmenting")
			}
			want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=%s", narrow, unix.ErrnoName(test.errno))
			if got := events.recorded(); !slices.Equal(got, []string{want}) {
				t.Errorf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

func TestSegmentationIsNotBlamedForWhatPlainSendsMeetAsWell(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("2001:db8::10", 2)
	events := &eventLog{}
	ep := arrivedFrom("[2001:db8:7::7]:4500", "2001:db8::99", 2)
	if err := kernelBind(kernel, events).Send(numbered(8, 1200), ep); err != nil {
		t.Fatalf("a send with somewhere else to go from failed: %v", err)
	}
	sent := kernel.datagrams()
	if got := numbers(sent); !slices.Equal(got, sequence(8)) {
		t.Fatalf("the datagrams went out as %v, want each once in order", got)
	}
	for _, datagram := range sent {
		if datagram.pinned || !datagram.segmented {
			t.Fatalf("a datagram went out pinned %v and segmented %v, want the kernel's source in one segmented message",
				datagram.pinned, datagram.segmented)
		}
	}
	if ep.unsegmentedUntil.Load() != 0 {
		t.Error("segmentation was blamed for a source the host no longer holds")
	}
	if !ep.unpinned.Load() {
		t.Error("the gone source was kept")
	}
	if got := events.recorded(); len(got) != 1 || got[0] != fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=EINVAL", ep) {
		t.Errorf("the bind recorded %q, want one unpinned endpoint", got)
	}
}

// a session a peer opened loses its arrival address on a path too narrow for its segments
// the kernel's choice then carries the batch one datagram to a message, whether segmentation stopped before or stops now
func TestFallbackFromAGoneSourceKeepsToTheSegmentationStop(t *testing.T) {
	for _, stoppedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("stopped first %v", stoppedFirst), func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.hold("192.0.2.20", 3)
			kernel.pathMTU[netip.MustParseAddr("198.51.100.7")] = 1280
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			ep := arrivedFrom("198.51.100.7:4500", "192.0.2.20", 3)
			if stoppedFirst {
				if err := bind.Send(numbered(8, 1400), ep); err != nil {
					t.Fatal(err)
				}
			}
			kernel.release("192.0.2.20")
			before := len(kernel.datagrams())
			if err := bind.Send(numbered(8, 1400), ep); err != nil {
				t.Fatalf("a batch with another source and single datagrams that fit failed: %v", err)
			}
			sent := kernel.datagrams()[before:]
			if got := numbers(sent); !slices.Equal(got, sequence(8)) {
				t.Fatalf("the datagrams went out as %v, want each once in order", got)
			}
			for _, datagram := range sent {
				if datagram.pinned || datagram.segmented {
					t.Fatalf("a datagram went out pinned %v and segmented %v, want each on its own from the kernel's choice",
						datagram.pinned, datagram.segmented)
				}
			}
			want := []string{
				fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EINVAL", ep),
				fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=ENETUNREACH", ep),
			}
			if got := events.recorded(); !slices.Equal(got, want) {
				t.Errorf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

// a refusal segments cannot cause stops nothing, though a plain resend would pass
func TestSegmentationIsNotBlamedForAnotherErrno(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	events := &eventLog{}
	bind := kernelBind(kernel, events)
	ep := dialed("198.51.100.1:4500")
	kernel.once = unix.ENETUNREACH
	if err := bind.Send(numbered(8, 1400), ep); !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("the send answered %v, want the ENETUNREACH the kernel gave", err)
	}
	if ep.unsegmentedUntil.Load() != 0 || len(events.recorded()) != 0 {
		t.Fatalf("a route rewritten between two sends stopped segmentation, recorded %q", events.recorded())
	}
	tried := len(kernel.messages())
	if err := bind.Send(numbered(8, 1400), ep); err != nil {
		t.Fatal(err)
	}
	if later := kernel.messages()[tried:]; len(later) != 1 || later[0].segment != 1400 {
		t.Errorf("the next send was handed over as %+v, want one segmented message", later)
	}
}

// a refused message of one datagram carried no segments to blame
func TestRefusedSingleDatagramLeavesSegmentationOn(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	events := &eventLog{}
	ep := dialed("198.51.100.1:4500")
	kernel.once = unix.EMSGSIZE
	if err := kernelBind(kernel, events).Send([][]byte{{0, 0, 0, 0}}, ep); !errors.Is(err, unix.EMSGSIZE) {
		t.Fatalf("the send answered %v, want the EMSGSIZE the kernel gave", err)
	}
	if ep.unsegmentedUntil.Load() != 0 || len(events.recorded()) != 0 {
		t.Errorf("a refused datagram that carried no segments stopped segmentation, recorded %q", events.recorded())
	}
}

// a stop lapses when linux would forget the path MTU it learned, and a path still narrow then stops it again
func TestSegmentationResumesOnceThePathMTUExpires(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	narrow := netip.MustParseAddr("198.51.100.1")
	kernel.pathMTU[narrow] = 1280
	events := &eventLog{}
	bind := kernelBind(kernel, events)
	ep := dialed("198.51.100.1:4500")
	segmented := func() bool {
		t.Helper()
		tried := len(kernel.messages())
		if err := bind.Send(numbered(8, 1400), ep); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(kernel.messages()[tried:], func(m triedMessage) bool { return m.segment != 0 })
	}
	if !segmented() {
		t.Fatal("the first send to a narrow path offered no segments")
	}
	bind.started = bind.started.Add(-unsegmentedFor + time.Second)
	if segmented() {
		t.Error("a send offered segments again before the path MTU expired")
	}
	kernel.mu.Lock()
	delete(kernel.pathMTU, narrow)
	kernel.mu.Unlock()
	bind.started = bind.started.Add(-time.Second)
	if !segmented() {
		t.Error("a send to a path that widened offered no segments once the path MTU expired")
	}
	kernel.mu.Lock()
	kernel.pathMTU[narrow] = 1280
	kernel.mu.Unlock()
	if !segmented() {
		t.Error("a send to a path that narrowed again offered no segments")
	}
	if segmented() {
		t.Error("a path that narrowed again was not stopped again")
	}
	want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EINVAL", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want, want}) {
		t.Errorf("two stops recorded %q, want each once", got)
	}
}

// the kernel chooses 192.0.2.10, the lower address, wherever a send names no source
func TestDialedMuxFollowsUnpinnedAndAcceptedMuxPinned(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.hold("192.0.2.20", 3)
	hub := kernelHub(kernel, &eventLog{})
	last := func() sentDatagram {
		t.Helper()
		sent := kernel.datagrams()
		if len(sent) == 0 {
			t.Fatal("nothing went out")
		}
		return sent[len(sent)-1]
	}

	out, err := hub.NewMux(net.ParseIP("198.51.100.1"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name     string
		endpoint *udpEndpoint
		moved    bool
		to       string
	}{
		{name: "the peer arriving from where it was dialed", endpoint: arrivedFrom("198.51.100.1:4500", "192.0.2.20", 3), to: "198.51.100.1:4500"},
		{name: "the peer moved", endpoint: arrivedFrom("198.51.100.9:6000", "192.0.2.20", 3), moved: true, to: "198.51.100.9:6000"},
		{name: "the moved peer arriving on another local address", endpoint: arrivedFrom("198.51.100.9:6000", "192.0.2.10", 2), to: "198.51.100.9:6000"},
	} {
		if moved := out.AdoptEndpoint(step.endpoint); moved != step.moved {
			t.Errorf("%s: a dialed mux reported moved %v, want %v", step.name, moved, step.moved)
		}
		if err := out.SendIKE([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if got := last(); got.to != netip.MustParseAddrPort(step.to) || got.pinned || got.from != netip.MustParseAddr("192.0.2.10") {
			t.Errorf("%s: a dialed mux sent to %s from %s pinned %v, want %s from the kernel's choice", step.name, got.to, got.from, got.pinned, step.to)
		}
	}

	in, err := hub.NewMuxTo(arrivedFrom("198.51.100.5:4500", "192.0.2.10", 2))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name          string
		endpoint      *udpEndpoint
		moved         bool
		to            string
		from          string
		unpinnedFirst bool
	}{
		{name: "the same peer arriving on the same address", endpoint: arrivedFrom("198.51.100.5:4500", "192.0.2.10", 2), to: "198.51.100.5:4500", from: "192.0.2.10"},
		{name: "a new port behind the peer's NAT", endpoint: arrivedFrom("198.51.100.5:4600", "192.0.2.10", 2), moved: true, to: "198.51.100.5:4600", from: "192.0.2.10"},
		{name: "the same peer arriving on another local address", endpoint: arrivedFrom("198.51.100.5:4600", "192.0.2.20", 3), moved: true, to: "198.51.100.5:4600", from: "192.0.2.20"},
		{name: "a pin that fell back meeting the address it fell back from", endpoint: arrivedFrom("198.51.100.5:4600", "192.0.2.20", 3), moved: true, to: "198.51.100.5:4600", from: "192.0.2.20", unpinnedFirst: true},
	} {
		if step.unpinnedFirst {
			in.Endpoint().(*udpEndpoint).unpinned.Store(true)
		}
		if moved := in.AdoptEndpoint(step.endpoint); moved != step.moved {
			t.Errorf("%s: the adoption reported moved %v, want %v", step.name, moved, step.moved)
		}
		if err := in.SendIKE([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if got := last(); got.to != netip.MustParseAddrPort(step.to) || !got.pinned || got.from != netip.MustParseAddr(step.from) {
			t.Errorf("%s: the mux sent to %s from %s pinned %v, want %s from %s", step.name, got.to, got.from, got.pinned, step.to, step.from)
		}
	}
}

// an adoption that changes nothing keeps the endpoint, and with it the stop its sends learned
func TestUnchangedAdoptionKeepsWhatSendsLearned(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.pathMTU[netip.MustParseAddr("198.51.100.5")] = 1280
	hub := kernelHub(kernel, &eventLog{})
	out, err := hub.NewMux(net.ParseIP("198.51.100.5"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	in, err := hub.NewMuxTo(arrivedFrom("198.51.100.5:4500", "192.0.2.10", 2))
	if err != nil {
		t.Fatal(err)
	}
	for name, mux := range map[string]*Mux{"dialed": out, "accepted": in} {
		if err := mux.SendESPBatch(numbered(8, 1400)); err != nil {
			t.Fatal(err)
		}
		if mux.AdoptEndpoint(arrivedFrom("198.51.100.5:4500", "192.0.2.10", 2)) {
			t.Errorf("%s: adopting the endpoint it sends to reported a move", name)
		}
		tried := len(kernel.messages())
		if err := mux.SendESPBatch(numbered(8, 1400)); err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(kernel.messages()[tried:], func(m triedMessage) bool { return m.segment != 0 }) {
			t.Errorf("%s: an adoption that changed nothing lost the stop its sends learned", name)
		}
	}
}

// the kernel's own answer to a source the host does not hold, through the hub's own events
func TestKernelRefusesAGoneSourceAndTheHubFallsBack(t *testing.T) {
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	peer := listenPeer(t, "udp4", "127.0.0.1")
	ep := pinnedEndpoint(peer.LocalAddr().(*net.UDPAddr), net.IPv4(192, 0, 2, 99).To4(), 0, false)
	if err := hub.SendIKETo([]byte("reply"), ep); err != nil {
		t.Fatalf("a reply from a source the host does not hold was not sent from another: %v", err)
	}
	buf := make([]byte, 64)
	if err := peer.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := peer.ReadFromUDP(buf); err != nil || string(buf[nonESPMarkerLen:n]) != "reply" {
		t.Fatalf("the peer read %q, %v", buf[:n], err)
	}
	want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=ENETUNREACH", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("the hub recorded %q, want %q", got, want)
	}
}

// two sends that meet a gone source at once both fall back and record it once
func TestSendsUnpinnedAtOnceRecordItOnce(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	events := &eventLog{}
	bind := kernelBind(kernel, events)
	ep := arrivedFrom("198.51.100.7:4500", "192.0.2.99", 2)
	atOnce(kernel, func() {
		if err := bind.Send([][]byte{{0, 0, 0, 0}}, ep); err != nil {
			t.Error(err)
		}
	})
	if got := len(kernel.datagrams()); got != 2 {
		t.Errorf("%d datagrams went out of two sends", got)
	}
	want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=ENETUNREACH", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("two sends that fell back at once recorded %q, want %q once", got, want)
	}
}

// two sends that meet a narrow path at once both go out one datagram to a message and record the stop once
func TestSendsUnsegmentedAtOnceRecordItOnce(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.pathMTU[netip.MustParseAddr("198.51.100.1")] = 1280
	events := &eventLog{}
	bind := kernelBind(kernel, events)
	ep := dialed("198.51.100.1:4500")
	atOnce(kernel, func() {
		if err := bind.Send(numbered(8, 1400), ep); err != nil {
			t.Error(err)
		}
	})
	if got := len(kernel.datagrams()); got != 16 {
		t.Errorf("%d datagrams went out of two sends of 8", got)
	}
	want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EINVAL", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("two sends that stopped segmenting at once recorded %q, want %q once", got, want)
	}
}
