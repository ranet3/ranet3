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

// fakeKernel answers sendmmsg as linux does from the addresses, interfaces and path MTUs it holds, for a socket set to IP_PMTUDISC_DO
type fakeKernel struct {
	mu sync.Mutex
	// local maps each address the host holds to its interface
	local   map[netip.Addr]int
	links   map[int]bool
	pathMTU map[netip.Addr]int
	// gsoErrno is how this kernel refuses a segment past the path MTU, EMSGSIZE from 6.14 on and EINVAL before
	gsoErrno unix.Errno
	// unsegmentable refuses every segmented message within the path to a destination with its errno, EIO for a route through an IPsec policy
	unsegmentable map[netip.Addr]unix.Errno
	// reads counts the path MTUs the bind read
	reads int
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
	// size is the bytes the message carried, every segment of it together
	size  int
	errno unix.Errno
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{local: map[netip.Addr]int{}, links: map[int]bool{}, pathMTU: map[netip.Addr]int{},
		unsegmentable: map[netip.Addr]unix.Errno{}, gsoErrno: unix.EMSGSIZE}
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
	tried := triedMessage{to: to, pinned: pinned, segment: segment, size: len(m.Buffers[0])}
	errno := k.route(to.Addr(), source, index, pinned, segment, len(m.Buffers[0]))
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

// route refuses a message of size bytes, segmented into segment bytes where that is not zero, as linux does after it found a source
func (k *fakeKernel) route(to, source netip.Addr, index int, pinned bool, segment, size int) unix.Errno {
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
	header := 20 + 8
	if !to.Is4() {
		header = 40 + 8
	}
	if segment == 0 {
		// DO refuses a datagram past the path MTU rather than fragment it
		if header+size > k.mtu(to) {
			return unix.EMSGSIZE
		}
		return 0
	}
	// udp_send_skb refuses a gso_size whose packets exceed the path's fragment size, then a route that cannot segment
	if header+segment > k.mtu(to) {
		return k.gsoErrno
	}
	return k.unsegmentable[to]
}

// routeMTU answers the bind's read of the path MTU to ep from the path MTUs the kernel holds
// a read for a send that carries a pin binds the pin's interface and address first, which linux refuses once either is gone
func (k *fakeKernel) routeMTU(ep *udpEndpoint) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads++
	if ep.pin() != nil {
		source, _ := netip.AddrFromSlice(ep.source)
		if ep.index != 0 && !k.links[ep.index] {
			return 0, unix.ENODEV
		}
		if _, ok := k.local[source.Unmap()]; !ok {
			return 0, unix.EADDRNOTAVAIL
		}
	}
	return k.mtu(ep.AddrPort().Addr()), nil
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
	return &udpBind{v4: socket(false), v6: socket(true), events: events.record, started: time.Now(), pathMTU: kernel.routeMTU}
}

func kernelHub(kernel *fakeKernel, events *eventLog) *Hub {
	h := &Hub{bind: kernelBind(kernel, events), muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now()}
	h.tables.Store(&spiTables{ike: map[uint64]*Mux{}, esp: map[uint32]*Mux{}})
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

// numbered cuts count numbered packets of size from one allocation, so a send may segment them
func numbered(count, size int) [][]byte { return sized(slices.Repeat([]int{size}, count)...) }

// sized cuts packets of sizes from one allocation, each numbered by its place, so a send may segment neighbors
func sized(sizes ...int) [][]byte {
	total := 0
	for _, size := range sizes {
		total += size
	}
	storage := make([]byte, total)
	packets := make([][]byte, len(sizes))
	offset := 0
	for i, size := range sizes {
		packets[i] = storage[offset : offset+size]
		binary.BigEndian.PutUint32(packets[i], uint32(i))
		offset += size
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

// a route that refuses segments and passes single datagrams, as one through an IPsec policy does, stops segmentation to its endpoint alone
// a pinned endpoint keeps its source, although EINVAL is also how linux refuses a source that is gone
func TestSegmentationStopsOnlyForTheEndpointThatRefusedIt(t *testing.T) {
	for _, test := range []struct {
		errno    unix.Errno
		refusing *udpEndpoint
	}{
		{unix.EINVAL, dialed("198.51.100.1:4500")},
		{unix.EIO, dialed("198.51.100.1:4500")},
		{unix.EINVAL, arrivedFrom("198.51.100.1:4500", "192.0.2.10", 2)},
	} {
		refusing := test.refusing
		t.Run(fmt.Sprintf("%s pinned %v", unix.ErrnoName(test.errno), refusing.control != nil), func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.unsegmentable[netip.MustParseAddr("198.51.100.1")] = test.errno
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			other := dialed("198.51.100.2:4500")

			if err := bind.Send(numbered(8, 1400), refusing); err != nil {
				t.Fatalf("a batch the route carries one datagram at a time failed: %v", err)
			}
			sent := kernel.datagrams()
			if got := numbers(sent); !slices.Equal(got, sequence(8)) {
				t.Fatalf("the datagrams went out as %v, want each once in order", got)
			}
			for _, datagram := range sent {
				if datagram.pinned != (refusing.control != nil) {
					t.Fatalf("a datagram went out pinned %v from an endpoint whose source was never refused", datagram.pinned)
				}
			}
			if refusing.unsegmentedUntil.Load() == 0 {
				t.Fatal("the endpoint whose route refused segments still segments")
			}
			if refusing.unpinned.Load() {
				t.Fatal("refused segments cost the endpoint its source")
			}
			tried := len(kernel.messages())
			if err := bind.Send(numbered(8, 1400), refusing); err != nil {
				t.Fatal(err)
			}
			for _, message := range kernel.messages()[tried:] {
				if message.segment != 0 {
					t.Fatalf("a later send over the refusing route segmented again: %+v", message)
				}
			}

			tried = len(kernel.messages())
			if err := bind.Send(numbered(8, 1400), other); err != nil {
				t.Fatal(err)
			}
			if later := kernel.messages()[tried:]; len(later) != 1 || later[0].segment != 1400 || later[0].errno != 0 {
				t.Errorf("the send to another endpoint was handed over as %+v, want one segmented message", later)
			}
			if other.unsegmentedUntil.Load() != 0 {
				t.Error("another endpoint stopped segmenting")
			}
			want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=%s", refusing, unix.ErrnoName(test.errno))
			if got := events.recorded(); !slices.Equal(got, []string{want}) {
				t.Errorf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

// a datagram larger than its path is refused, segmented or alone, and the send reads the path MTU and reports it
// the datagrams of the batch the path carries go after it, those past it do not, and nothing stops segmenting
// a kernel from 6.14 on refuses the segments with EMSGSIZE and the send resends none of them one to a message
// an older one answers EINVAL, and the resend's first single datagram meets the EMSGSIZE
// 1240 bytes fit an IPv4 path of 1280 and not an IPv6 one
// 1252 bytes fill an IPv4 path of 1280 and 1253 go past it
// 1232 bytes fill an IPv6 one and 1233 go past it
// a run of datagrams that fill the path goes in one message after the report, as a shorter run does
func TestRefusedDatagramReportsItsPathAndTheRestStillGo(t *testing.T) {
	const pathMTU = 1280
	sizes := []int{64, 1400, 1400, 1400, 600, 600, 1240, 1240, 64, 1400, 64, 1252, 1252, 1253, 64, 1232, 1232, 1233, 64}
	for _, test := range []struct {
		gsoErrno unix.Errno
		ep       *udpEndpoint
	}{
		{unix.EMSGSIZE, dialed("198.51.100.1:4500")},
		{unix.EINVAL, dialed("198.51.100.1:4500")},
		{unix.EMSGSIZE, arrivedFrom("198.51.100.1:4500", "192.0.2.10", 2)},
		{unix.EMSGSIZE, dialed("[2001:db8:7::1]:4500")},
		{unix.EINVAL, arrivedFrom("[2001:db8:7::1]:4500", "2001:db8::10", 2)},
	} {
		ep := test.ep
		t.Run(fmt.Sprintf("%s to %s pinned %v", unix.ErrnoName(test.gsoErrno), ep, ep.control != nil), func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.hold("2001:db8::10", 2)
			kernel.gsoErrno = test.gsoErrno
			kernel.pathMTU[ep.AddrPort().Addr()] = pathMTU
			events := &eventLog{}
			header := 20 + 8
			if !ep.AddrPort().Addr().Is4() {
				header = 40 + 8
			}

			err := kernelBind(kernel, events).Send(sized(sizes...), ep)
			report, ok := err.(*PathMTUError)
			if !ok || *report != (PathMTUError{Endpoint: ep.AddrPort(), MTU: pathMTU}) {
				t.Fatalf("the send answered %v, want the report of a %d byte path to %s alone", err, pathMTU, ep)
			}
			var within []uint32
			for i, size := range sizes {
				if size+header <= pathMTU {
					within = append(within, uint32(i))
				}
			}
			sent := kernel.datagrams()
			if got := numbers(sent); !slices.Equal(got, within) {
				t.Fatalf("the datagrams went out as %v, want those within the path once in order, %v", got, within)
			}
			for _, datagram := range sent {
				if datagram.pinned != (ep.control != nil) {
					t.Errorf("a datagram went out pinned %v from an endpoint whose source was never refused", datagram.pinned)
				}
				if (len(datagram.payload) == 600 || len(datagram.payload)+header == pathMTU) && !datagram.segmented {
					t.Error("a run within the path went one datagram to a message after the report")
				}
			}
			resent := 0
			for _, message := range kernel.messages() {
				if message.segment == 0 && message.size+header > pathMTU {
					resent++
				}
			}
			wantResent := 0
			if test.gsoErrno == unix.EINVAL {
				wantResent = 1
			}
			if resent != wantResent {
				t.Errorf("%d datagrams past the path were handed over one to a message, want %d", resent, wantResent)
			}
			if kernel.reads != 1 {
				t.Errorf("the send read the path MTU %d times, want once", kernel.reads)
			}
			if ep.unsegmentedUntil.Load() != 0 || ep.unpinned.Load() || len(events.recorded()) != 0 {
				t.Errorf("a refusal for size changed the endpoint, unsegmented until %d, unpinned %v, recorded %q",
					ep.unsegmentedUntil.Load(), ep.unpinned.Load(), events.recorded())
			}
		})
	}
}

// a session a peer opened loses its arrival address while its path narrows
// the kernel's choice of source is refused for size, which means linux routed the datagram from it, so the send keeps that choice
// the path MTU is then read for the route that choice takes, as no route from the gone address can be read
func TestFallbackRefusedForSizeKeepsTheKernelsChoice(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.pathMTU[netip.MustParseAddr("198.51.100.7")] = 1280
	events := &eventLog{}
	ep := arrivedFrom("198.51.100.7:4500", "192.0.2.99", 2)
	err := kernelBind(kernel, events).Send(numbered(8, 1400), ep)
	if report, ok := err.(*PathMTUError); !ok || report.MTU != 1280 {
		t.Fatalf("the send answered %v, want the report of a 1280 byte path", err)
	}
	if len(kernel.datagrams()) != 0 {
		t.Errorf("%d datagrams past the path went out", len(kernel.datagrams()))
	}
	if !ep.unpinned.Load() {
		t.Error("the endpoint still names the source that refused it")
	}
	want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=ENETUNREACH", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("the bind recorded %q, want %q", got, want)
	}
}

// the report reaches what sends through a mux, which reads it to narrow its session
func TestMuxHandsThePathReportOn(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.pathMTU[netip.MustParseAddr("198.51.100.5")] = 1280
	hub := kernelHub(kernel, &eventLog{})
	mux, err := hub.NewMux(net.ParseIP("198.51.100.5"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	err = mux.SendESPBatch(numbered(8, 1400))
	report, ok := errors.AsType[*PathMTUError](err)
	if want := (PathMTUError{Endpoint: netip.MustParseAddrPort("198.51.100.5:4500"), MTU: 1280}); !ok || *report != want {
		t.Errorf("the mux answered %v, want the report %v", err, &want)
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

// a session a peer opened loses its arrival address on a route that refuses segments
// the kernel's choice then carries the batch one datagram to a message, whether segmentation stopped before or stops now
func TestFallbackFromAGoneSourceKeepsToTheSegmentationStop(t *testing.T) {
	for _, stoppedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("stopped first %v", stoppedFirst), func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.10", 2)
			kernel.hold("192.0.2.20", 3)
			kernel.unsegmentable[netip.MustParseAddr("198.51.100.7")] = unix.EIO
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
				t.Fatalf("a batch with another source and single datagrams the route passes failed: %v", err)
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
				fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EIO", ep),
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
	kernel.once = unix.EIO
	if err := kernelBind(kernel, events).Send([][]byte{{0, 0, 0, 0}}, ep); !errors.Is(err, unix.EIO) {
		t.Fatalf("the send answered %v, want the EIO the kernel gave", err)
	}
	if ep.unsegmentedUntil.Load() != 0 || len(events.recorded()) != 0 {
		t.Errorf("a refused datagram that carried no segments stopped segmentation, recorded %q", events.recorded())
	}
}

// a stop lapses after unsegmentedFor, and a route that refuses segments again then stops them again
func TestSegmentationResumesOnceItsStopLapses(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	refusing := netip.MustParseAddr("198.51.100.1")
	kernel.unsegmentable[refusing] = unix.EIO
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
		t.Fatal("the first send over a route that refuses segments offered none")
	}
	bind.started = bind.started.Add(-unsegmentedFor + time.Second)
	if segmented() {
		t.Error("a send offered segments again before the stop lapsed")
	}
	kernel.mu.Lock()
	delete(kernel.unsegmentable, refusing)
	kernel.mu.Unlock()
	bind.started = bind.started.Add(-time.Second)
	if !segmented() {
		t.Error("a send over a route that takes segments again offered none once the stop lapsed")
	}
	kernel.mu.Lock()
	kernel.unsegmentable[refusing] = unix.EIO
	kernel.mu.Unlock()
	if !segmented() {
		t.Error("a send over a route that refuses segments again offered none")
	}
	if segmented() {
		t.Error("a route that refuses segments again was not stopped again")
	}
	want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EIO", ep)
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
	kernel.unsegmentable[netip.MustParseAddr("198.51.100.5")] = unix.EIO
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

// two sends that meet a route refusing segments at once both go out one datagram to a message and record the stop once
func TestSendsUnsegmentedAtOnceRecordItOnce(t *testing.T) {
	kernel := newFakeKernel()
	kernel.hold("192.0.2.10", 2)
	kernel.unsegmentable[netip.MustParseAddr("198.51.100.1")] = unix.EIO
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
	want := fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=EIO", ep)
	if got := events.recorded(); !slices.Equal(got, []string{want}) {
		t.Errorf("two sends that stopped segmenting at once recorded %q, want %q once", got, want)
	}
}
