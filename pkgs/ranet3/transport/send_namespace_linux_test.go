// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// vethInfoPeer is VETH_INFO_PEER of linux/veth.h, which describes the other end of a new pair
const vethInfoPeer = 1

// lockedPathMTU is the path MTU to the far end along each route the test locks, which path MTU discovery cannot change
// datagrams of 1400 bytes exceed it alone or as segments, and the veth under it carries 1500
const lockedPathMTU = 1280

// testMark is the mark of the bind whose datagrams a rule routes by it
const testMark = 0x2a

// the tables a rule routes into, by the send's mark, its pinned source or its pinned interface
// each holds a route to the far end locked at lockedPathMTU, and each number is its rule's priority too, ahead of the main table's
const (
	markTable   = 100
	sourceTable = 101
	deviceTable = 102
)

// sentinel numbers the datagram sent after a batch, which the far end reads after every datagram of the batch that arrived
const sentinel = math.MaxUint32

// linux refuses a datagram past a locked path MTU, segmented or alone, as the bind sets DF on every datagram
// the send reports the route's path MTU, sends the datagrams within it, and cuts none into fragments
// segmentation stays on, since a refusal for size says nothing of segments
// a kernel from 6.14 on refuses the segments with EMSGSIZE, and the send resends none of them one to a message
// an older one answers EINVAL, and the resend's first single datagram meets the EMSGSIZE
// a rule picks each locked route by the send's mark, its pinned source or its pinned interface, while the main table's route carries 1500
// so the report carries the locked path MTU only where its read names each of them as the send does
// the peer listens at the far end of a veth pair, in a network namespace of its own
func TestKernelRefusesWhatALockedPathCannotCarry(t *testing.T) {
	far, link := lockedFarEnd(t)
	events := &eventLog{}
	marked, markedLogs := listenHanded(t, testMark, events)
	plain, plainLogs := listenHanded(t, 0, events)
	for i, address := range farAddresses {
		listener := far.listeners[i]
		to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(address.Addr(), uint16(listener.LocalAddr().(*net.UDPAddr).Port)))
		ipv6 := !address.Addr().Is4()
		header := headerFor(address.Addr())
		for _, way := range []struct {
			name string
			bind *udpBind
			log  *handedConn
			ep   *udpEndpoint
		}{
			{"the bind's mark", marked, markedLogs[i], &udpEndpoint{addr: to}},
			{"its pinned source", plain, plainLogs[i], pinnedEndpoint(to, steeredSources[i].Addr().AsSlice(), 0, ipv6)},
			{"its pinned interface", plain, plainLogs[i], pinnedEndpoint(to, nearAddresses[i].Addr().AsSlice(), link.Index, ipv6)},
		} {
			pinned := way.ep.control != nil
			for _, segmented := range []bool{true, false} {
				// eight datagrams past the path in one message with the first of four within it, the rest of those and a short one in the next
				sizes := []int{1400, 1400, 1400, 1400, 1400, 1400, 1400, 1400, 600, 600, 600, 600, 64}
				if !segmented {
					sizes = []int{1400}
				}
				way.log.handed = nil
				err := way.bind.Send(sized(sizes...), way.ep)
				report, ok := err.(*PathMTUError)
				if !ok || *report != (PathMTUError{Endpoint: way.ep, MTU: lockedPathMTU}) {
					t.Errorf("a send routed by %s to %s answered %v, want the report of its %d byte path alone", way.name, way.ep, err, lockedPathMTU)
				}
				var want []triedMessage
				if segmented {
					refusal := unix.EMSGSIZE
					if len(way.log.handed) > 0 && way.log.handed[0].errno == unix.EINVAL {
						refusal = unix.EINVAL
					}
					want = append(want, triedMessage{pinned: pinned, segment: 1400, size: 8*1400 + 600, errno: refusal})
					if refusal == unix.EINVAL {
						want = append(want, triedMessage{pinned: pinned, size: 1400, errno: unix.EMSGSIZE})
					}
					want = append(want, triedMessage{pinned: pinned, segment: 600, size: 4*600 + 64})
					t.Logf("linux refused the segments routed by %s to %s with %s", way.name, way.ep, unix.ErrnoName(refusal))
				} else {
					want = append(want, triedMessage{pinned: pinned, size: 1400, errno: unix.EMSGSIZE})
				}
				if !slices.Equal(way.log.handed, want) {
					t.Errorf("a send routed by %s to %s handed linux %+v, want %+v", way.name, way.ep, way.log.handed, want)
				}

				if err := way.bind.Send([][]byte{binary.BigEndian.AppendUint32(nil, sentinel)}, way.ep); err != nil {
					t.Fatalf("the datagram after the batch failed: %v", err)
				}
				var within []arrival
				for number, size := range sizes {
					if size+header <= lockedPathMTU {
						within = append(within, arrival{uint32(number), size})
					}
				}
				if got := arrivals(t, listener); !slices.Equal(got, within) {
					t.Errorf("a send routed by %s to %s reached the far end as %v, want the datagrams within the path whole, %v", way.name, way.ep, got, within)
				}
			}
			if way.ep.unsegmentedUntil.Load() != 0 {
				t.Errorf("sends routed by %s to %s stopped segmenting", way.name, way.ep)
			}
		}
	}
	if got := events.recorded(); len(got) != 0 {
		t.Errorf("refusals for size recorded %q, want nothing", got)
	}
	ipv4, ipv6, err := far.reassembled()
	if err != nil {
		t.Fatal(err)
	}
	if ipv4 != 0 || ipv6 != 0 {
		t.Errorf("the far end put %d IPv4 and %d IPv6 datagrams back together from fragments, want none", ipv4, ipv6)
	}
}

// a mux under the floor lets its family's socket fragment, and linux then sends a datagram past a locked path in fragments, which the far end puts back together
// a segment past the path is refused under DONT and WANT as under DO
// the segments go again one datagram to a message, each in fragments
// the other family still refuses a datagram past its path and reports the path, and so does the family once the mux stops
// IPv4 fragments first and IPv6 next, each through its own option
// the mux under the floor sends to an endpoint of its own in the family
// the sends go to the far end's listener
// the listener's endpoint still segments
func TestKernelFragmentsPastALockedPathOnlyWhileTheFamilyAsks(t *testing.T) {
	far, _ := lockedFarEnd(t)
	events := &eventLog{}
	bind, logs := listenHanded(t, testMark, events)
	var eps, unders []*udpEndpoint
	for i, address := range farAddresses {
		port := far.listeners[i].LocalAddr().(*net.UDPAddr).Port
		eps = append(eps, &udpEndpoint{addr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(address.Addr(), uint16(port)))})
		unders = append(unders, &udpEndpoint{addr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(address.Addr(), 4500))})
	}
	// sent hands sizes to the bind toward the far address of family and reads back what arrived
	sent := func(family int, sizes ...int) ([]arrival, error) {
		t.Helper()
		err := bind.Send(sized(sizes...), eps[family])
		if err := bind.Send([][]byte{binary.BigEndian.AppendUint32(nil, sentinel)}, eps[family]); err != nil {
			t.Fatalf("the datagram after the batch to %s failed: %v", eps[family], err)
		}
		return arrivals(t, far.listeners[family]), err
	}
	// refused sends one datagram past the path toward family, which only its report answers
	refused := func(family int, when string) {
		t.Helper()
		got, err := sent(family, 1400)
		if report, ok := err.(*PathMTUError); !ok || *report != (PathMTUError{Endpoint: eps[family], MTU: lockedPathMTU}) || len(got) != 0 {
			t.Errorf("%s, a datagram past the path to %s answered %v and reached the far end as %v, want its report alone", when, eps[family], err, got)
		}
	}
	eight := []int{1400, 1400, 1400, 1400, 1400, 1400, 1400, 1400}
	var whole []arrival
	for number := range eight {
		whole = append(whole, arrival{uint32(number), 1400})
	}
	var unsegmented []string
	for family, ep := range eps {
		if err := bind.fragment(unders[family], true); err != nil {
			t.Fatalf("let the socket of the family of %s fragment: %v", ep, err)
		}
		if got, err := sent(family, 1400); err != nil || !slices.Equal(got, whole[:1]) {
			t.Errorf("a datagram past the path to %s, whose family fragments, answered %v and reached the far end as %v, want it whole", ep, err, got)
		}
		logs[family].handed = nil
		if got, err := sent(family, eight...); err != nil || !slices.Equal(got, whole) {
			t.Errorf("eight segments past the path to %s, whose family fragments, answered %v and reached the far end as %v, want all of them whole", ep, err, got)
		}
		refusal := unix.EMSGSIZE
		if len(logs[family].handed) > 0 && logs[family].handed[0].errno == unix.EINVAL {
			refusal = unix.EINVAL
		}
		want := []triedMessage{{segment: 1400, size: 8 * 1400, errno: refusal}}
		for range eight {
			want = append(want, triedMessage{size: 1400})
		}
		// the sentinel goes one datagram to a message too
		want = append(want, triedMessage{size: 4})
		if !slices.Equal(logs[family].handed, want) {
			t.Errorf("the segments past the path to %s, whose family fragments, were handed to linux as %+v, want %+v", ep, logs[family].handed, want)
		}
		unsegmented = append(unsegmented, fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=%s", ep, unix.ErrnoName(refusal)))
		refused(1-family, fmt.Sprintf("while the family of %s fragments", ep))
		if err := bind.fragment(unders[family], false); err != nil {
			t.Fatalf("stop the socket of the family of %s fragmenting: %v", ep, err)
		}
		refused(family, "once the family stopped fragmenting")
	}
	ipv4, ipv6, err := far.reassembled()
	if err != nil {
		t.Fatal(err)
	}
	if ipv4 != 9 || ipv6 != 9 {
		t.Errorf("the far end put %d IPv4 and %d IPv6 datagrams back together from fragments, want the 9 of each family sent while it fragmented", ipv4, ipv6)
	}
	if got := events.recorded(); !slices.Equal(got, unsegmented) {
		t.Errorf("the bind recorded %q, want %q", got, unsegmented)
	}
}

// a mux under the floor lets the IPv4 socket fragment
// linux then sends without DF a datagram its route carries whole
// a router ahead of a narrower hop that answers nothing fragments such a datagram rather than drop it
// the socket sets DF on it again once the family stops fragmenting
// the route over loopback carries 65536 bytes and locks nothing
// WANT would set DF on the datagram there
// a raw socket reads the datagram's IP header as it arrives, in a network namespace of the test's own
func TestKernelSendsWithoutDFWhatTheRouteCarriesWhileIPv4Fragments(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a network namespace and a raw socket need root on linux")
	}
	runtime.LockOSThread()
	if err := unshareEmptyNamespace(); err != nil {
		t.Fatal(err)
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.close()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("look up loopback: %v", err)
	}
	if err := netlink.request(unix.RTM_NEWLINK, 0, linkMessage(loopback.Index, unix.IFF_UP)); err != nil {
		t.Fatalf("bring loopback up: %v", err)
	}
	raw, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("open a raw socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(raw) })
	budget := unix.NsecToTimeval(arrivalBudget.Nanoseconds())
	if err := unix.SetsockoptTimeval(raw, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &budget); err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	to := sink.LocalAddr().(*net.UDPAddr)
	ep := &udpEndpoint{addr: to}
	bind, _ := listenHanded(t, 0, &eventLog{})
	// flags sends the floor's datagram to the sink
	// it returns the flags and fragment offset of the datagram's IP header as it arrived
	flags := func(when string) uint16 {
		t.Helper()
		if err := bind.Send([][]byte{make([]byte, floorDatagram)}, ep); err != nil {
			t.Fatalf("%s, the floor's datagram answered %v", when, err)
		}
		packet := make([]byte, 65536)
		for {
			n, _, err := unix.Recvfrom(raw, packet, 0)
			if err != nil {
				t.Fatalf("%s, the floor's datagram never arrived: %v", when, err)
			}
			header := int(packet[0]&0x0f) * 4
			if n == header+8+floorDatagram && int(binary.BigEndian.Uint16(packet[header+2:])) == to.Port {
				return binary.BigEndian.Uint16(packet[6:])
			}
		}
	}
	// dontFragment is DF among the flags, with no more fragments and a fragment offset of zero
	const dontFragment = 0x4000
	if got := flags("before the family fragments"); got != dontFragment {
		t.Errorf("before the family fragments, the floor's datagram arrived with flags and offset %#04x, want DF alone", got)
	}
	if err := bind.fragment(ep, true); err != nil {
		t.Fatalf("let the IPv4 socket fragment: %v", err)
	}
	if got := flags("while the family fragments"); got != 0 {
		t.Errorf("while the family fragments, the floor's datagram arrived with flags and offset %#04x, want it whole without DF", got)
	}
	if err := bind.fragment(ep, false); err != nil {
		t.Fatalf("stop the IPv4 socket fragmenting: %v", err)
	}
	if got := flags("once the family stopped fragmenting"); got != dontFragment {
		t.Errorf("once the family stopped fragmenting, the floor's datagram arrived with flags and offset %#04x, want DF alone", got)
	}
}

// lockedFarEnd opens the far end in a network namespace of its own and gives the test's thread one of its own, joined by a veth pair
// it routes each far address by the send's mark, its pinned source and its pinned interface into a table whose route locks the path at lockedPathMTU
// and it returns the far end and the test's end of the pair
func lockedFarEnd(t *testing.T) (farEnd, *net.Interface) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("building a veth pair needs root on linux")
	}
	runtime.LockOSThread()
	if err := unshareEmptyNamespace(); err != nil {
		t.Fatal(err)
	}
	near, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open this namespace: %v", err)
	}
	opened := make(chan farEnd, 1)
	go func() { opened <- openFarEnd(near) }()
	far := <-opened
	_ = unix.Close(near)
	if far.err != nil {
		t.Fatal(far.err)
	}
	t.Cleanup(far.close)
	link, err := net.InterfaceByName("near")
	if err != nil {
		t.Fatalf("look up the near end: %v", err)
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.close()
	if err := netlink.configure(link.Index, slices.Concat(nearAddresses, steeredSources)); err != nil {
		t.Fatalf("configure the near end: %v", err)
	}
	for i, address := range farAddresses {
		source := steeredSources[i].Addr()
		for _, rule := range []struct {
			table      uint32
			sourceBits int
			match      []byte
		}{
			{markTable, 0, slices.Concat(attribute(unix.FRA_FWMARK, word(testMark)), attribute(unix.FRA_FWMASK, word(^uint32(0))))},
			{sourceTable, source.BitLen(), attribute(unix.FRA_SRC, source.AsSlice())},
			{deviceTable, 0, attribute(unix.FRA_OIFNAME, cString("near"))},
		} {
			if err := netlink.steer(addressFamily(address.Addr()), rule.table, rule.sourceBits, rule.match); err != nil {
				t.Fatalf("route by a rule into table %d: %v", rule.table, err)
			}
			if err := netlink.lockPathMTU(link.Index, address.Addr(), lockedPathMTU, rule.table); err != nil {
				t.Fatalf("lock the path MTU to %s in table %d: %v", address.Addr(), rule.table, err)
			}
		}
	}
	return far, link
}

// the near end's addresses, then the far end's, one of each family on the same prefixes
// the near end also holds steeredSources, which a rule routes by
var (
	nearAddresses  = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64")}
	steeredSources = []netip.Prefix{netip.MustParsePrefix("192.0.2.3/24"), netip.MustParsePrefix("2001:db8::3/64")}
	farAddresses   = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24"), netip.MustParsePrefix("2001:db8::2/64")}
)

// handedConn stands between a socket and linux and logs each message it hands over, with the errno linux refused it with
type handedConn struct {
	conn   udpBatchConn
	handed []triedMessage
}

// WriteBatch logs the messages sendmmsg took, and the first of them when it answers an error, the only one an error is about
// a message refused after others went ends a short count instead, and the next call hands it over again
func (c *handedConn) WriteBatch(messages []ipv4.Message, flags int) (int, error) {
	n, err := c.conn.WriteBatch(messages, flags)
	for i := range max(n, 0) {
		c.handed = append(c.handed, handedMessage(&messages[i], 0))
	}
	if err != nil {
		errno, _ := errors.AsType[unix.Errno](err)
		c.handed = append(c.handed, handedMessage(&messages[0], errno))
	}
	return n, err
}

func handedMessage(m *ipv4.Message, errno unix.Errno) triedMessage {
	_, _, pinned, segment := parseSendControl(m.OOB)
	return triedMessage{pinned: pinned, segment: segment, size: len(m.Buffers[0]), errno: errno}
}

// listenHanded opens a bind with mark whose sockets hand their messages over through a log of each, in the order of farAddresses
func listenHanded(t *testing.T, mark uint32, events *eventLog) (*udpBind, []*handedConn) {
	t.Helper()
	opened, _, _, err := listenPacketBind(0, mark, events.record)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	bind := opened.(*udpBind)
	var logs []*handedConn
	for _, socket := range []*udpSocket{bind.v4, bind.v6} {
		log := &handedConn{conn: socket.pc}
		socket.pc = log
		logs = append(logs, log)
	}
	return bind, logs
}

// arrival is a datagram as the far end read it, the number it carries and its size
type arrival struct {
	number uint32
	size   int
}

// arrivals reads listener until the sentinel arrives and returns what arrived before it in the order of the numbers carried
func arrivals(t *testing.T, listener *net.UDPConn) []arrival {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	var got []arrival
	buf := make([]byte, 2048)
	for {
		n, err := listener.Read(buf)
		if err != nil {
			t.Fatalf("%d datagrams arrived and then not the sentinel: %v", len(got), err)
		}
		number := binary.BigEndian.Uint32(buf)
		if number == sentinel {
			slices.SortFunc(got, func(a, b arrival) int { return cmp.Compare(a.number, b.number) })
			return got
		}
		got = append(got, arrival{number, n})
	}
}

// farEnd is the peer's half of the veth pair, listening in a network namespace of its own
type farEnd struct {
	// listeners hold one socket of each family, in the order of farAddresses
	listeners []*net.UDPConn
	// snmp and snmp6 are the namespace's IP counters of each family, opened from within it
	snmp, snmp6 *os.File
	err         error
}

func (f farEnd) close() {
	for _, listener := range f.listeners {
		_ = listener.Close()
	}
	for _, counters := range []*os.File{f.snmp, f.snmp6} {
		if counters != nil {
			_ = counters.Close()
		}
	}
}

// reassembled reads how many datagrams of each family the far end put back together from fragments
// /proc/net/snmp gives each protocol a line of names and then a line of values, and /proc/net/snmp6 each counter a line
func (f farEnd) reassembled() (ipv4, ipv6 uint64, err error) {
	var read [2]string
	for i, counters := range []*os.File{f.snmp, f.snmp6} {
		if _, err := counters.Seek(0, io.SeekStart); err != nil {
			return 0, 0, err
		}
		text, err := io.ReadAll(counters)
		if err != nil {
			return 0, 0, err
		}
		read[i] = string(text)
	}
	found := 0
	lines := strings.Split(read[0], "\n")
	for i := 0; i+1 < len(lines); i++ {
		names, ok := strings.CutPrefix(lines[i], "Ip: ")
		if !ok {
			continue
		}
		values := strings.Fields(strings.TrimPrefix(lines[i+1], "Ip: "))
		if at := slices.Index(strings.Fields(names), "ReasmOKs"); at >= 0 && at < len(values) {
			if ipv4, err = strconv.ParseUint(values[at], 10, 64); err != nil {
				return 0, 0, err
			}
			found++
		}
		break
	}
	for line := range strings.Lines(read[1]) {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "Ip6ReasmOKs" {
			if ipv6, err = strconv.ParseUint(fields[1], 10, 64); err != nil {
				return 0, 0, err
			}
			found++
		}
	}
	if found != 2 {
		return 0, 0, errors.New("the far end's counters name no reassembled datagrams of one family")
	}
	return ipv4, ipv6, nil
}

// openFarEnd makes the veth pair in a network namespace of its own and hands the near end to the namespace near names
// it locks its thread and never unlocks it, and the runtime retires the thread with the goroutine
// nothing else runs in the namespace, which lives on in the listeners' sockets
func openFarEnd(near int) farEnd {
	runtime.LockOSThread()
	if err := unshareEmptyNamespace(); err != nil {
		return farEnd{err: err}
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		return farEnd{err: err}
	}
	defer netlink.close()
	peer := slices.Concat(linkMessage(0, 0), attribute(unix.IFLA_IFNAME, cString("near")), attribute(unix.IFLA_NET_NS_FD, word(uint32(near))))
	kind := slices.Concat(attribute(unix.IFLA_INFO_KIND, cString("veth")), attribute(unix.IFLA_INFO_DATA, attribute(vethInfoPeer, peer)))
	pair := slices.Concat(linkMessage(0, 0), attribute(unix.IFLA_IFNAME, cString("far")), attribute(unix.IFLA_LINKINFO, kind))
	if err := netlink.request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, pair); err != nil {
		return farEnd{err: fmt.Errorf("make the veth pair: %w", err)}
	}
	link, err := net.InterfaceByName("far")
	if err != nil {
		return farEnd{err: fmt.Errorf("look up the far end: %w", err)}
	}
	if err := netlink.configure(link.Index, farAddresses); err != nil {
		return farEnd{err: fmt.Errorf("configure the far end: %w", err)}
	}
	var end farEnd
	for _, network := range []string{"udp4", "udp6"} {
		listener, err := net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			end.close()
			return farEnd{err: fmt.Errorf("listen on the far end: %w", err)}
		}
		end.listeners = append(end.listeners, listener)
	}
	// a counter file keeps to the namespace of the thread that opened it, this one
	if end.snmp, err = os.Open("/proc/thread-self/net/snmp"); err == nil {
		end.snmp6, err = os.Open("/proc/thread-self/net/snmp6")
	}
	if err != nil {
		end.close()
		return farEnd{err: fmt.Errorf("open the far end's counters: %w", err)}
	}
	return end
}

// unshareEmptyNamespace moves the calling thread, which its caller locked, into a new network namespace
// and refuses to go on unless the namespace changed and holds no route
func unshareEmptyNamespace() error {
	before, err := namespaceOf()
	if err != nil {
		return err
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare a network namespace: %w", err)
	}
	after, err := namespaceOf()
	if err != nil {
		return err
	}
	if after == before {
		return errors.New("refusing to continue: the network namespace did not change")
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("dump the routes of the new namespace: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return fmt.Errorf("parse the route dump: %w", err)
	}
	for _, message := range messages {
		if message.Header.Type == syscall.RTM_NEWROUTE {
			return errors.New("refusing to continue: this network namespace already holds routes")
		}
	}
	return nil
}

// namespaceOf is the inode of the calling thread's network namespace
func namespaceOf() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return 0, fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	return st.Ino, nil
}

// routeNetlink is a route netlink socket in the network namespace of the thread that opened it
type routeNetlink int

func openRouteNetlink() (routeNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("open route netlink: %w", err)
	}
	return routeNetlink(fd), nil
}

func (n routeNetlink) close() { _ = unix.Close(int(n)) }

// request sends one message and answers the error the kernel acknowledged it with
func (n routeNetlink) request(kind, flags uint16, body []byte) error {
	message := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	message = append(message, body...)
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint16(message[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	if err := unix.Sendto(int(n), message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	reply := make([]byte, os.Getpagesize())
	got, _, err := unix.Recvfrom(int(n), reply, 0)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseNetlinkMessage(reply[:got])
	if err != nil {
		return err
	}
	if len(messages) != 1 || messages[0].Header.Type != unix.NLMSG_ERROR || len(messages[0].Data) < 4 {
		return errors.New("the kernel answered with something other than an acknowledgment")
	}
	if errno := -int32(binary.NativeEndian.Uint32(messages[0].Data)); errno != 0 {
		return unix.Errno(errno)
	}
	return nil
}

// configure gives link index its addresses without duplicate address detection, then brings it up
func (n routeNetlink) configure(index int, addresses []netip.Prefix) error {
	for _, address := range addresses {
		header := []byte{addressFamily(address.Addr()), byte(address.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
		binary.NativeEndian.PutUint32(header[4:], uint32(index))
		raw := address.Addr().AsSlice()
		body := slices.Concat(header, attribute(unix.IFA_LOCAL, raw), attribute(unix.IFA_ADDRESS, raw))
		if err := n.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
			return fmt.Errorf("add %s: %w", address, err)
		}
	}
	return n.request(unix.RTM_NEWLINK, 0, linkMessage(index, unix.IFF_UP))
}

// lockPathMTU routes to an address over link index in table with a path MTU that path MTU discovery cannot change
func (n routeNetlink) lockPathMTU(index int, to netip.Addr, mtu int, table uint32) error {
	scope := byte(unix.RT_SCOPE_UNIVERSE)
	if to.Is4() {
		scope = unix.RT_SCOPE_LINK
	}
	header := []byte{addressFamily(to), byte(to.BitLen()), 0, 0, byte(table), unix.RTPROT_BOOT, scope, unix.RTN_UNICAST, 0, 0, 0, 0}
	metrics := slices.Concat(attribute(unix.RTAX_MTU, word(uint32(mtu))), attribute(unix.RTAX_LOCK, word(1<<unix.RTAX_MTU)))
	body := slices.Concat(header, attribute(unix.RTA_DST, to.AsSlice()), attribute(unix.RTA_OIF, word(uint32(index))),
		attribute(unix.RTA_METRICS, metrics))
	return n.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// steer adds a rule of family, at table's number as its priority, that looks up in table what match and a source prefix of sourceBits select
func (n routeNetlink) steer(family byte, table uint32, sourceBits int, match []byte) error {
	header := []byte{family, 0, byte(sourceBits), 0, byte(table), 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	body := slices.Concat(header, attribute(unix.FRA_PRIORITY, word(table)), attribute(unix.FRA_TABLE, word(table)), match)
	return n.request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// linkMessage is an ifinfomsg for link index that sets flags and changes nothing else
func linkMessage(index int, flags uint32) []byte {
	message := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(message[4:], uint32(index))
	binary.NativeEndian.PutUint32(message[8:], flags)
	binary.NativeEndian.PutUint32(message[12:], flags)
	return message
}

func attribute(kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	encoded := make([]byte, (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(encoded[0:], uint16(length))
	binary.NativeEndian.PutUint16(encoded[2:], kind)
	copy(encoded[unix.SizeofRtAttr:], value)
	return encoded
}

func word(value uint32) []byte { return binary.NativeEndian.AppendUint32(nil, value) }

func cString(value string) []byte { return append([]byte(value), 0) }

func addressFamily(address netip.Addr) byte {
	if address.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
