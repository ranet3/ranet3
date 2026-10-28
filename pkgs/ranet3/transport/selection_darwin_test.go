// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testSelection names one interface for every address, under a generation each move advances
type testSelection struct {
	mu         sync.Mutex
	index      int
	generation uint64
	// asked counts the calls of Interface
	asked atomic.Int64
}

func newTestSelection(index int) *testSelection {
	return &testSelection{index: index, generation: 1}
}

func (s *testSelection) Interface(netip.Addr) (int, uint64) {
	s.asked.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.index, s.generation
}

func (s *testSelection) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// move names index from the next generation on
func (s *testSelection) move(index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index = index
	s.generation++
}

var _ Selection = (*testSelection)(nil)

// loopbackFamilies are the two families a unit test sends in over lo0
var loopbackFamilies = []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}}

// a selection that names no interface for a peer refuses its datagrams with ENETUNREACH and writes none
// as a marked lookup that ends in an empty main does on linux, and opens no pair to it
func TestDarwinSendWithNoSelectedInterfaceIsRefused(t *testing.T) {
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			hub, err := NewHub(":0", Underlay{}, Runtime{Selection: newTestSelection(0)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := listenPeer(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr)
			mux, err := hub.NewMux(at.IP, at.Port)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("named no interface")
			if err := hub.bind.Send([][]byte{payload}, mux.Endpoint()); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("the shared socket's send to %s answered %v, want ENETUNREACH", at, err)
			}
			if openNow(mux).socket.Load() != nil {
				t.Errorf("a pair opened to %s, which the selection names no interface for", at)
			}
			if err := mux.send([][]byte{payload}, mux.Endpoint()); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("the mux's send to %s answered %v, want ENETUNREACH", at, err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(pairQuiet)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, readBufferSize)
			if n, from, err := peer.ReadFromUDPAddrPort(buf); err == nil {
				t.Errorf("the peer read %q from %s", buf[:n], from)
			}
		})
	}
}

// a hub with no selection, as on iOS, names no interface
// its unpinned datagrams carry no packet info and arrive, and its pairs are keyed to no interface
func TestDarwinHubWithNoSelectionNamesNothing(t *testing.T) {
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			hub, err := NewHub(":0", Underlay{}, Runtime{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := listenPeer(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr)
			mux, err := hub.NewMux(at.IP, at.Port)
			if err != nil {
				t.Fatal(err)
			}
			bind := hub.bind.(*darwinBind)
			ep := mux.Endpoint().(*darwinEndpoint)
			socket := bind.v4
			if ep.addr.Addr().Is6() {
				socket = bind.v6
			}
			if control, generation, err := bind.selectedControl(socket, ep); control != nil || generation != 0 || err != nil {
				t.Errorf("a send to %s from a hub with no selection carries %x under generation %d, %v, want no control message", at, control, generation, err)
			}
			if k := bind.pairOf(ep); k.index != 0 {
				t.Errorf("the pair to %s from a hub with no selection is keyed to interface %d", at, k.index)
			}
			payload := []byte("named nothing")
			if err := hub.bind.Send([][]byte{payload}, ep); err != nil {
				t.Fatal(err)
			}
			readFrom(t, peer, payload)
		})
	}
}

// the control naming the selected interface is built once per endpoint and generation, names the interface and no source
// and the shared socket releases its cached route once a generation
func TestDarwinSelectedControlIsBuiltOncePerGeneration(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			selection := newTestSelection(loopback.Index)
			hub, err := NewHub(":0", Underlay{}, Runtime{Selection: selection})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := listenPeer(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr)
			mux, err := hub.NewMux(at.IP, at.Port)
			if err != nil {
				t.Fatal(err)
			}
			bind := hub.bind.(*darwinBind)
			ep := mux.Endpoint().(*darwinEndpoint)
			socket := bind.v4
			if ep.addr.Addr().Is6() {
				socket = bind.v6
			}
			send := func(payload string) {
				t.Helper()
				if err := hub.bind.Send([][]byte{[]byte(payload)}, ep); err != nil {
					t.Fatalf("send %q to %s naming lo0: %v", payload, at, err)
				}
				readFrom(t, peer, []byte(payload))
			}
			for _, payload := range []string{"first", "second", "third"} {
				send(payload)
			}
			if asked := selection.asked.Load(); asked != 1 {
				t.Errorf("three sends under one generation asked the selection %d times, want once", asked)
			}
			selected := ep.selected.Load()
			if selected == nil {
				t.Fatalf("the endpoint keeps no selection after a send")
			}
			source, index, fragments, err := sentPin(selected.control)
			if err != nil || index != loopback.Index || source.IsValid() && !source.IsUnspecified() || fragments {
				t.Errorf("the control names %s at interface %d, fragmenting %v, %v, want no source at lo0's %d", source, index, fragments, err, loopback.Index)
			}
			if released := socket.released.Load(); released != 1 {
				t.Errorf("the socket released its route at generation %d, want 1", released)
			}
			selection.move(loopback.Index)
			send("after the move")
			if asked := selection.asked.Load(); asked != 2 {
				t.Errorf("a send under a new generation left the selection asked %d times, want twice", asked)
			}
			if selected := ep.selected.Load(); selected.generation != 2 {
				t.Errorf("the endpoint keeps the selection of generation %d, want 2", selected.generation)
			}
			if released := socket.released.Load(); released != 2 {
				t.Errorf("the socket released its route at generation %d, want 2", released)
			}
		})
	}
}

// an endpoint's selection is recorded when it is first resolved and each time it names another interface,
// with an empty name and index zero where it names none, and a new generation naming the same interface records nothing
func TestDarwinSelectionIsRecordedOncePerChange(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			selection := newTestSelection(loopback.Index)
			log := &eventLog{}
			hub, err := NewHub(":0", Underlay{}, Runtime{Selection: selection, Events: log.record})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := listenPeer(t, family.network, family.loopback)
			ep, err := hub.bind.ParseEndpoint(peer.LocalAddr().(*net.UDPAddr).AddrPort().String())
			if err != nil {
				t.Fatal(err)
			}
			// a send the selection names no interface for is refused, and its answer is recorded all the same
			_ = hub.bind.Send([][]byte{[]byte("selected")}, ep)
			for _, index := range []int{loopback.Index, loopback.Index, 0, 0, loopback.Index} {
				selection.move(index)
				_ = hub.bind.Send([][]byte{[]byte("selected")}, ep)
			}
			named := fmt.Sprintf("transport.underlay.selected endpoint=%s interface=lo0 interface_index=%d", ep, loopback.Index)
			unnamed := fmt.Sprintf("transport.underlay.selected endpoint=%s interface= interface_index=0", ep)
			if got, want := log.recorded(), []string{named, unnamed, named}; !slices.Equal(got, want) {
				t.Errorf("six generations naming lo0, lo0, lo0, nothing, nothing and lo0 recorded %q, want %q", got, want)
			}
		})
	}
}

// the path a hub gives for an endpoint keeps a link-local endpoint's zone for the selection to answer, names the interface
// holding a pin, a link-local pin's arrival interface or the one holding the pin's address, and leaves a pin no interface
// holds to the selection, as the sends do, and a hub with no selection gives none
func TestDarwinUnderlayPathIsWhereTheDatagramsLeave(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	hub := selectedHub(t, newTestSelection(loopback.Index))
	zoned, err := hub.bind.ParseEndpoint("[fe80::9%lo0]:4500")
	if err != nil {
		t.Fatal(err)
	}
	peer, linkLocal := netip.MustParseAddrPort("198.51.100.9:4500"), netip.MustParseAddrPort("[fe80::9%lo0]:4500")
	for _, test := range []struct {
		name     string
		endpoint Endpoint
		want     UnderlayPath
	}{
		{"a link-local endpoint", zoned, UnderlayPath{Address: linkLocal.Addr()}},
		{"a pin lo0 holds", pinnedEndpoint(peer, netip.MustParseAddr("127.0.0.1"), 0), UnderlayPath{Address: peer.Addr(), Pin: "lo0"}},
		{"a link-local pin", pinnedEndpoint(linkLocal, netip.MustParseAddr("fe80::1"), loopback.Index), UnderlayPath{Address: linkLocal.Addr(), Pin: "lo0"}},
		{"a pin no interface holds", pinnedEndpoint(peer, netip.MustParseAddr("198.51.100.77"), 0), UnderlayPath{Address: peer.Addr()}},
	} {
		if got, ok := hub.SendsBy(test.endpoint); !ok || got != test.want {
			t.Errorf("%s leaves by %+v, %v, want %+v", test.name, got, ok, test.want)
		}
	}
	unselected, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unselected.Close() })
	if got, ok := unselected.SendsBy(zoned); ok {
		t.Errorf("a hub with no selection gives the path %+v", got)
	}
}

const (
	// utunControl is the kernel control a utun is made through
	utunControl = "com.apple.net.utun_control"
	// sysprotoControl and utunOptIfname are SYSPROTO_CONTROL and UTUN_OPT_IFNAME, which golang.org/x/sys/unix does not carry
	sysprotoControl = 2
	utunOptIfname   = 2
	// utunHeader is the address family a utun's descriptor puts before each packet
	utunHeader = 4
	// tunWait bounds the retries of a utun the kernel answers busy for
	tunWait = 5 * time.Second
	// tunPoll is how often a read of a utun's descriptor looks again
	tunPoll = 2 * time.Millisecond
	// tunQuiet is how long a utun carries nothing before a test takes it that nothing left by it
	tunQuiet = 200 * time.Millisecond
	// underlayPort is the port every peer behind a test utun is sent to
	underlayPort = 4500
)

// testTUN is a utun a test makes, and the control descriptor every packet the kernel routes out of it is read from
type testTUN struct {
	name   string
	index  int
	fd     int
	v4, v6 netip.Addr
	once   sync.Once
}

// openUTUN makes a utun and answers its control descriptor
func openUTUN() (int, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return -1, err
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	// unit 0 takes the first free utun, never one another program holds
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// newTestTUN makes a utun holding v4 and v6, whose removal with every route and address on it the test's end or destroy does
func newTestTUN(t *testing.T, v4, v6 string) *testTUN {
	t.Helper()
	fd, err := openUTUN()
	for deadline := time.Now().Add(tunWait); errors.Is(err, unix.EBUSY) && time.Now().Before(deadline); fd, err = openUTUN() {
		time.Sleep(tunPoll)
	}
	if err != nil {
		t.Fatalf("make a utun: %v", err)
	}
	u := &testTUN{fd: fd, v4: netip.MustParseAddr(v4), v6: netip.MustParseAddr(v6)}
	t.Cleanup(u.destroy)
	if u.name, err = unix.GetsockoptString(fd, sysprotoControl, utunOptIfname); err != nil {
		t.Fatalf("read the name of a new utun: %v", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	// a utun is point to point, so its IPv4 address is its own destination
	hostCommand(t, "ifconfig", u.name, "inet", v4, v4, "netmask", "255.255.255.255", "up")
	hostCommand(t, "ifconfig", u.name, "inet6", v6, "prefixlen", "64")
	waitDAD(t, u.name)
	link, err := net.InterfaceByName(u.name)
	if err != nil {
		t.Fatal(err)
	}
	u.index = link.Index
	t.Logf("made %s, index %d, holding %s and %s", u.name, u.index, u.v4, u.v6)
	return u
}

// destroy removes u with every route and address on it
func (u *testTUN) destroy() { u.once.Do(func() { _ = unix.Close(u.fd) }) }

// route adds a route to destination out of u, scoped to u where scoped is set, and answers its removal, which the test's end runs too
func (u *testTUN) route(t *testing.T, destination string, scoped bool) func() {
	t.Helper()
	family := "-inet"
	if netip.MustParsePrefix(destination).Addr().Is6() {
		family = "-inet6"
	}
	args := []string{family, "-net", destination, "-interface", u.name}
	if scoped {
		args = append(args, "-ifscope", u.name)
	}
	hostCommand(t, append([]string{"route", "-n", "add"}, args...)...)
	var once sync.Once
	remove := func() {
		once.Do(func() { _ = exec.Command("route", append([]string{"-n", "delete"}, args...)...).Run() })
	}
	t.Cleanup(remove)
	return remove
}

// drain reads every packet u holds
func (u *testTUN) drain() {
	buf := make([]byte, readBufferSize)
	for {
		if _, err := unix.Read(u.fd, buf); err != nil {
			return
		}
	}
}

// datagram is a UDP datagram to one address and port carrying one payload
type datagram struct {
	to      netip.AddrPort
	payload []byte
}

// in answers whether packet is an IP packet carrying d
// a packet is matched on its destination and payload, never taken for d by its place in the queue
func (d datagram) in(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	var header int
	var to netip.Addr
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || packet[9] != unix.IPPROTO_UDP {
			return false
		}
		header, to = int(packet[0]&0x0f)*4, netip.AddrFrom4([4]byte(packet[16:20]))
	case 6:
		if len(packet) < 40 || packet[6] != unix.IPPROTO_UDP {
			return false
		}
		header, to = 40, netip.AddrFrom16([16]byte(packet[24:40]))
	default:
		return false
	}
	if len(packet) < header+8 || to != d.to.Addr() || binary.BigEndian.Uint16(packet[header+2:]) != d.to.Port() {
		return false
	}
	return bytes.Equal(packet[header+8:], d.payload)
}

// carried reads u for at most within, until a packet carrying one of datagrams comes out
func (u *testTUN) carried(within time.Duration, datagrams ...datagram) bool {
	buf := make([]byte, readBufferSize)
	for deadline := time.Now().Add(within); time.Now().Before(deadline); {
		n, err := unix.Read(u.fd, buf)
		if err != nil || n <= utunHeader {
			time.Sleep(tunPoll)
			continue
		}
		for _, d := range datagrams {
			if d.in(buf[utunHeader:n]) {
				return true
			}
		}
	}
	return false
}

// leftBy asserts that d came out of want and out of none of others
func leftBy(t *testing.T, d datagram, want *testTUN, others ...*testTUN) {
	t.Helper()
	if !want.carried(arrivalBudget, d) {
		t.Errorf("%q to %s never came out of %s", d.payload, d.to, want.name)
	}
	for _, other := range others {
		if other.carried(tunQuiet, d) {
			t.Errorf("%q to %s came out of %s", d.payload, d.to, other.name)
		}
	}
}

// drainAll drains each of tuns, so a read finds only what a send after it put there
func drainAll(tuns ...*testTUN) {
	for _, u := range tuns {
		u.drain()
	}
}

// the addresses the test utuns hold: U stands in for an uplink, U2 for a second one and M for ranet3's own tun
const (
	uplinkV4, uplinkV6 = "198.51.100.1", "2001:db8:a::1"
	secondV4, secondV6 = "198.51.100.2", "2001:db8:b::1"
	meshV4, meshV6     = "192.0.2.1", "2001:db8:c::1"
)

// underlayFamilies are the peers behind U in each family and the routes that hold them
var underlayFamilies = []struct {
	name string
	// peer and neighbor are two peers inside narrow, which is inside wide
	peer, neighbor netip.Addr
	narrow, wide   string
	// gone is an address no interface holds, a pin the kernel refuses
	gone netip.Addr
	// cover is the zero-free cover an exit default goes in as, holding every address but the zero one
	cover []string
	// unrouted is the errno darwin answers a send naming an interface that holds no route to the peer with
	// in_pcbladdr in bsd/netinet/in_pcb.c answers ENETUNREACH, and selectroute in bsd/netinet6/in6_src.c EHOSTUNREACH
	unrouted unix.Errno
}{
	{
		name: "IPv4", peer: netip.MustParseAddr("203.0.113.9"), neighbor: netip.MustParseAddr("203.0.113.10"),
		narrow: "203.0.113.0/25", wide: "203.0.113.0/24", gone: netip.MustParseAddr("198.51.100.77"),
		cover:    []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"},
		unrouted: unix.ENETUNREACH,
	},
	{
		name: "IPv6", peer: netip.MustParseAddr("2001:db8:e::9"), neighbor: netip.MustParseAddr("2001:db8:e::a"),
		narrow: "2001:db8:e::/64", wide: "2001:db8:e::/48", gone: netip.MustParseAddr("2001:db8:a::77"),
		cover:    []string{"100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1"},
		unrouted: unix.EHOSTUNREACH,
	},
}

// selectedHub is a hub whose sends name the interface selection answers
func selectedHub(t *testing.T, selection Selection) *Hub {
	t.Helper()
	hub, err := NewHub(":0", Underlay{}, Runtime{Selection: selection})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	return hub
}

// muxTo is a mux of hub to peer at underlayPort
func muxTo(t *testing.T, hub *Hub, peer netip.Addr) *Mux {
	t.Helper()
	mux, err := hub.NewMux(peer.AsSlice(), underlayPort)
	if err != nil {
		t.Fatal(err)
	}
	return mux
}

// every datagram to a peer the selection names U for leaves U, past a route on M that an unnamed send would take
// U holds the peer's route scoped to it, as macOS scopes the routes of each uplink but the primary one
// M holds either a route less specific than U's or the zero-free cover
// the arms are the shared socket, an endpoint whose pin the kernel refuses, and a pair, in both families
func TestDarwinUnderlayLeavesTheSelectedInterface(t *testing.T) {
	requireHostNet(t, "test utuns")
	u, m := newTestTUN(t, uplinkV4, uplinkV6), newTestTUN(t, meshV4, meshV6)
	for _, family := range underlayFamilies {
		for _, mesh := range []struct {
			name   string
			routes []string
		}{
			{"a less specific route on M", []string{family.wide}},
			{"the zero-free cover on M", family.cover},
		} {
			t.Run(family.name+", "+mesh.name, func(t *testing.T) {
				u.route(t, family.narrow, true)
				for _, destination := range mesh.routes {
					m.route(t, destination, false)
				}
				hub := selectedHub(t, newTestSelection(u.index))
				peer, neighbor := netip.AddrPortFrom(family.peer, underlayPort), netip.AddrPortFrom(family.neighbor, underlayPort)

				// the pinned send comes first, on a socket that has cached no route to the peer
				// ip_output in bsd/netinet/ip_output.c checks an IPv4 source only where the socket's cached route was not yet chosen for a source under the routing table's generation
				refused := datagram{peer, []byte(family.name + ", " + mesh.name + ", a refused pin")}
				pinned := pinnedEndpoint(peer, family.gone, 0)
				drainAll(u, m)
				if err := hub.bind.Send([][]byte{refused.payload}, pinned); err != nil {
					t.Fatalf("the send to %s pinned to %s, which no interface holds: %v", peer, family.gone, err)
				}
				if !pinned.unpinned.Load() {
					t.Errorf("the send to %s kept the pin %s, which no interface holds", peer, family.gone)
				}
				leftBy(t, refused, u, m)

				// to an address inside narrow no earlier send reached, so the send rides no route the socket cached for another
				alone := netip.AddrPortFrom(family.neighbor.Next(), underlayPort)
				shared := datagram{alone, []byte(family.name + ", " + mesh.name + ", the shared socket")}
				ep, err := hub.bind.ParseEndpoint(alone.String())
				if err != nil {
					t.Fatal(err)
				}
				drainAll(u, m)
				if err := hub.bind.Send([][]byte{shared.payload}, ep); err != nil {
					t.Fatalf("the shared socket's send to %s: %v", alone, err)
				}
				leftBy(t, shared, u, m)

				paired := datagram{neighbor, []byte(family.name + ", " + mesh.name + ", a pair")}
				mux := muxTo(t, hub, family.neighbor)
				if openNow(mux).socket.Load() == nil {
					t.Fatalf("the pair to %s opened no socket", neighbor)
				}
				drainAll(u, m)
				if err := mux.send([][]byte{paired.payload}, mux.Endpoint()); err != nil {
					t.Fatalf("the pair's send to %s: %v", neighbor, err)
				}
				leftBy(t, paired, u, m)
				if fallbacks := hub.PairFallbacks(); fallbacks != 0 {
					t.Errorf("the pair to %s fell back %d times", neighbor, fallbacks)
				}
			})
		}
	}
}

// once the peer's route moves from U to U2 and the selection follows, every datagram leaves U2, on the shared socket and on the pair
// U keeps a route to the peer scoped to it, and the one peer on the shared socket last left U from a send in the settle
// the socket's route the kernel cached then would take a later send naming U2 to U, in_pcbladdr in bsd/netinet/in_pcb.c
func TestDarwinUnderlayFollowsTheSelection(t *testing.T) {
	requireHostNet(t, "test utuns")
	u, u2 := newTestTUN(t, uplinkV4, uplinkV6), newTestTUN(t, secondV4, secondV6)
	for _, family := range underlayFamilies {
		t.Run(family.name, func(t *testing.T) {
			u.route(t, family.wide, true)
			held := u.route(t, family.wide, false)
			selection := newTestSelection(u.index)
			hub := selectedHub(t, selection)
			peer, neighbor := netip.AddrPortFrom(family.peer, underlayPort), netip.AddrPortFrom(family.neighbor, underlayPort)
			ep, err := hub.bind.ParseEndpoint(peer.String())
			if err != nil {
				t.Fatal(err)
			}
			mux := muxTo(t, hub, family.neighbor)
			if openNow(mux).socket.Load() == nil {
				t.Fatalf("the pair to %s opened no socket", neighbor)
			}
			send := func(step string, want, other *testTUN) {
				t.Helper()
				d := datagram{peer, []byte(family.name + ", the shared socket, " + step)}
				drainAll(u, u2)
				if err := hub.bind.Send([][]byte{d.payload}, ep); err != nil {
					t.Fatalf("the shared socket's send to %s %s: %v", peer, step, err)
				}
				leftBy(t, d, want, other)
			}
			send("before the move", u, u2)
			held()
			u2.route(t, family.wide, false)
			send("in the settle", u, u2)
			selection.move(u2.index)
			send("after the move", u2, u)

			paired := datagram{neighbor, []byte(family.name + ", the pair, after the move")}
			if openNow(mux).socket.Load() == nil {
				t.Fatalf("the pair to %s opened no socket after the move", neighbor)
			}
			drainAll(u, u2)
			if err := mux.send([][]byte{paired.payload}, mux.Endpoint()); err != nil {
				t.Fatalf("the pair's send to %s after the move: %v", neighbor, err)
			}
			leftBy(t, paired, u2, u)
			if open := hub.PairSockets(); open != 1 {
				t.Errorf("the hub holds %d sockets connected to one peer after the move, want the new pair's alone", open)
			}
		})
	}
}

// a send that built its control under one generation and reaches the socket after a send of the next released its route
// leaves by the interface it names, and the next generation's send after it leaves by the new interface, not by the route the late send cached
// the two sends are ordered by hand, as two muxes racing a selection change order them, both naming the peer on a route scoped to its interface
func TestDarwinUnderlayReleasesTheRouteALateSendCached(t *testing.T) {
	requireHostNet(t, "test utuns")
	u, u2 := newTestTUN(t, uplinkV4, uplinkV6), newTestTUN(t, secondV4, secondV6)
	for _, family := range underlayFamilies {
		t.Run(family.name, func(t *testing.T) {
			u.route(t, family.wide, true)
			u2.route(t, family.wide, true)
			selection := newTestSelection(u.index)
			hub := selectedHub(t, selection)
			bind := hub.bind.(*darwinBind)
			peer := netip.AddrPortFrom(family.peer, underlayPort)
			parsed, err := bind.ParseEndpoint(peer.String())
			if err != nil {
				t.Fatal(err)
			}
			ep := parsed.(*darwinEndpoint)
			socket := bind.v4
			if family.peer.Is6() {
				socket = bind.v6
			}
			late, lateGeneration, err := bind.selectedControl(socket, ep)
			if err != nil {
				t.Fatal(err)
			}
			selection.move(u2.index)
			next, nextGeneration, err := bind.selectedControl(socket, ep)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range []struct {
				name        string
				control     []byte
				generation  uint64
				want, other *testTUN
			}{
				{"the late send", late, lateGeneration, u, u2},
				{"the next generation's send", next, nextGeneration, u2, u},
			} {
				d := datagram{peer, []byte(family.name + ", " + step.name)}
				drainAll(u, u2)
				if err := socket.writeSelected(d.payload, ep, step.control, step.generation); err != nil {
					t.Fatalf("%s to %s under generation %d: %v", step.name, peer, step.generation, err)
				}
				leftBy(t, d, step.want, step.other)
			}
		})
	}
}

// goneErrnos answer a send scoped to an interface that is gone
// ENXIO for packet info naming its index, ENETUNREACH and EADDRNOTAVAIL for a socket scoped to it, unconnected and connected
var goneErrnos = []unix.Errno{unix.ENXIO, unix.ENETUNREACH, unix.EADDRNOTAVAIL}

func goneError(err error) bool {
	for _, errno := range goneErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// once U is gone under a pair and the shared socket, both refuse their sends, the pair falls back and nothing reaches M
// M holds the zero-free cover, which an unnamed send would take
func TestDarwinUnderlaySendsNothingOnceItsInterfaceIsGone(t *testing.T) {
	requireHostNet(t, "test utuns")
	m := newTestTUN(t, meshV4, meshV6)
	for _, family := range underlayFamilies {
		t.Run(family.name, func(t *testing.T) {
			u := newTestTUN(t, uplinkV4, uplinkV6)
			u.route(t, family.wide, false)
			for _, destination := range family.cover {
				m.route(t, destination, false)
			}
			hub := selectedHub(t, newTestSelection(u.index))
			peer, neighbor := netip.AddrPortFrom(family.peer, underlayPort), netip.AddrPortFrom(family.neighbor, underlayPort)
			ep, err := hub.bind.ParseEndpoint(peer.String())
			if err != nil {
				t.Fatal(err)
			}
			mux := muxTo(t, hub, family.neighbor)
			if openNow(mux).socket.Load() == nil {
				t.Fatalf("the pair to %s opened no socket", neighbor)
			}
			u.destroy()
			drainAll(m)
			shared := datagram{peer, []byte(family.name + ", the shared socket, U gone")}
			if err := hub.bind.Send([][]byte{shared.payload}, ep); !goneError(err) {
				t.Errorf("the shared socket's send to %s with U gone answered %v, want one of %v", peer, err, goneErrnos)
			}
			paired := datagram{neighbor, []byte(family.name + ", the pair, U gone")}
			if err := mux.send([][]byte{paired.payload}, mux.Endpoint()); !goneError(err) {
				t.Errorf("the pair's send to %s with U gone answered %v, want one of %v", neighbor, err, goneErrnos)
			}
			if fallbacks, open := hub.PairFallbacks(), hub.PairSockets(); fallbacks != 1 || open != 0 {
				t.Errorf("the hub counts %d fallbacks and holds %d sockets connected to one peer, want the pair dropped once", fallbacks, open)
			}
			if m.carried(tunQuiet, shared, paired) {
				t.Errorf("a datagram to %s or %s came out of M with U gone", peer, neighbor)
			}
		})
	}
}

// a route on M longer than U's holding the peer turns down a send naming U, and nothing reaches M
// rt_lookup_common in bsd/net/route.c drops the unscoped match on another interface and finds no route scoped to U
func TestDarwinUnderlayRefusesAPeerTheMeshShadows(t *testing.T) {
	requireHostNet(t, "test utuns")
	u, m := newTestTUN(t, uplinkV4, uplinkV6), newTestTUN(t, meshV4, meshV6)
	for _, family := range underlayFamilies {
		t.Run(family.name, func(t *testing.T) {
			u.route(t, family.wide, false)
			m.route(t, family.narrow, false)
			hub := selectedHub(t, newTestSelection(u.index))
			peer, neighbor := netip.AddrPortFrom(family.peer, underlayPort), netip.AddrPortFrom(family.neighbor, underlayPort)
			ep, err := hub.bind.ParseEndpoint(peer.String())
			if err != nil {
				t.Fatal(err)
			}
			drainAll(u, m)
			shared := datagram{peer, []byte(family.name + ", the shared socket, shadowed")}
			if err := hub.bind.Send([][]byte{shared.payload}, ep); !errors.Is(err, family.unrouted) {
				t.Errorf("the shared socket's send to %s past a shadow on M answered %v, want %s", peer, err, unix.ErrnoName(family.unrouted))
			}
			mux := muxTo(t, hub, family.neighbor)
			if openNow(mux).socket.Load() != nil {
				t.Errorf("a pair to %s connected past a shadow on M", neighbor)
			}
			paired := datagram{neighbor, []byte(family.name + ", the mux, shadowed")}
			if err := mux.send([][]byte{paired.payload}, mux.Endpoint()); !errors.Is(err, family.unrouted) {
				t.Errorf("the mux's send to %s past a shadow on M answered %v, want %s", neighbor, err, unix.ErrnoName(family.unrouted))
			}
			if m.carried(tunQuiet, shared, paired) {
				t.Errorf("a datagram to %s or %s came out of M", peer, neighbor)
			}
		})
	}
}
