// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"bytes"
	"encoding/binary"
	"maps"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

const (
	// holeDADWait bounds the wait for a test utun's IPv6 address to leave duplicate address detection, and holeDADPoll is how often it looks
	holeDADWait = 5 * time.Second
	holeDADPoll = 50 * time.Millisecond
	// holeArrival bounds the wait for a datagram to come out of a test utun, and holeReadPoll is how often it reads
	holeArrival  = 2 * time.Second
	holeReadPoll = 5 * time.Millisecond
	// holePort is the port every datagram of the test is sent to
	holePort = 4500
	// utunHeader is the address family a utun puts ahead of every packet it hands its descriptor
	utunHeader = 4
)

// holeOverlay holds the mesh route each family's endpoint lies in, so row L6 leaves that route as it is, and a prefix
// inside each family's holding
var holeOverlay = prefixes(prefix("203.0.113.0/24"), prefix("2001:db8:100::/48"), prefix("192.0.2.240/28"), prefix("2001:db8:200:1f0::/60"))

// holeFamilies are one family's routes and addresses each
var holeFamilies = []struct {
	name string
	// wide is U's route inside the overlay and narrow the mesh's inside it, holding peer and neighbor
	wide, narrow   string
	peer, neighbor netip.Addr
	// lan is U's route holding the mesh's routes inLAN, outside the overlay, and holding, which holds a prefix of the
	// overlay. lanTarget lies in inLAN, outside in holding outside the overlay, and inside in the overlay
	lan, inLAN, holding        string
	lanTarget, outside, inside netip.Addr
}{
	{
		name: "IPv4", wide: "203.0.113.0/24", narrow: "203.0.113.0/25",
		peer: netip.MustParseAddr("203.0.113.9"), neighbor: netip.MustParseAddr("203.0.113.10"),
		lan: "192.0.2.0/24", inLAN: "192.0.2.0/25", holding: "192.0.2.128/25",
		lanTarget: netip.MustParseAddr("192.0.2.9"), outside: netip.MustParseAddr("192.0.2.130"), inside: netip.MustParseAddr("192.0.2.241"),
	},
	{
		name: "IPv6", wide: "2001:db8:100::/48", narrow: "2001:db8:100::/56",
		peer: netip.MustParseAddr("2001:db8:100::9"), neighbor: netip.MustParseAddr("2001:db8:100::a"),
		lan: "2001:db8:200::/48", inLAN: "2001:db8:200::/56", holding: "2001:db8:200:100::/56",
		lanTarget: netip.MustParseAddr("2001:db8:200::9"), outside: netip.MustParseAddr("2001:db8:200:100::9"), inside: netip.MustParseAddr("2001:db8:200:1f0::9"),
	},
}

// holeRig is a reconciler on M, a test utun standing in for ranet3's, beside U, one standing in for an uplink whose descriptor the test reads
// listed and sent are the endpoints the reconciler's runtime answers, the trust document's and the live sessions'
type holeRig struct {
	u         *selectTUN
	uFD       int
	m         int
	table     *netstack.RouteTable
	reconcile *Reconciler
	listed    []netip.Addr
	sent      []netip.Addr
	selection *Selection
	// before is each utun's routes before the first pass, and defaults the host's
	before   map[int]map[netip.Prefix]bool
	defaults []string
	stopped  bool
}

func newHoleRig(t *testing.T) *holeRig {
	t.Helper()
	uName, uFD := createUTUNWithFD(t)
	setInterfaceUp(t, uName)
	rig := &holeRig{
		u:     &selectTUN{name: uName, index: interfaceIndex(t, uName), plat: testTUNPlatform(t, uName)},
		uFD:   uFD,
		table: netstack.NewRouteTable(),
	}
	for _, assigned := range []string{"198.51.100.1/26", "2001:db8:aa::1/64"} {
		if err := rig.u.plat.AddAddr(prefix(assigned)); err != nil {
			t.Fatalf("assign %s to %s: %v", assigned, uName, err)
		}
	}
	for _, family := range holeFamilies {
		rig.u.add(t, family.wide, false)
		rig.u.add(t, family.lan, false)
	}
	mName, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mName)
	rig.m = interfaceIndex(t, mName)
	rig.selection = openTestSelection(t, nil, mName)
	reconciler, err := New(Table{ID: DefaultTable, Proto: DefaultProtocol}, rig.runtime(mName), rig.table)
	if err != nil {
		t.Fatal(err)
	}
	rig.reconcile = reconciler
	plat := reconciler.plat.(*routePlatform)
	for _, assigned := range []string{"198.51.100.129/26", "2001:db8:cc::1/64"} {
		if err := plat.AddAddr(prefix(assigned)); err != nil {
			t.Fatalf("assign %s to %s: %v", assigned, mName, err)
		}
	}
	waitHoleDAD(t, uName)
	waitHoleDAD(t, mName)
	rig.before = map[int]map[netip.Prefix]bool{rig.u.index: heldOn(t, rig.u.index), rig.m: heldOn(t, rig.m)}
	rig.defaults = defaultRoutesOnHost(t)
	t.Cleanup(func() {
		if !rig.stopped {
			_ = rig.reconcile.withdraw(nil)
		}
		_ = rig.reconcile.plat.Close()
	})
	return rig
}

// runtime hands the reconciler on mesh the overlay and the endpoints the rig's arm sets
func (rig *holeRig) runtime(mesh string) Runtime {
	return Runtime{
		Interface: mesh,
		Overlay:   holeOverlay,
		Selection: rig.selection,
		Underlay:  func() []netip.Addr { return rig.listed },
		Sends: func() []Send {
			var out []Send
			for _, destination := range rig.sent {
				out = append(out, Send{Destination: destination})
			}
			return out
		},
	}
}

// pass sets the mesh's routes to destinations and runs one pass
func (rig *holeRig) pass(t *testing.T, destinations ...string) {
	t.Helper()
	for _, entry := range rig.table.Snapshot() {
		rig.table.Remove(entry.Source, entry.Destination)
	}
	for _, destination := range destinations {
		rig.table.Set(netip.Prefix{}, prefix(destination), nil)
	}
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
}

// stop withdraws the reconciler and asserts the table is as it was before its first pass, on both utuns but for the kernel's clones and in the host's defaults
func (rig *holeRig) stop(t *testing.T) {
	t.Helper()
	rig.stopped = true
	if err := rig.reconcile.withdraw(nil); err != nil {
		t.Fatal(err)
	}
	for index, before := range rig.before {
		if after := heldOn(t, index); !maps.Equal(before, after) {
			t.Errorf("interface %d holds %v after the reconciler stopped, want %v", index, after, before)
		}
	}
	if after := defaultRoutesOnHost(t); !sameDefaults(rig.defaults, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", rig.defaults, after)
	}
}

// waitHoleDAD waits for every IPv6 address on name to leave duplicate address detection, since a tentative one is no source
func waitHoleDAD(t *testing.T, name string) {
	t.Helper()
	for deadline := time.Now().Add(holeDADWait); ; time.Sleep(holeDADPoll) {
		out, err := exec.Command("ifconfig", name).CombinedOutput()
		if err != nil {
			t.Fatalf("ifconfig %s: %v: %s", name, err, out)
		}
		if !strings.Contains(string(out), "tentative") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("an IPv6 address on %s stayed tentative for %s: %s", name, holeDADWait, out)
		}
	}
}

// sendBound sends payload to target from a socket scoped to index with IP_BOUND_IF or IPV6_BOUND_IF
func sendBound(index int, target netip.Addr, payload []byte) error {
	domain, level, option := unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	var to unix.Sockaddr = &unix.SockaddrInet6{Addr: target.As16(), Port: holePort}
	if target.Is4() {
		domain, level, option = unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
		to = &unix.SockaddrInet4{Addr: target.As4(), Port: holePort}
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, level, option, index); err != nil {
		return err
	}
	return unix.Sendto(fd, payload, 0, to)
}

// carriedOut reads fd for at most holeArrival, until a UDP datagram to target at holePort carrying payload comes out
// a packet is matched on its destination and payload, never taken by its place in the queue
func carriedOut(fd int, target netip.Addr, payload []byte) bool {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	for deadline := time.Now().Add(holeArrival); time.Now().Before(deadline); {
		n, err := unix.Read(fd, buf)
		if err != nil || n <= utunHeader {
			time.Sleep(holeReadPoll)
			continue
		}
		packet := buf[utunHeader:n]
		var header int
		var to netip.Addr
		switch {
		case packet[0]>>4 == 4 && len(packet) >= 20 && packet[9] == unix.IPPROTO_UDP:
			header, to = int(packet[0]&0x0f)*4, netip.AddrFrom4([4]byte(packet[16:20]))
		case packet[0]>>4 == 6 && len(packet) >= 40 && packet[6] == unix.IPPROTO_UDP:
			header, to = 40, netip.AddrFrom16([16]byte(packet[24:40]))
		default:
			continue
		}
		if len(packet) >= header+8 && to == target && binary.BigEndian.Uint16(packet[header+2:]) == holePort && bytes.Equal(packet[header+8:], payload) {
			return true
		}
	}
	return false
}

// U holds R, a route of the host, and the mesh a route longer than R holding a
// peer's endpoint, which a send scoped to U meets in rt_lookup_common
// (bsd/net/route.c) as a match on another interface it drops, after which it
// finds no route on U. The hole arm hands the endpoint as a live session's
// destination alone: RTM_GET scoped to U answers U for it, and a datagram from
// a socket bound to U leaves U, while another address inside the mesh's route
// ends at M unbound. The listed arm lists the endpoint, with the same
// answers. The L6 arm puts a mesh route outside the overlay inside a route U
// holds, longer than /0, and an unbound lookup of an address inside it ends at
// U, as rule 5410 sends it on linux. The arm around the overlay puts a mesh
// route holding a prefix of the overlay inside that route of U's, and an
// unbound lookup ends at U outside the prefix and at M inside it. The
// reconciler's withdrawal leaves both utuns and the host's defaults as they
// were.
func TestDarwinHolesLetTheUnderlayPastALongerMeshRoute(t *testing.T) {
	requireNetTest(t)
	rig := newHoleRig(t)
	for _, family := range holeFamilies {
		for _, arm := range []struct {
			name   string
			listed bool
		}{
			{"the hole", false},
			{"a listed endpoint", true},
		} {
			t.Run(family.name+", "+arm.name, func(t *testing.T) {
				rig.listed, rig.sent = nil, []netip.Addr{family.peer}
				if arm.listed {
					rig.listed, rig.sent = []netip.Addr{family.peer}, nil
				}
				rig.pass(t, family.narrow)
				if got := askRoute(t, family.peer, rig.u.index); got != rig.u.index {
					t.Errorf("RTM_GET scoped to U for %s answers interface %d, want U's %d, where 0 is ESRCH", family.peer, got, rig.u.index)
				}
				payload := []byte(family.name + ", " + arm.name)
				drainTUN(rig.uFD)
				if err := sendBound(rig.u.index, family.peer, payload); err != nil {
					t.Errorf("a datagram to %s from a socket bound to U: %v", family.peer, err)
				} else if !carriedOut(rig.uFD, family.peer, payload) {
					t.Errorf("a datagram to %s from a socket bound to U never came out of U", family.peer)
				}
				if got := askRoute(t, family.neighbor, 0); got != rig.m {
					t.Errorf("an unbound RTM_GET for %s, inside the mesh's %s, answers interface %d, want M's %d", family.neighbor, family.narrow, got, rig.m)
				}
			})
		}
		t.Run(family.name+", row L6", func(t *testing.T) {
			rig.listed, rig.sent = nil, nil
			rig.pass(t, family.inLAN)
			if got := askRoute(t, family.lanTarget, 0); got != rig.u.index {
				t.Errorf("an unbound RTM_GET for %s, inside U's %s and the mesh's %s outside the overlay, answers interface %d, want U's %d", family.lanTarget, family.lan, family.inLAN, got, rig.u.index)
			}
		})
		t.Run(family.name+", row L6 around the overlay", func(t *testing.T) {
			rig.listed, rig.sent = nil, nil
			rig.pass(t, family.holding)
			for address, want := range map[netip.Addr]int{family.outside: rig.u.index, family.inside: rig.m} {
				if got := askRoute(t, address, 0); got != want {
					t.Errorf("an unbound RTM_GET for %s, inside U's %s and the mesh's %s, which holds the overlay's %v, answers interface %d, want %d", address, family.lan, family.holding, holeOverlay, got, want)
				}
			}
		})
	}
	rig.pass(t)
	rig.stop(t)
}
