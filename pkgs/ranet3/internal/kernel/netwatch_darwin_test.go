// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The two interfaces the reads below move between.
const (
	// far above the indexes a host hands out
	// and a test that reaches the running kernel fails alike on every machine
	uplinkIndex = 916
	dockIndex   = 919
)

// namedDevices is the interface list these tests decide, so the two indexes
// above name the same devices on every machine the suite runs on.
type namedDevices struct{ Host }

func (namedDevices) InterfaceName(index int) (string, error) {
	switch index {
	case uplinkIndex:
		return "uplink0", nil
	case dockIndex:
		return "dock0", nil
	}
	return "", errors.New("no such interface")
}

// watchedMeshIndex stands for the tun in the reads below, an index no host hands out as uplinkIndex and dockIndex are
const watchedMeshIndex = 923

// readHost is a machine whose interfaces and defaults a test decides
type readHost struct {
	namedDevices
	interfaces []HostInterface
	linksErr   error
	v4, v6     RouteAnswer
}

func (h readHost) Links() ([]HostInterface, error) { return h.interfaces, h.linksErr }

func (h readHost) Lookup(destination, _ netip.Addr) (RouteAnswer, error) {
	answer := h.v4
	if destination.Is6() {
		answer = h.v6
	}
	if answer.Index == 0 {
		return RouteAnswer{}, ErrNoDefaultRoute
	}
	return answer, nil
}

// the read holds every up interface outside the mesh as a link of both families, the loopback among them, with its ready global unicast
// addresses: an IPv4 address on a point-to-point link is a host and its far end a peer, a broadcast link's broadcast is no peer, and an
// IPv6 address under duplicate address detection, optimistic or not, or found duplicated is left out
// a default that names the mesh is none of the host's own
func TestDarwinNetworkReadSkipsTheMeshAndDownInterfaces(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	host := readHost{
		interfaces: []HostInterface{
			{Index: 1, Name: Loopback, Up: true, Loopback: true, Addresses: []HostAddress{
				{Prefix: prefix("127.0.0.1/8")}, {Prefix: prefix("::1/128")}, {Prefix: prefix("fe80::1/64")}}},
			{Index: uplinkIndex, Name: "uplink0", Up: true, Addresses: []HostAddress{
				{Prefix: prefix("192.0.2.10/24"), Far: netip.MustParseAddr("192.0.2.255")},
				{Prefix: prefix("fe80::1/64")},
				{Prefix: prefix("2001:db8::10/64"), Far: netip.IPv6Unspecified(), Flags: in6IffAutoconfSecured},
				{Prefix: prefix("2001:db8::11/64"), Flags: in6IffTentative},
				{Prefix: prefix("2001:db8::12/64"), Flags: in6IffOptimistic | in6IffAutoconfSecured},
				{Prefix: prefix("2001:db8::13/64"), Flags: in6IffDuplicated}}},
			{Index: dockIndex, Name: "dock0", Addresses: []HostAddress{{Prefix: prefix("198.51.100.1/24")}}},
			{Index: 920, Name: "utun4", Up: true, PointToPoint: true, Addresses: []HostAddress{
				{Prefix: prefix("203.0.113.7/24"), Far: netip.MustParseAddr("203.0.113.8")}}},
			{Index: watchedMeshIndex, Name: "utun9", Up: true, PointToPoint: true, Addresses: []HostAddress{
				{Prefix: prefix("10.99.0.1/32"), Far: netip.MustParseAddr("10.99.0.1")}, {Prefix: prefix("3fff:a::1/128")}}},
		},
		v4: RouteAnswer{Index: uplinkIndex, Gateway: gateway},
		v6: RouteAnswer{Index: watchedMeshIndex},
	}
	reader := hostReader{host: host, mesh: watchedMeshIndex}
	state, err := reader.read()
	if err != nil {
		t.Fatal(err)
	}
	want := NetworkState{
		IPv4: NetworkFamily{
			Default: DefaultRoute{Interface: "uplink0", Gateway: gateway}, Addresses: addrs("192.0.2.10", "203.0.113.7"),
			Links: []Link{
				{Name: Loopback},
				{Name: "uplink0", Prefixes: []netip.Prefix{prefix("192.0.2.10/24")}},
				{Name: "utun4", Prefixes: []netip.Prefix{prefix("203.0.113.7/32")}, Peers: []netip.Prefix{prefix("203.0.113.8/32")}},
			},
		},
		IPv6: NetworkFamily{
			Addresses: addrs("2001:db8::10"),
			Links:     []Link{{Name: Loopback}, {Name: "uplink0", Prefixes: []netip.Prefix{prefix("2001:db8::10/64")}}, {Name: "utun4"}},
		},
	}
	for _, family := range []struct{ got, want NetworkFamily }{{state.IPv4, want.IPv4}, {state.IPv6, want.IPv6}} {
		if family.got.Default != family.want.Default || !slices.Equal(family.got.Addresses, family.want.Addresses) || !sameLinks(family.got.Links, family.want.Links) {
			t.Errorf("a family reads as %+v, want %+v", family.got, family.want)
		}
	}

	host.v4 = RouteAnswer{}
	host.linksErr = errors.New("no listing")
	reader.host = host
	if _, err := reader.read(); err == nil {
		t.Error("a read without the interface list succeeded")
	}
}

// watchRig takes the steps of a real kernel's links under a network watch, each signaling once or not at all
type watchRig struct {
	t *testing.T
	w *NetworkWatch
}

// dadWindow outlasts duplicate address detection on a broadcast link, which ends within about two seconds of the add
const dadWindow = 5 * time.Second

// step runs one change and waits within for the watch to signal it, with the links want accepts, then a quiet window for a second
// signal, and where want is nil waits within for no signal at all
func (r *watchRig) step(name string, within time.Duration, run func() error, want func(NetworkChange) error) {
	r.t.Helper()
	if err := run(); err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	select {
	case change := <-r.w.Changes():
		if want == nil {
			r.t.Errorf("%s signaled %+v", name, change.Families())
			return
		}
		if err := want(change); err != nil {
			r.t.Errorf("%s signaled %v", name, err)
		}
	case <-time.After(within):
		if want != nil {
			r.t.Errorf("%s signaled nothing within %s", name, within)
		}
		return
	}
	select {
	case change := <-r.w.Changes():
		r.t.Errorf("%s signaled a second time, %+v", name, change.Families())
	case <-time.After(quietWindow):
	}
}

// link wants device a link of both families holding exactly the prefixes and the peers of each, space separated
func wantLink(device, v4, peers4, v6, peers6 string) func(NetworkChange) error {
	return func(change NetworkChange) error {
		for _, family := range []struct {
			links           []Link
			prefixes, peers string
		}{{change.After.IPv4.Links, v4, peers4}, {change.After.IPv6.Links, v6, peers6}} {
			i := slices.IndexFunc(family.links, func(l Link) bool { return l.Name == device })
			if i < 0 {
				return fmt.Errorf("links without %s, %+v", device, family.links)
			}
			got := family.links[i]
			if !slices.Equal(got.Prefixes, prefixList(family.prefixes)) || !slices.Equal(got.Peers, prefixList(family.peers)) {
				return fmt.Errorf("%s holding %v with peers %v, want %q with peers %q", device, got.Prefixes, got.Peers, family.prefixes, family.peers)
			}
		}
		return nil
	}
}

// linkGone wants device a link of neither family
func linkGone(device string) func(NetworkChange) error {
	return func(change NetworkChange) error {
		for _, links := range [][]Link{change.After.IPv4.Links, change.After.IPv6.Links} {
			if slices.ContainsFunc(links, func(l Link) bool { return l.Name == device }) {
				return fmt.Errorf("links still holding %s, %+v", device, links)
			}
		}
		return nil
	}
}

func prefixList(list string) []netip.Prefix {
	var out []netip.Prefix
	for _, word := range strings.Fields(list) {
		out = append(out, netip.MustParsePrefix(word))
	}
	return out
}

// ifconfig is a step that runs ifconfig on one interface
func ifconfig(device string, args ...string) func() error {
	return commandStep("ifconfig", append([]string{device}, args...)...)
}

// commandStep is a step that runs one command
func commandStep(name string, args ...string) func() error {
	return func() error {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// destroyableUTUN creates a utun and returns its name and the step that destroys it
// the step puts /dev/null in the place of the control descriptor in one dup2, which drops the utun, and the cleanup that closes the
// descriptor later closes /dev/null rather than whatever reused the number
func destroyableUTUN(t *testing.T) (string, func() error) {
	t.Helper()
	name, fd := createUTUNWithFD(t)
	unix.CloseOnExec(fd)
	return name, func() error {
		null, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(null)
		return unix.Dup2(null, fd)
	}
}

// createFeth creates a fake ethernet interface, down, under a unit no interface holds, and returns its name and the step that destroys it
func createFeth(t *testing.T) (string, func() error) {
	t.Helper()
	name := ""
	for unit := 90; unit < 120 && name == ""; unit++ {
		if _, err := net.InterfaceByName(fmt.Sprintf("feth%d", unit)); err != nil {
			name = fmt.Sprintf("feth%d", unit)
		}
	}
	if name == "" {
		t.Fatal("no free feth unit between 90 and 119")
	}
	if err := ifconfig(name, "create")(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var err error
	destroy := func() error {
		once.Do(func() { err = ifconfig(name, "destroy")() })
		return err
	}
	t.Cleanup(func() {
		if err := destroy(); err != nil {
			t.Errorf("%s was left behind: %v", name, err)
		}
	})
	return name, destroy
}

// against the real kernel, every step that moves a link outside the mesh signals once and every other step signals nothing, on two utuns
// and a pair of feth this test creates: a link that comes up, goes down or goes, an address that comes or goes whether or not its route
// already exists, which XNU reports by a kernel event alone, and a utun's later IPv6 addresses, which it reports by a routing message alone
// a route out of a link, an address on a second utun standing in for the mesh, and an IPv6 address found duplicated signal nothing
// an IPv6 address on a broadcast link joins the links only once duplicate address detection ends, by the event that ends it
// the default route is never touched
func TestDarwinNetworkWatchOnRealKernel(t *testing.T) {
	requireNetTest(t)
	mesh := createUTUN(t)
	shared, err := ShareWatcher(nil, mesh)
	if err != nil {
		t.Fatalf("open the watcher: %v", err)
	}
	t.Cleanup(func() { _ = shared.Close() })
	w, err := WatchNetwork(nil, mesh, shared.Reader())
	if err != nil {
		t.Fatalf("open the watch: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	r := &watchRig{t: t, w: w}
	q := quietWindow
	var a, b string
	var destroyA, destroyB func() error
	r.step("utun A created, up at once", q, func() error { a, destroyA = destroyableUTUN(t); return nil }, func(change NetworkChange) error {
		return wantLink(a, "", "", "", "")(change)
	})
	r.step("utun A up, which it already is", q, ifconfig(a, "up"), nil)
	r.step("utun A 198.18.77.1 to 198.18.77.2", q, ifconfig(a, "inet", "198.18.77.1", "198.18.77.2", "netmask", "255.255.255.0", "alias"),
		wantLink(a, "198.18.77.1/32", "198.18.77.2/32", "", ""))
	r.step("utun A 198.18.77.3 to the same far end, which sends no routing message", q,
		ifconfig(a, "inet", "198.18.77.3", "198.18.77.2", "netmask", "255.255.255.0", "alias"),
		wantLink(a, "198.18.77.1/32 198.18.77.3/32", "198.18.77.2/32", "", ""))
	r.step("a route out of utun A", q, commandStep("route", "-n", "add", "-net", "198.51.100.0/24", "-interface", a), nil)
	r.step("the route gone", q, commandStep("route", "-n", "delete", "-net", "198.51.100.0/24", "-interface", a), nil)
	r.step("utun A 198.18.79.1/24 with itself as far end", q, ifconfig(a, "inet", "198.18.79.1/24", "198.18.79.1", "alias"),
		wantLink(a, "198.18.77.1/32 198.18.77.3/32 198.18.79.1/32", "198.18.77.2/32", "", ""))
	r.step("utun A 198.18.79.5/24 with itself as far end", q, ifconfig(a, "inet", "198.18.79.5/24", "198.18.79.5", "alias"),
		wantLink(a, "198.18.77.1/32 198.18.77.3/32 198.18.79.1/32 198.18.79.5/32", "198.18.77.2/32", "", ""))
	r.step("utun A 198.18.77.1 gone, its far end shared", q, ifconfig(a, "inet", "198.18.77.1", "delete"),
		wantLink(a, "198.18.77.3/32 198.18.79.1/32 198.18.79.5/32", "198.18.77.2/32", "", ""))
	r.step("utun A 198.18.77.3 gone, which sends no routing message", q, ifconfig(a, "inet", "198.18.77.3", "delete"),
		wantLink(a, "198.18.79.1/32 198.18.79.5/32", "", "", ""))
	r.step("utun A 198.18.79.5 gone", q, ifconfig(a, "inet", "198.18.79.5", "delete"), wantLink(a, "198.18.79.1/32", "", "", ""))
	r.step("utun A down", q, ifconfig(a, "down"), linkGone(a))
	r.step("utun A up again", q, ifconfig(a, "up"), wantLink(a, "198.18.79.1/32", "", "", ""))
	r.step("utun A destroyed holding an address", q, func() error { return destroyA() }, linkGone(a))

	r.step("an address on the mesh", q, ifconfig(mesh, "inet", "198.18.78.1", "198.18.78.2", "up"), nil)
	r.step("the mesh address gone", q, ifconfig(mesh, "inet", "198.18.78.1", "delete"), nil)

	r.step("utun B created, up at once", q, func() error { b, destroyB = destroyableUTUN(t); return nil }, func(change NetworkChange) error {
		return wantLink(b, "", "", "", "")(change)
	})
	r.step("utun B up, which it already is", q, ifconfig(b, "up"), nil)
	r.step("utun B 2001:db8:78::1/64", q, ifconfig(b, "inet6", "2001:db8:78::1", "prefixlen", "64", "alias"),
		wantLink(b, "", "", "2001:db8:78::1/64", ""))
	r.step("utun B 2001:db8:78::5/64, which posts no kernel event", q, ifconfig(b, "inet6", "2001:db8:78::5", "prefixlen", "64", "alias"),
		wantLink(b, "", "", "2001:db8:78::1/64 2001:db8:78::5/64", ""))
	r.step("utun B 2001:db8:78::9 to 2001:db8:78::a", q, ifconfig(b, "inet6", "2001:db8:78::9", "2001:db8:78::a", "prefixlen", "128", "alias"),
		wantLink(b, "", "", "2001:db8:78::1/64 2001:db8:78::5/64 2001:db8:78::9/128", "2001:db8:78::a/128"))
	r.step("utun B 2001:db8:78::5 gone", q, ifconfig(b, "inet6", "2001:db8:78::5", "delete"),
		wantLink(b, "", "", "2001:db8:78::1/64 2001:db8:78::9/128", "2001:db8:78::a/128"))
	r.step("utun B 2001:db8:78::9 gone", q, ifconfig(b, "inet6", "2001:db8:78::9", "delete"), wantLink(b, "", "", "2001:db8:78::1/64", ""))
	r.step("utun B down", q, ifconfig(b, "down"), linkGone(b))
	r.step("utun B destroyed while down", q, func() error { return destroyB() }, nil)

	var c, d string
	var destroyC, destroyD func() error
	r.step("feth C created, down", q, func() error { c, destroyC = createFeth(t); return nil }, nil)
	r.step("feth D created, down", q, func() error { d, destroyD = createFeth(t); return nil }, nil)
	r.step("feth C peered with feth D", q, ifconfig(c, "peer", d), nil)
	r.step("feth D up", q, ifconfig(d, "up"), func(change NetworkChange) error { return wantLink(d, "", "", "", "")(change) })
	r.step("feth C up", q, ifconfig(c, "up"), func(change NetworkChange) error { return wantLink(c, "", "", "", "")(change) })
	r.step("feth C 198.18.81.1/24", q, ifconfig(c, "inet", "198.18.81.1/24", "alias"), wantLink(c, "198.18.81.1/24", "", "", ""))
	r.step("feth C 198.18.81.5/24 inside its network, which sends no routing message", q, ifconfig(c, "inet", "198.18.81.5/24", "alias"),
		wantLink(c, "198.18.81.1/24 198.18.81.5/24", "", "", ""))
	detected := netip.MustParseAddr("2001:db8:81::1")
	flags := func() uint32 {
		flags, err := addressFlags6(c, detected)
		if err != nil {
			t.Fatalf("read the flags of the address on feth C: %v", err)
		}
		return flags
	}
	r.step("feth C 2001:db8:81::1/64, a link's only once detection ends", dadWindow, func() error {
		if err := ifconfig(c, "inet6", "2001:db8:81::1", "prefixlen", "64", "alias")(); err != nil {
			return err
		}
		if now := flags(); now&(in6IffTentative|in6IffOptimistic) == 0 {
			t.Errorf("the address on feth C left detection before the first read, flags %#x", now)
		}
		interfaces, err := runningKernel{}.Links()
		if err != nil {
			return err
		}
		if _, v6 := hostLinks(interfaces, 0); slices.Contains(v6.Addresses, detected) {
			t.Errorf("a read holds the address on feth C while it is tentative, %v", v6.Addresses)
		}
		return nil
	}, func(change NetworkChange) error {
		if now := flags(); now&(in6IffTentative|in6IffOptimistic|in6IffDuplicated) != 0 {
			return fmt.Errorf("the address on feth C with flags %#x", now)
		}
		return wantLink(c, "198.18.81.1/24 198.18.81.5/24", "", "2001:db8:81::1/64", "")(change)
	})
	r.step("feth D 2001:db8:81::1/64, which feth C holds", dadWindow, ifconfig(d, "inet6", "2001:db8:81::1", "prefixlen", "64", "alias"), nil)
	r.step("feth D's duplicated address gone", q, ifconfig(d, "inet6", "2001:db8:81::1", "delete"), nil)
	r.step("feth C 198.18.81.5 gone, which sends no routing message", q, ifconfig(c, "inet", "198.18.81.5", "delete"),
		wantLink(c, "198.18.81.1/24", "", "2001:db8:81::1/64", ""))
	r.step("feth C 198.18.81.1 gone", q, ifconfig(c, "inet", "198.18.81.1", "delete"), wantLink(c, "", "", "2001:db8:81::1/64", ""))
	r.step("feth C down", q, ifconfig(c, "down"), linkGone(c))
	r.step("feth C destroyed while down", q, func() error { return destroyC() }, nil)
	r.step("feth D destroyed while up", q, func() error { return destroyD() }, linkGone(d))
}
