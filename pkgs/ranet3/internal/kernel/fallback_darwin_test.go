// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

const (
	// testLoopback is lo0's index on switchHost, and testOther another
	// program's utun there
	testLoopback = 1
	testOther    = 7
)

// switchHost is a host whose table a test sets and whose route socket keeps
// what reaches it, naming lo0 and another program's utun5
type switchHost struct {
	runningKernel
	t       *testing.T
	entries []dumpEntry
	sent    [][]byte
}

func (h *switchHost) Dump() ([]byte, error) { return dumpRIB(h.t, h.entries...), nil }

func (h *switchHost) InterfaceIndex(name string) (int, error) {
	if name == Loopback {
		return testLoopback, nil
	}
	return 0, errors.New("no such interface")
}

func (h *switchHost) InterfaceName(index int) (string, error) {
	switch index {
	case testLoopback:
		return Loopback, nil
	case testOther:
		return "utun5", nil
	}
	return "", errors.New("no such interface")
}

func (h *switchHost) RouteSocket() (RouteWriter, error) { return h, nil }
func (h *switchHost) WriteRoute(raw []byte) error {
	h.sent = append(h.sent, raw)
	return nil
}
func (h *switchHost) Close() error { return nil }

// rejectEntry is a reject in the switch's shape at destination as a dump reports it
func rejectEntry(destination netip.Prefix) dumpEntry {
	return dumpEntry{index: testLoopback, flags: loopFlags, dst: destination, gateway: routeAddr(loopGateway(destination))}
}

// sentKeys is the type and key of each message in sent, checking each carries
// the rejects' shape: their flags, no interface, and the loopback gateway of
// its family
func sentKeys(t *testing.T, messages []*route.RouteMessage) (kinds []int, keys []netip.Prefix) {
	t.Helper()
	for _, rm := range messages {
		destination, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_DST])
		if err != nil {
			t.Fatal(err)
		}
		mask, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_NETMASK])
		if err != nil {
			t.Fatal(err)
		}
		bits, _ := maskBits(mask)
		key := netip.PrefixFrom(destination, bits)
		gateway, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_GATEWAY])
		if err != nil || gateway != loopGateway(key) || rm.Flags != loopFlags || rm.Index != 0 {
			t.Errorf("the message at %s carries flags %#x, interface %d and gateway %v, want %#x, none and %s",
				key, rm.Flags, rm.Index, rm.Addrs[unix.RTAX_GATEWAY], loopFlags, loopGateway(key))
		}
		kinds, keys = append(kinds, rm.Type), append(keys, key)
	}
	return kinds, keys
}

func addressFromRouteAddrOK(addr route.Addr) (netip.Addr, error) {
	address, ok := addressFromRouteAddr(addr)
	if !ok {
		return netip.Addr{}, errors.New("a message without an address where one was written")
	}
	return address, nil
}

// The switch reads its rejects from the pass's dump alone, adds each it finds
// missing on lo0 in their shape, both families' on a tun holding an IPv4
// address alone, names another program's route at a key or a route of
// another shape on lo0, a reject via another loopback address among them, as
// the fault and never takes either over, and deletes from a dump of its own
// every reject of its shape and nothing else
func TestDarwinSwitchWritesReadsAndDeletesTheRejects(t *testing.T) {
	host := &switchHost{t: t}
	plat, sock := testPlatform(t, Table{}, Runtime{})
	plat.host, plat.loopback, plat.bare = host, testLoopback, []Family{FamilyIPv6}
	sets := fallbackSets{}
	if _, err := plat.readFallback(sets); !errors.Is(err, errNoLoopDump) {
		t.Errorf("a read before any dump of the pass answered %v, want %v", err, errNoLoopDump)
	}
	if _, err := plat.ownedRoutes(dumpRIB(t)); err != nil {
		t.Fatal(err)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault != "the reject at 1.0.0.0/8 is missing" {
		t.Errorf("an empty table reads %+v, %v, want the first reject missing", read, err)
	}
	if err := plat.writeFallback(sets, false); err != nil {
		t.Fatal(err)
	}
	kinds, keys := sentKeys(t, sock.messages(t))
	if !slices.Equal(keys, rejectKeys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_ADD }) {
		t.Errorf("the write sent %v at %v, want an add at each of %v", kinds, keys, rejectKeys)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault != "" {
		t.Errorf("after the write the switch reads %+v, %v, want no fault", read, err)
	}

	taken, misshaped, elsewhere := prefix("2000::/3"), prefix("128.0.0.0/1"), prefix("64.0.0.0/2")
	var entries []dumpEntry
	for _, key := range rejectKeys {
		switch key {
		case taken:
			entries = append(entries, dumpEntry{index: testOther, flags: unix.RTF_UP | unix.RTF_STATIC, dst: key, gateway: &route.LinkAddr{Index: testOther}})
		case misshaped:
			blackhole := rejectEntry(key)
			blackhole.flags = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_BLACKHOLE
			entries = append(entries, blackhole)
		case elsewhere:
			// a reject on lo0 by another loopback address
			other := rejectEntry(key)
			other.gateway = routeAddr(addr("127.0.0.2"))
			entries = append(entries, other)
		default:
			entries = append(entries, rejectEntry(key))
		}
	}
	// a route scoped to the tun at a key is keyed apart and meets no reject
	entries = append(entries, dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE, dst: prefix("1.0.0.0/8"), gateway: ourGateway()})
	if _, err := plat.ownedRoutes(dumpRIB(t, entries...)); err != nil {
		t.Fatal(err)
	}
	want := "the route 64.0.0.0/2 via 127.0.0.2 on lo0 is no reject of the switch's shape"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}
	plat.loops[elsewhere] = ""
	want = "the route 128.0.0.0/1 via 127.0.0.1 on lo0 is no reject of the switch's shape"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}
	sock.sent, sock.err = nil, unix.EEXIST
	if err := plat.writeFallback(sets, false); err != nil {
		t.Fatal(err)
	}
	if kinds, keys := sentKeys(t, sock.messages(t)); !slices.Equal(keys, []netip.Prefix{misshaped, taken}) || slices.Contains(kinds, unix.RTM_DELETE) {
		t.Errorf("the rewrite sent %v at %v, want an add at each of %s and %s and no delete", kinds, keys, misshaped, taken)
	}
	plat.loops[misshaped] = ""
	want = "another program's route 2000::/3 on utun5 holds a key of the switch's"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}
	// a member of ours whole out of the tun at a key, whose delete has not gone
	whole := []dumpEntry{{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC, dst: misshaped, gateway: ourGateway()}}
	for _, key := range rejectKeys {
		if key != misshaped {
			whole = append(whole, rejectEntry(key))
		}
	}
	if _, err := plat.ownedRoutes(dumpRIB(t, whole...)); err != nil {
		t.Fatal(err)
	}
	want = "this node's own route 128.0.0.0/1 on interface 42 holds a key of the switch's until it goes in as its halves"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}

	sock.sent, sock.err = nil, nil
	host.entries = entries
	if held, err := plat.holdsFallback(); err != nil || !held {
		t.Errorf("a listing of the rejects answers %v, %v", held, err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	kinds, keys = sentKeys(t, sock.messages(t))
	foreign := func(key netip.Prefix) bool { return key == taken || key == misshaped || key == elsewhere }
	wantKeys := slices.DeleteFunc(slices.Clone(rejectKeys), foreign)
	if !slices.Equal(keys, wantKeys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_DELETE }) {
		t.Errorf("the delete sent %v at %v, want a delete at each of %v", kinds, keys, wantKeys)
	}
	host.entries = entries[:0:0]
	for _, entry := range entries {
		if foreign(entry.dst) {
			host.entries = append(host.entries, entry)
		}
	}
	if held, err := plat.holdsFallback(); err != nil || held {
		t.Errorf("a listing of no reject answers %v, %v", held, err)
	}
}

// The start with no reconciler deletes the rejects at the switch's keys and
// the holds at its overlay's, and leaves a reject of their shape another
// program wrote at another key, and a debug read lists each reject with the
// sends of IPv4's alone counted
func TestDarwinDeleteFallbackTakesTheRejectsAlone(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("2001:db8:ee::/48"))
	host := &switchHost{t: t, entries: []dumpEntry{rejectEntry(prefix("10.0.0.0/8"))}}
	for _, key := range slices.Concat(rejectKeys, overlayKeys(overlay)) {
		host.entries = append(host.entries, rejectEntry(key))
	}
	read, err := readRejects(host)
	if err != nil || !read.Held || len(read.Rules) != len(rejectKeys) || read.Where != "rejects on lo0" {
		t.Fatalf("the debug read answers %+v, %v, want the %d rejects on lo0", read, err, len(rejectKeys))
	}
	for i, rule := range read.Rules {
		key := rejectKeys[i]
		if rule.Spec != key.String()+" via "+loopGateway(key).String()+" reject" || rule.Counted != key.Addr().Is4() {
			t.Errorf("the reject at %s reads %+v", key, rule)
		}
	}
	for _, keys := range [][]netip.Prefix{rejectKeys, overlayKeys(overlay)} {
		host.sent = nil
		if err := deleteRejects(host, keys); err != nil {
			t.Fatal(err)
		}
		var messages []*route.RouteMessage
		for _, raw := range host.sent {
			parsed, err := route.ParseRIB(route.RIBTypeRoute, raw)
			if err != nil || len(parsed) != 1 {
				t.Fatalf("parse back a sent message: %v", err)
			}
			messages = append(messages, parsed[0].(*route.RouteMessage))
		}
		kinds, sent := sentKeys(t, messages)
		if !slices.Equal(sent, keys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_DELETE }) {
			t.Errorf("the start deleted %v at %v, want a delete at each of %v alone", kinds, sent, keys)
		}
	}
}

// A route on lo0 with the rejects' flags and gateway that carries RTF_HOST and
// RTF_WASCLONED as well, as XNU's clone of a route does, or RTF_IFSCOPE, is no
// reject or hold of ranet3's: the start with no reconciler deletes none of
// them and the debug read lists none
func TestDarwinRejectShapeLeavesClonesAndScopedRoutes(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.9/32"), prefix("2001:db8:ee::9/128"))
	cloned := func(destination string) dumpEntry {
		entry := rejectEntry(prefix(destination))
		entry.flags |= unix.RTF_HOST | unix.RTF_WASCLONED
		entry.hostRoute = true
		return entry
	}
	scoped := func(destination string) dumpEntry {
		entry := rejectEntry(prefix(destination))
		entry.flags |= unix.RTF_IFSCOPE
		return entry
	}
	host := &switchHost{t: t, entries: []dumpEntry{
		cloned("192.0.2.9/32"), cloned("2001:db8:ee::9/128"), scoped("128.0.0.0/1"), scoped("8000::/1"),
	}}
	if read, err := readRejects(host); err != nil || read.Held || len(read.Rules) != 0 {
		t.Errorf("the debug read answers %+v, %v, want no reject", read, err)
	}
	for _, keys := range [][]netip.Prefix{rejectKeys, overlayKeys(overlay)} {
		host.sent = nil
		if err := deleteRejects(host, keys); err != nil {
			t.Fatal(err)
		}
		if len(host.sent) != 0 {
			t.Errorf("the start at %v sent %d deletes, want none", keys, len(host.sent))
		}
	}
}

// An overlay hold goes on lo0 in the rejects' shape, unscoped, though the tun
// holds no address of its family, reads back from the pass's dump as ours at
// a key of the overlay and as nobody's at another key, and leaves by a delete
// in that shape. A hold at a prefix a reload took out of the overlay stays
// ours to delete.
func TestDarwinOverlayHoldGoesOnLoopback(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("2001:db8:ee::/48"))
	plat, sock := testPlatform(t, Table{}, Runtime{Overlay: overlay})
	plat.loopback = testLoopback
	plat.cover(overlay, nil, []Family{FamilyIPv6}, hostTable{})
	held := Route{Destination: prefix("2001:db8:ee::/48"), Metric: holdMetric, Unreachable: true}
	if plat.scopes(held) {
		t.Errorf("the hold at %s is scoped", held.Destination)
	}
	if err := plat.AddRoute(held); err != nil {
		t.Fatal(err)
	}
	kinds, keys := sentKeys(t, sock.messages(t))
	if !slices.Equal(keys, []netip.Prefix{held.Destination}) || kinds[0] != unix.RTM_ADD {
		t.Errorf("the hold sent %v at %v, want an add at %s", kinds, keys, held.Destination)
	}
	foreign := prefix("198.51.100.0/24")
	routes, err := plat.ownedRoutes(dumpRIB(t, rejectEntry(held.Destination), rejectEntry(foreign)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(routes, []Route{held}) {
		t.Errorf("the dump reads back %v, want %+v alone", routes, held)
	}

	plat.cover(overlay[:1], nil, nil, hostTable{})
	routes, err = plat.ownedRoutes(dumpRIB(t, rejectEntry(held.Destination)))
	if err != nil || !slices.Equal(routes, []Route{held}) {
		t.Fatalf("after a reload took %s out of the overlay the dump reads back %v, %v, want the hold still ours", held.Destination, routes, err)
	}
	sock.sent = nil
	if err := plat.DelRoute(held); err != nil {
		t.Fatal(err)
	}
	if kinds, keys := sentKeys(t, sock.messages(t)); !slices.Equal(keys, []netip.Prefix{held.Destination}) || kinds[0] != unix.RTM_DELETE {
		t.Errorf("the withdrawal sent %v at %v, want a delete at %s", kinds, keys, held.Destination)
	}
	if routes, err := plat.ownedRoutes(dumpRIB(t, rejectEntry(held.Destination))); err != nil || len(routes) != 0 {
		t.Errorf("once deleted, a route of the hold's shape at %s outside the overlay reads back as %v, %v, want nobody's", held.Destination, routes, err)
	}

	// a reload that takes the prefix out of the overlay before any dump has
	// read the hold back: the add's own record keeps it ours
	plat, _ = testPlatform(t, Table{}, Runtime{Overlay: overlay})
	plat.loopback = testLoopback
	plat.cover(overlay, nil, []Family{FamilyIPv6}, hostTable{})
	if err := plat.AddRoute(held); err != nil {
		t.Fatal(err)
	}
	plat.cover(overlay[:1], nil, nil, hostTable{})
	if routes, err := plat.ownedRoutes(dumpRIB(t, rejectEntry(held.Destination))); err != nil || !slices.Equal(routes, []Route{held}) {
		t.Errorf("after a reload took %s out of the overlay before any dump the dump reads back %v, %v, want the hold still ours", held.Destination, routes, err)
	}
}

// A route of the mesh's at a full-length overlay prefix goes in as a host
// route out of the tun, RTF_HOST with no netmask and the tun named as its
// interface, which the kernel keys apart from the hold there, a network route
// with a mask of all ones. Both read back from a dump, the IPv6 host route
// with the RTF_LLINFO XNU marks it with and a clone of one not, and the
// route's delete is a host route's too.
func TestDarwinFullLengthRouteGoesInAsAHostRouteBesideTheHold(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.9/32"), prefix("2001:db8:ee::9/128"))
	plat, sock := testPlatform(t, Table{}, Runtime{Overlay: overlay})
	plat.loopback = testLoopback
	plat.cover(overlay, nil, nil, hostTable{})
	for _, key := range overlayKeys(overlay) {
		sock.sent = nil
		hold := Route{Destination: key, Metric: holdMetric, Unreachable: true}
		mesh := Route{Destination: key, Metric: routeMetric(key, false)}
		for _, r := range []Route{hold, mesh} {
			if err := plat.AddRoute(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := plat.DelRoute(mesh); err != nil {
			t.Fatal(err)
		}
		messages := sock.messages(t)
		if len(messages) != 3 {
			t.Fatalf("at %s the adds and the delete sent %d messages, want 3", key, len(messages))
		}
		if messages[0].Flags != loopFlags || messages[0].Addrs[unix.RTAX_NETMASK] == nil {
			t.Errorf("the hold at %s went in with flags %#x and netmask %v, want %#x and one", key, messages[0].Flags, messages[0].Addrs[unix.RTAX_NETMASK], loopFlags)
		}
		for _, rm := range messages[1:] {
			ifp, ok := rm.Addrs[unix.RTAX_IFP].(*route.LinkAddr)
			if rm.Flags&unix.RTF_HOST == 0 || rm.Addrs[unix.RTAX_NETMASK] != nil || !ok || ifp.Index != testIndex || rm.Index != testIndex {
				t.Errorf("the mesh's route at %s went as type %d with flags %#x, netmask %v, interface %v and index %d, want RTF_HOST, none, the tun's and %d",
					key, rm.Type, rm.Flags, rm.Addrs[unix.RTAX_NETMASK], rm.Addrs[unix.RTAX_IFP], rm.Index, testIndex)
			}
		}
		if messages[1].Type != unix.RTM_ADD || messages[2].Type != unix.RTM_DELETE {
			t.Errorf("the mesh's route at %s went as types %d and %d, want an add and a delete", key, messages[1].Type, messages[2].Type)
		}
		flags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_HOST
		if key.Addr().Is6() {
			// as nd6_rtrequest marks it
			flags |= unix.RTF_LLINFO
		}
		host := dumpEntry{index: testIndex, flags: flags, dst: key, gateway: &route.LinkAddr{Index: testIndex}, hostRoute: true}
		next := netip.PrefixFrom(key.Addr().Next(), key.Bits())
		clone := dumpEntry{index: testIndex, flags: flags | unix.RTF_WASCLONED, dst: next, gateway: &route.LinkAddr{Index: testIndex}, hostRoute: true}
		entries := []dumpEntry{rejectEntry(key), host, clone}
		if key.Addr().Is6() {
			// a host route out of the tun whose gateway names a link other than the tun's
			entries = append(entries, dumpEntry{index: testIndex, flags: flags, dst: netip.PrefixFrom(next.Addr().Next(), key.Bits()), gateway: &route.LinkAddr{}, hostRoute: true})
		}
		routes, err := plat.ownedRoutes(dumpRIB(t, entries...))
		if err != nil || !slices.Equal(routes, []Route{hold, mesh}) {
			t.Errorf("the dump at %s reads back %v, %v, want %v and %v, no clone and no host route naming no link", key, routes, err, hold, mesh)
		}
	}
}

// The hold of ours read back at a full-length overlay prefix is no route in
// the key of the mesh's host route there, so an add of that route refused with
// EEXIST, another program's host route holding the address, is warned as at
// any other key another program holds
func TestDarwinHostRouteRefusedBesideTheHoldIsWarned(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.9/32"), prefix("2001:db8:ee::9/128"))
	plat, sock := testPlatform(t, Table{}, Runtime{Overlay: overlay})
	plat.loopback = testLoopback
	plat.cover(overlay, nil, nil, hostTable{})
	keys := overlayKeys(overlay)
	if _, err := plat.ownedRoutes(dumpRIB(t, rejectEntry(keys[0]), rejectEntry(keys[1]))); err != nil {
		t.Fatal(err)
	}
	logs := captureKernelLogs(t)
	sock.err = unix.EEXIST
	for _, key := range keys {
		if err := plat.AddRoute(Route{Destination: key, Metric: routeMetric(key, false)}); !errors.Is(err, errRouteSkipped) {
			t.Errorf("the refused add at %s answered %v, want it skipped", key, err)
		}
	}
	if got := strings.Count(logs.String(), "kernel is leaving a route that another program holds"); got != len(keys) {
		t.Errorf("the refusals beside the holds warned %d times, want once at each of %v:\n%s", got, keys, logs)
	}
}

// startHost is switchHost naming the tun as well, which holds no address, and
// whose watcher never wakes
type startHost struct{ *switchHost }

func (startHost) Addresses(int) ([]netip.Prefix, error) { return nil, nil }

func (h startHost) InterfaceIndex(name string) (int, error) {
	if name == "utun9" {
		return testIndex, nil
	}
	return h.switchHost.InterfaceIndex(name)
}

func (h startHost) Watch(int, int) (Watcher, error) { return quietWatcher{}, nil }

type quietWatcher struct{}

func (quietWatcher) Changed() <-chan struct{} { return nil }
func (quietWatcher) Close() error             { return nil }

// A reconciler stopped before its first pass deletes the holds a crash left
// at its start's overlay keys, and leaves a route of their shape at another
// key, as a node starting down and stopped again does
func TestDarwinStopBeforeTheFirstPassDeletesTheHoldsACrashLeft(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("2001:db8:ee::/48"))
	host := &switchHost{t: t}
	for _, key := range slices.Concat(overlayKeys(overlay), []netip.Prefix{prefix("198.51.100.0/24")}) {
		host.entries = append(host.entries, rejectEntry(key))
	}
	reconciler, err := New(Table{}, Runtime{Interface: "utun9", Overlay: overlay, Host: startHost{host}}, netstack.NewRouteTable())
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.withdraw(nil); err != nil {
		t.Fatal(err)
	}
	_ = reconciler.Close()
	var messages []*route.RouteMessage
	for _, raw := range host.sent {
		parsed, err := route.ParseRIB(route.RIBTypeRoute, raw)
		if err != nil || len(parsed) != 1 {
			t.Fatalf("parse back a sent message: %v", err)
		}
		messages = append(messages, parsed[0].(*route.RouteMessage))
	}
	kinds, keys := sentKeys(t, messages)
	slices.SortFunc(keys, comparePrefixes)
	want := overlayKeys(overlay)
	slices.SortFunc(want, comparePrefixes)
	if !slices.Equal(keys, want) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_DELETE }) {
		t.Errorf("the stop sent %v at %v, want a delete at each of %v alone", kinds, keys, want)
	}
}

// The underlay's selection, handed the overlay in force, passes over the
// holds on lo0 at its keys as it passes over the switch's rejects, so an
// endpoint inside an overlay prefix is selected by the host's own routes, and
// a route of the holds' shape at a key outside the overlay stays a candidate.
// A hold at a prefix a reload took out of the overlay is a candidate again.
func TestDarwinSelectionPassesTheOverlayHoldsOver(t *testing.T) {
	// loopback stands in for lo0, an index apart from the selection's mesh
	const loopback = 4
	onLoop := func(destination string) dumpEntry {
		entry := rejectEntry(prefix(destination))
		entry.index = loopback
		return entry
	}
	host := newSelectionHost(t,
		dumpEntry{index: selectionUplink, flags: unix.RTF_UP | unix.RTF_GATEWAY, dst: prefix("0.0.0.0/0"), gateway: routeAddr(addr("198.51.100.1"))},
		dumpEntry{index: selectionUplink, flags: unix.RTF_UP | unix.RTF_GATEWAY, dst: prefix("::/0"), gateway: routeAddr(addr("2001:db8::1"))},
		onLoop("192.0.2.0/24"), onLoop("2001:db8:ee::/48"), onLoop("203.0.113.0/24"),
	)
	selection := openTestSelection(t, host, selectionMeshName)
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("2001:db8:ee::/48"))
	selects := func(step string, want map[string]string) {
		t.Helper()
		for destination, route := range want {
			if got, _, ok := selection.Route(addr(destination)); !ok || got != prefix(route) {
				t.Errorf("%s: %s selects %s, %v, want the route at %s", step, destination, got, ok, route)
			}
		}
	}
	selection.holdOverlay(overlay)
	selects("the overlay handed", map[string]string{"192.0.2.77": "0.0.0.0/0", "2001:db8:ee::77": "::/0", "203.0.113.7": "203.0.113.0/24"})
	selection.holdOverlay(overlay[:1])
	selects("the overlay reloaded", map[string]string{"192.0.2.77": "0.0.0.0/0", "2001:db8:ee::77": "2001:db8:ee::/48"})
}

// The underlay's selection passes over the switch's rejects, which carry no
// datagram, NAT64's among them, so an endpoint a DNS64 resolver names inside
// 64:ff9b::/96 or 64:ff9b:1::/48 is selected by the uplink's default, and
// keeps another program's reject as a candidate
func TestDarwinSelectionPassesTheSwitchOver(t *testing.T) {
	entries := []dumpEntry{
		{index: testOther, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY, dst: prefix("0.0.0.0/0"), gateway: routeAddr(addr("192.0.2.1"))},
		{index: testOther, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY, dst: prefix("::/0"), gateway: routeAddr(addr("2001:db8::1"))},
		rejectEntry(prefix("10.0.0.0/8")),
	}
	for _, key := range rejectKeys {
		entries = append(entries, rejectEntry(key))
	}
	routes, err := hostRoutes(dumpRIB(t, entries...), nil)
	if err != nil {
		t.Fatal(err)
	}
	for destination, want := range map[string]string{
		"203.0.113.7": "0.0.0.0/0", "64:ff9b::c000:201": "::/0", "64:ff9b:1::c000:201": "::/0", "10.1.2.3": "10.0.0.0/8",
	} {
		if got, ok := selectRoute(routes, testIndex, addr(destination), 0); !ok || got.destination != prefix(want) {
			t.Errorf("%s selects %+v, want the route at %s", destination, got, want)
		}
	}
}

// lookHost is switchHost answering each longest match from answers, and with
// ErrNoDefaultRoute for an address it holds none for
type lookHost struct {
	*switchHost
	answers map[netip.Addr]RouteAnswer
}

func (h *lookHost) Lookup(destination, mask netip.Addr) (RouteAnswer, error) {
	answer, ok := h.answers[destination]
	if mask.IsValid() || !ok {
		return RouteAnswer{}, ErrNoDefaultRoute
	}
	return answer, nil
}

// darwin's lookup half asks the unbound longest match of each read and judges
// the hold's reject on lo0 as the hold's, another utun's longer route as taken,
// and no route at all as taken
func TestDarwinLookupsJudgeTheRouteEachEndsAt(t *testing.T) {
	plat, _ := testPlatform(t, Table{}, Runtime{})
	plat.host = &lookHost{switchHost: &switchHost{t: t}, answers: map[netip.Addr]RouteAnswer{
		addr("192.0.2.1"): {Index: testLoopback, Gateway: addr("127.0.0.1"), Prefix: prefix("192.0.2.0/24"), Reject: true},
		addr("3fff:c::1"): {Index: testOther, Prefix: prefix("3fff:c::/33")},
	}}
	reads := []RouteRead{{Destination: addr("192.0.2.1")}, {Destination: addr("3fff:c::1")}, {Destination: addr("3fff:d::1")}}
	answers, err := plat.lookups(reads)
	if err != nil {
		t.Fatal(err)
	}
	holds := []netip.Prefix{prefix("192.0.2.0/24"), prefix("3fff:c::/32"), prefix("3fff:d::/32")}
	want := []struct {
		text  string
		taken bool
	}{
		{"192.0.2.0/24 via 127.0.0.1 on lo0 reject", false},
		{"3fff:c::/33 on utun5", true},
		{"a refusal (network is unreachable)", true},
	}
	for i, answer := range answers {
		if text, taken := plat.judge(holds[i], answer); text != want[i].text || taken != want[i].taken {
			t.Errorf("the lookup of %s judged %q taken %v, want %q taken %v", reads[i].Destination, text, taken, want[i].text, want[i].taken)
		}
	}
}
