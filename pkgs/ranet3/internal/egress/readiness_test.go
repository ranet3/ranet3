// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// readTUN is the tun of the exits these tests read for, read4 and read6 the
// read addresses of the prefixes they advertise, 198.51.100.0/24 and ::/0, and
// readMembers a member of each family, a host route reading its own address
var (
	readTUN     = "ranet3"
	read4       = netip.MustParseAddr("198.51.100.128")
	read6       = netip.MustParseAddr("8000::")
	readMembers = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("3fff:20::1/128")}
)

// lookupHost answers a translator's lookups by destination and its settings
// from a tree, recording each batch it is handed
type lookupHost struct {
	answers map[netip.Addr]Answer
	tree    map[string]string
	err     error
	asked   [][]Lookup
}

func (h *lookupHost) lookup(lookups []Lookup) ([]Answer, error) {
	h.asked = append(h.asked, slices.Clone(lookups))
	if h.err != nil {
		return nil, h.err
	}
	answers := make([]Answer, len(lookups))
	for i, lookup := range lookups {
		answers[i] = h.answers[lookup.Destination]
	}
	return answers, nil
}

func (h *lookupHost) sysctl(path string) string { return h.tree[path] }

// passingAnswer is a lookup's answer on an exit routing it right: the forward
// route leaving by the uplink eth0, and the reply, arriving there, by the tun
func passingAnswer() Answer {
	return Answer{
		Route:    Route{Type: "unicast", Hops: []Hop{{Device: "eth0"}}},
		ReplyIIF: "eth0",
		Reply:    Route{Type: "unicast", Hops: []Hop{{Device: readTUN}}},
	}
}

// readingExit is a translator advertising cfg on the tun readTUN, reading its
// lookups from host and its members from members at each pass
func readingExit(t *testing.T, cfg Egress, host *lookupHost, members *[]netip.Prefix, bus *events.Bus) *Translator {
	t.Helper()
	rt := Runtime{
		Interface: readTUN,
		Events:    bus,
		Lookup:    host.lookup,
		Sysctl:    host.sysctl,
		Members:   func() []netip.Prefix { return slices.Clone(*members) },
	}
	return translator(t, cfg, rt, &fakeBackend{})
}

// Each read that holds a family not ready names itself, the prefix, the
// address, the source and the device the lookup arrived on, then what the
// kernel answered: an error with the setting that refuses it, a route of
// another type, hops none of which is live, a forward route back into the tun,
// or a reply route out of the uplink. An IPv6 lookup that fails names no
// setting, since IPv6 answers its route where forwarding is off. The family's
// prefixes are withheld, and the egress.ready event carries the reason
func TestEachLookupNamesWhatHoldsItsFamilyNotReady(t *testing.T) {
	forward4 := "the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3"
	reply4 := "the reply lookup of 192.0.2.1 for 198.51.100.0/24 from 198.51.100.128 arriving on eth0"
	forward6 := "the lookup of 8000:: for ::/0 from 3fff:20::1 arriving on ranet3"
	reply6 := "the reply lookup of 3fff:20::1 for ::/0 from 8000:: arriving on eth0"
	failed := func(errno syscall.Errno) func(*Answer) {
		return func(a *Answer) {
			*a = Answer{Err: fmt.Errorf("kernel: look up the route: %w", errno), ReplyErr: errors.New("kernel: no reply lookup: the forward lookup failed")}
		}
	}
	for _, test := range []struct {
		name   string
		read   netip.Addr
		change func(*Answer)
		tree   map[string]string
		want   string
	}{
		{"a forward lookup the tun refuses", read4, failed(syscall.EHOSTUNREACH), map[string]string{"net/ipv4/conf/ranet3/forwarding": "0"},
			forward4 + " failed: no route to host, with net.ipv4.conf.ranet3.forwarding at 0"},
		{"a forward lookup finding a blackhole", read4, func(a *Answer) { a.Route = Route{Type: "blackhole"} }, nil,
			forward4 + " found a route of type blackhole"},
		{"a forward lookup whose one hop is dead", read4, func(a *Answer) { a.Route.Hops[0].Dead = true }, nil,
			forward4 + " found no live next hop among eth0"},
		{"a forward lookup finding no hop", read4, func(a *Answer) { a.Route.Hops = nil }, nil,
			forward4 + " found no live next hop"},
		{"a forward lookup back into the tun", read4, func(a *Answer) {
			a.Route.Hops = []Hop{{Device: "eth0", LinkDown: true}, {Device: readTUN}}
		}, nil, forward4 + " leaves by ranet3 again"},
		{"a reply lookup reverse path filtering refuses", read4, func(a *Answer) { a.Reply, a.ReplyErr = Route{}, syscall.EINVAL },
			map[string]string{"net/ipv4/conf/all/rp_filter": "1"}, reply4 + " failed: invalid argument, with reverse path filtering at 1 on eth0"},
		{"a reply lookup finding a throw", read4, func(a *Answer) { a.Reply = Route{Type: "throw"} }, nil,
			reply4 + " found a route of type throw"},
		{"a reply lookup whose one hop is link-down", read4, func(a *Answer) { a.Reply.Hops[0].LinkDown = true }, nil,
			reply4 + " found no live next hop among ranet3"},
		{"a reply lookup out of the uplink", read4, func(a *Answer) { a.Reply.Hops = append(a.Reply.Hops, Hop{Device: "eth1"}) }, nil,
			reply4 + " leaves by eth1 rather than ranet3"},
		{"an IPv6 forward lookup failing", read6, failed(syscall.ENETUNREACH), map[string]string{"net/ipv4/conf/ranet3/forwarding": "0"},
			forward6 + " failed: network is unreachable"},
		{"an IPv6 reply lookup out of the uplink", read6, func(a *Answer) { a.Reply.Hops = []Hop{{Device: "eth0"}} }, nil,
			reply6 + " leaves by eth0 rather than ranet3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := &lookupHost{answers: map[netip.Addr]Answer{read4: passingAnswer(), read6: passingAnswer()}, tree: test.tree}
			changed := host.answers[test.read]
			test.change(&changed)
			host.answers[test.read] = changed
			members := readMembers
			bus := events.New()
			tr := readingExit(t, Egress{Advertise: prefixes(t, "198.51.100.0/24", "::/0")}, host, &members, bus)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			stats := tr.Stats()
			if stats.Ready4 == test.read.Is4() || stats.Ready6 == test.read.Is6() || stats.Unready != test.want {
				t.Errorf("the pass reports ready %v and %v with the reason %q, want the family of %s alone not ready with %q",
					stats.Ready4, stats.Ready6, stats.Unready, test.read, test.want)
			}
			announced := []netip.Prefix{netip.MustParsePrefix("::/0")}
			if test.read.Is6() {
				announced = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
			}
			if got := tr.Announce(); !slices.Equal(got, announced) {
				t.Errorf("the pass announces %v, want %v alone", got, announced)
			}
			if got, want := readyEvents(bus), [][4]string{{fmt.Sprint(test.read.Is6()), fmt.Sprint(test.read.Is4()), test.want, ""}}; !slices.Equal(got, want) {
				t.Errorf("egress.ready recorded %q, want %q", got, want)
			}
			want := []Lookup{
				{Source: readMembers[0].Addr(), Destination: read4, IIF: readTUN, Reply: true},
				{Source: readMembers[1].Addr(), Destination: read6, IIF: readTUN, Reply: true},
			}
			if len(host.asked) != 1 || !slices.Equal(host.asked[0], want) {
				t.Errorf("the pass asked for %v, want one batch of %v", host.asked, want)
			}
		})
	}
}

// A failed IPv4 lookup names the setting of the device it arrived on that
// refuses it, read from the host's tree whatever errno the kernel answered:
// the tun's for a forward lookup and the uplink's for its reply, forwarding off
// ahead of reverse path filtering, at the larger of all's and the device's,
// and the other device's settings never
func TestFailedLookupNamesTheSettingWhateverTheErrno(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EHOSTUNREACH, syscall.EXDEV, syscall.EINVAL} {
		for _, reply := range []bool{false, true} {
			device, other := readTUN, "eth0"
			lookup := "the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3"
			if reply {
				device, other = other, device
				lookup = "the reply lookup of 192.0.2.1 for 198.51.100.0/24 from 198.51.100.128 arriving on eth0"
			}
			conf := func(device, name string) string { return "net/ipv4/conf/" + device + "/" + name }
			for _, setting := range []struct {
				tree map[string]string
				want string
			}{
				{map[string]string{conf(device, "forwarding"): "0", conf("all", "rp_filter"): "1"}, ", with net.ipv4.conf." + device + ".forwarding at 0"},
				{map[string]string{conf(device, "forwarding"): "1", conf("all", "rp_filter"): "1", conf(device, "rp_filter"): "0"}, ", with reverse path filtering at 1 on " + device},
				{map[string]string{conf("all", "rp_filter"): "0", conf(device, "rp_filter"): "2"}, ", with reverse path filtering at 2 on " + device},
				{map[string]string{conf(other, "forwarding"): "0", conf(other, "rp_filter"): "1"}, ""},
				{map[string]string{conf(device, "forwarding"): "1", conf("all", "rp_filter"): "0", conf(device, "rp_filter"): "0"}, ""},
				{nil, ""},
			} {
				answer := passingAnswer()
				refused := fmt.Errorf("kernel: look up the route: %w", errno)
				if reply {
					answer.Reply, answer.ReplyErr = Route{}, refused
				} else {
					answer = Answer{Err: refused, ReplyErr: errors.New("kernel: no reply lookup: the forward lookup failed")}
				}
				host := &lookupHost{answers: map[netip.Addr]Answer{read4: answer}, tree: setting.tree}
				members := readMembers[:1]
				tr := readingExit(t, Egress{Advertise: prefixes(t, "198.51.100.0/24", "::/0")}, host, &members, events.New())
				if err := tr.reconcile(); err != nil {
					t.Fatal(err)
				}
				if got, want := tr.Stats().Unready, lookup+" failed: "+errno.Error()+setting.want; got != want {
					t.Errorf("errno %d with the settings %v reads %q, want %q", errno, setting.tree, got, want)
				}
			}
		}
	}
}

// readyEvents is each egress.ready on bus, as its ipv4, ipv6, reason and
// skipped values
func readyEvents(bus *events.Bus) [][4]string {
	var out [][4]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
		out = append(out, [4]string{event.Attrs["ipv4"], event.Attrs["ipv6"], event.Attrs["reason"], event.Attrs["skipped"]})
	}
	return out
}

// A family no member gives a source to read from skips both its lookups and is
// judged by its rule and forwarding alone, whatever its lookups would answer,
// and the pass and the egress.ready event say so. The skip ends once a member
// of the family is routed, and the event says that too, the pair unmoved. A
// pass that changes none of it records no event
func TestFamilyWithNoMemberSkipsItsLookupsAndSaysSo(t *testing.T) {
	bus := events.New()
	host := &lookupHost{answers: map[netip.Addr]Answer{read4: passingAnswer(), read6: {Err: syscall.ENETUNREACH}}}
	members := readMembers[:1]
	var calls int
	tr := readingExit(t, Egress{Advertise: prefixes(t, "198.51.100.0/24", "::/0")}, host, &members, bus)
	tr.rt.Ready = func(bool, bool, bool) { calls++ }
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const skipped = "lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay"
	if stats := tr.Stats(); !stats.Ready4 || !stats.Ready6 || stats.Skipped != skipped {
		t.Errorf("with no IPv6 member the pass reports ready %v and %v, skipping %q, want both ready, skipping %q", stats.Ready4, stats.Ready6, stats.Skipped, skipped)
	}
	if want := []Lookup{{Source: readMembers[0].Addr(), Destination: read4, IIF: readTUN, Reply: true}}; len(host.asked) != 1 || !slices.Equal(host.asked[0], want) {
		t.Errorf("with no IPv6 member the pass asked for %v, want one batch of %v", host.asked, want)
	}
	if got, want := readyEvents(bus), [][4]string{{"true", "true", "", skipped}}; !slices.Equal(got, want) {
		t.Errorf("egress.ready recorded %q, want %q", got, want)
	}

	host.answers[read6] = passingAnswer()
	members = readMembers
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := tr.Stats(); !stats.Ready4 || !stats.Ready6 || stats.Skipped != "" {
		t.Errorf("with a member of each family the pass reports ready %v and %v, skipping %q, want both ready, skipping nothing", stats.Ready4, stats.Ready6, stats.Skipped)
	}
	want := [][4]string{{"true", "true", "", skipped}, {"true", "true", "", ""}}
	if got := readyEvents(bus); !slices.Equal(got, want) {
		t.Errorf("egress.ready recorded %q, want %q", got, want)
	}
	if calls != 1 {
		t.Errorf("Ready was told %d times, want once, the skip ending moving no family", calls)
	}

	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := readyEvents(bus); !slices.Equal(got, want) || calls != 1 {
		t.Errorf("after a pass changing nothing egress.ready recorded %q and Ready was told %d times, want %q and once", got, calls, want)
	}
}

// Where neither family is ready the reason names the family each of its parts
// holds, a family this node does not translate giving none, and a reason both
// families share is given once
func TestReasonNamesTheFamilyEachPartHolds(t *testing.T) {
	forward4 := "the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3 found a route of type blackhole"
	reply6 := "the reply lookup of 3fff:20::1 for ::/0 from 8000:: arriving on eth0 leaves by eth0 rather than ranet3"
	refused := errors.New("kernel: open a netlink socket: too many open files")
	for _, test := range []struct {
		name      string
		advertise []string
		err       error
		want      string
	}{
		{"ipv4 alone translated", []string{"198.51.100.0/24"}, nil, "ipv4 " + forward4},
		{"ipv6 alone translated", []string{"::/0"}, nil, "ipv6 " + reply6},
		{"both translated", []string{"198.51.100.0/24", "::/0"}, nil, "ipv4 " + forward4 + ", ipv6 " + reply6},
		{"both held by one failure", []string{"198.51.100.0/24", "::/0"}, refused, "the route lookups failed: " + refused.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			blackholed, uplinked := passingAnswer(), passingAnswer()
			blackholed.Route = Route{Type: "blackhole"}
			uplinked.Reply.Hops = []Hop{{Device: "eth0"}}
			host := &lookupHost{answers: map[netip.Addr]Answer{read4: blackholed, read6: uplinked}, err: test.err}
			members := readMembers
			tr := readingExit(t, Egress{Advertise: prefixes(t, test.advertise...)}, host, &members, events.New())
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			if stats := tr.Stats(); stats.Ready4 || stats.Ready6 || stats.Unready != test.want {
				t.Errorf("advertising %v the pass reports ready %v and %v with the reason %q, want neither ready with %q",
					test.advertise, stats.Ready4, stats.Ready6, stats.Unready, test.want)
			}
		})
	}
}

// A pass that holds a family not ready for another reason reports that
// reason, though it moves no family and tells Ready nothing
func TestReasonFollowsAPassThatMovesNoFamily(t *testing.T) {
	blackholed, uplinked := passingAnswer(), passingAnswer()
	blackholed.Route = Route{Type: "blackhole"}
	uplinked.Reply.Hops = []Hop{{Device: "eth1"}}
	host := &lookupHost{answers: map[netip.Addr]Answer{read4: blackholed, read6: passingAnswer()}}
	members := readMembers
	var calls int
	tr := readingExit(t, Egress{Advertise: prefixes(t, "198.51.100.0/24", "::/0")}, host, &members, events.New())
	tr.rt.Ready = func(bool, bool, bool) { calls++ }
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	host.answers[read4] = uplinked
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const want = "the reply lookup of 192.0.2.1 for 198.51.100.0/24 from 198.51.100.128 arriving on eth0 leaves by eth1 rather than ranet3"
	if stats := tr.Stats(); stats.Ready4 || !stats.Ready6 || stats.Unready != want || calls != 1 {
		t.Errorf("the second pass reports ready %v and %v with the reason %q after %d calls of Ready, want IPv4 alone not ready with %q after one",
			stats.Ready4, stats.Ready6, stats.Unready, calls, want)
	}
}

// A prefix holding no address the kernel takes as a unicast destination skips
// its own lookup and is named, its family judged by its other prefixes, and a
// family whose every prefix holds none is judged by its rule and forwarding
// alone
func TestPrefixWithNoReadAddressSkipsItsLookupAndIsNamed(t *testing.T) {
	host := &lookupHost{answers: map[netip.Addr]Answer{read4: passingAnswer(), read6: passingAnswer()}}
	members := readMembers
	cfg := Egress{Advertise: prefixes(t, "198.51.100.0/24", "fe80::/10", "::/0")}
	tr := readingExit(t, cfg, host, &members, events.New())
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const skipped = "lookup skipped for fe80::/10, which holds no address the kernel takes as a unicast destination"
	if stats := tr.Stats(); !stats.Ready4 || !stats.Ready6 || stats.Skipped != skipped {
		t.Errorf("the pass reports ready %v and %v, skipping %q, want both ready, skipping %q", stats.Ready4, stats.Ready6, stats.Skipped, skipped)
	}
	want := []Lookup{
		{Source: readMembers[0].Addr(), Destination: read4, IIF: readTUN, Reply: true},
		{Source: readMembers[1].Addr(), Destination: read6, IIF: readTUN, Reply: true},
	}
	if len(host.asked) != 1 || !slices.Equal(host.asked[0], want) {
		t.Errorf("the pass asked for %v, want one batch of %v", host.asked, want)
	}
	if got := tr.Announce(); !slices.Equal(got, plain(cfg.Advertise)) {
		t.Errorf("the pass announces %v, want %v", got, cfg.Advertise)
	}

	alone := &lookupHost{}
	tr = readingExit(t, Egress{Advertise: prefixes(t, "fe80::/10")}, alone, &members, events.New())
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := tr.Stats(); stats.Ready4 || !stats.Ready6 || stats.Skipped != skipped || len(alone.asked) != 0 {
		t.Errorf("advertising fe80::/10 alone the pass reports ready %v and %v, skipping %q, after asking for %v, want IPv6 alone ready, skipping %q and asking nothing",
			stats.Ready4, stats.Ready6, stats.Skipped, alone.asked, skipped)
	}
}

// The lookups read from the first member of the family holding a read address,
// by lowest base address and then longest prefix, a member holding none passed
// over
func TestLookupsReadFromTheFirstMemberHoldingAReadAddress(t *testing.T) {
	for _, test := range []struct {
		members []string
		family  uint8
		want    string
	}{
		{[]string{"203.0.113.0/24", "192.0.2.64/26", "192.0.2.0/24"}, FamilyIPv4, "192.0.2.128"},
		{[]string{"192.0.2.0/24", "192.0.2.0/25"}, FamilyIPv4, "192.0.2.64"},
		{[]string{"192.0.2.7/32", "0.0.0.0/32", "3fff:20::1/128"}, FamilyIPv4, "192.0.2.7"},
		{[]string{"3fff:20::1/128", "::1/128", "3fff:20::/48"}, FamilyIPv6, "3fff:20:0:8000::"},
		{[]string{"192.0.2.7/32"}, FamilyIPv6, ""},
		{nil, FamilyIPv4, ""},
	} {
		var members []netip.Prefix
		for _, member := range test.members {
			members = append(members, netip.MustParsePrefix(member))
		}
		got, ok := memberSource(members, test.family)
		if want, err := netip.ParseAddr(test.want); got != want || ok != (err == nil) {
			t.Errorf("the members %v read %s's lookups from %s (%v), want %q", test.members, familyName(test.family), got, ok, test.want)
		}
	}
}

// A batch that fails whole, or answers fewer lookups than it was handed,
// holds every family it read not ready with that reason, and leaves a family
// it read nothing for to its rule and forwarding
func TestFailedBatchHoldsEveryFamilyItRead(t *testing.T) {
	for _, test := range []struct {
		name   string
		answer func(*lookupHost) func([]Lookup) ([]Answer, error)
		want   string
	}{
		{"a batch failing whole", func(host *lookupHost) func([]Lookup) ([]Answer, error) {
			host.err = errors.New("kernel: open a netlink socket: too many open files")
			return host.lookup
		}, "the route lookups failed: kernel: open a netlink socket: too many open files"},
		{"a batch answering short", func(host *lookupHost) func([]Lookup) ([]Answer, error) {
			return func(lookups []Lookup) ([]Answer, error) {
				answers, err := host.lookup(lookups)
				return answers[:len(answers)-1], err
			}
		}, "the route lookups answered 0 of 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := &lookupHost{answers: map[netip.Addr]Answer{read4: passingAnswer()}}
			members := readMembers[:1]
			tr := readingExit(t, Egress{Advertise: prefixes(t, "198.51.100.0/24", "::/0")}, host, &members, events.New())
			tr.rt.Lookup = test.answer(host)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			if stats := tr.Stats(); stats.Ready4 || !stats.Ready6 || stats.Unready != test.want {
				t.Errorf("the pass reports ready %v and %v with the reason %q, want IPv4 alone not ready with %q", stats.Ready4, stats.Ready6, stats.Unready, test.want)
			}
		})
	}
}
