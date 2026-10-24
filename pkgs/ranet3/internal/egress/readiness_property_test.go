// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// memberPool is the members a pass draws from, of both families, a host route
// and wider prefixes among them
var memberPool = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.64/26"), netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("3fff:20::/48"), netip.MustParsePrefix("3fff:20::1/128"), netip.MustParsePrefix("2001:db8:5::/48"),
}

// lookupErrors answers a lookup the kernel refuses: the errnos of forwarding
// off, of reverse path filtering before and after Linux 6.13 and of no route,
// and the batch's own error for a nexthop object holding no hop
var lookupErrors = []error{
	syscall.EHOSTUNREACH, syscall.EXDEV, syscall.EINVAL, syscall.ENETUNREACH,
	errors.New("kernel: the route to 198.51.100.0/24 names nexthop object 7 without its hops"),
}

// hostRoute draws a route a lookup finds: unicast three times in four and
// otherwise of another type ip-route(8) names, with up to three hops, none
// among them as often as a nexthop object holding none would read, each on the
// tun or another device and now and then dead or link-down
func hostRoute(tc hegel.TestCase, tun string) Route {
	route := Route{Type: "unicast"}
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		route.Type = hegel.Draw(tc, hegel.SampledFrom([]string{"blackhole", "unreachable", "prohibit", "throw", "local"}))
	}
	for range hegel.Draw(tc, pbt.Spanning(0, 3)) {
		route.Hops = append(route.Hops, Hop{
			Device:   hegel.Draw(tc, hegel.SampledFrom([]string{tun, "eth0", "eth1"})),
			Dead:     hegel.Draw(tc, hegel.WeightedBooleans(1.0/6)),
			LinkDown: hegel.Draw(tc, hegel.WeightedBooleans(1.0/6)),
		})
	}
	return route
}

// hostAnswer is how a host answers the lookups to one destination: the forward
// route or its error, and the reply's
type hostAnswer struct {
	route, reply  Route
	err, replyErr error
}

// hostAnswers draws a host's answer to one destination, the forward route
// leaving by the uplink and the reply by the tun each half the time, and
// otherwise a drawn route or error
func hostAnswers(tun string) hegel.Generator[hostAnswer] {
	return hegel.Composite(func(tc hegel.TestCase) hostAnswer {
		var a hostAnswer
		switch {
		case hegel.Draw(tc, hegel.Booleans()):
			a.route = Route{Type: "unicast", Hops: []Hop{{Device: "eth0"}}}
		case hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)):
			a.err = hegel.Draw(tc, hegel.SampledFrom(lookupErrors))
		default:
			a.route = hostRoute(tc, tun)
		}
		switch {
		case hegel.Draw(tc, hegel.Booleans()):
			a.reply = Route{Type: "unicast", Hops: []Hop{{Device: tun}}}
		case hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)):
			a.replyErr = hegel.Draw(tc, hegel.SampledFrom(lookupErrors))
		default:
			a.reply = hostRoute(tc, tun)
		}
		return a
	})
}

// answer is a lookup's Answer from the host, as the batch gives it: the reply
// lookup arrives on the forward route's first hop neither dead nor link-down,
// and has an error of its own where the forward lookup failed or found none
func (a hostAnswer) answer(lookup Lookup) Answer {
	if a.err != nil {
		out := Answer{Err: a.err}
		if lookup.Reply {
			out.ReplyErr = errors.New("kernel: no reply lookup: the forward lookup failed")
		}
		return out
	}
	out := Answer{Route: a.route}
	if !lookup.Reply {
		return out
	}
	live := slices.IndexFunc(a.route.Hops, func(hop Hop) bool { return !hop.Dead && !hop.LinkDown })
	if live < 0 {
		out.ReplyErr = errors.New("kernel: no reply lookup: the route has no live next hop")
		return out
	}
	out.ReplyIIF, out.Reply, out.ReplyErr = a.route.Hops[live].Device, a.reply, a.replyErr
	return out
}

// modelLive is the devices of a route's hops the kernel marks neither dead nor
// link-down
func modelLive(route Route) []string {
	var devices []string
	for _, hop := range route.Hops {
		if !hop.Dead && !hop.LinkDown {
			devices = append(devices, hop.Device)
		}
	}
	return devices
}

// modelLookups is the lookups the model reads for a family whose rule and
// forwarding pass, empty where it skips them: from the read address of the
// first member of the family, by lowest base and then longest prefix, that
// holds one, to the read address of each prefix it advertises, or of its
// default where it advertises none, each arriving on the tun, the first asking
// for its reply. A family with no such member reads nothing
func modelLookups(cfg Egress, tun string, members []netip.Prefix, family uint8) []Lookup {
	of := func(prefix netip.Prefix) bool { return prefix.Addr().Is4() == (family == FamilyIPv4) }
	ordered := slices.SortedFunc(slices.Values(slices.DeleteFunc(slices.Clone(members), func(p netip.Prefix) bool { return !of(p) })),
		func(a, b netip.Prefix) int { return cmp.Or(a.Addr().Compare(b.Addr()), b.Bits()-a.Bits()) })
	var source netip.Addr
	for _, member := range ordered {
		if address, ok := readAddress(member); ok {
			source = address
			break
		}
	}
	if !source.IsValid() {
		return nil
	}
	var prefixes []netip.Prefix
	for _, prefix := range cfg.Advertise {
		if of(prefix.Prefix) {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}
	if len(prefixes) == 0 {
		prefixes = map[uint8][]netip.Prefix{FamilyIPv4: {netip.MustParsePrefix("0.0.0.0/0")}, FamilyIPv6: {netip.MustParsePrefix("::/0")}}[family]
	}
	var lookups []Lookup
	for _, prefix := range prefixes {
		if address, ok := readAddress(prefix); ok {
			lookups = append(lookups, Lookup{Source: source, Destination: address, IIF: tun, Reply: len(lookups) == 0})
		}
	}
	return lookups
}

// modelPasses is whether a family's lookups take a translated packet's path
// on host: every forward lookup finds a unicast route with a live hop and none
// of its live hops on the tun, and the first one's reply a unicast route whose
// live hops, at least one, are all the tun
func modelPasses(lookups []Lookup, host map[netip.Addr]hostAnswer, tun string) bool {
	for _, lookup := range lookups {
		a := host[lookup.Destination]
		if live := modelLive(a.route); a.err != nil || a.route.Type != "unicast" || len(live) == 0 || slices.Contains(live, tun) {
			return false
		}
	}
	first := host[lookups[0].Destination]
	live := modelLive(first.reply)
	return first.replyErr == nil && first.reply.Type == "unicast" && len(live) > 0 &&
		!slices.ContainsFunc(live, func(device string) bool { return device != tun })
}

// Over a run of passes on a host drawn anew for each, the rule and forwarding
// drawn as the egress segments' property draws them, the members drawn from a
// pool, none at all among them, and each destination's forward and reply
// answers drawn, the batch now and then failing whole or answering short: a
// family is ready exactly when the model says, the lookups handed to the batch
// are the model's, and the readiness kept in Stats, the prefixes announced and
// the pair and SID word handed to Ready move together. A family the model
// reads no lookup for, with no member to read from, is judged by its rule and
// forwarding alone, and the pass says what it skipped
func TestReadinessFollowsTheLookupsOverDrawnAnswers(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		cfg, rt := drawn.cfg, drawn.rt
		ht.Assume(cfg.Validate() == nil && cfg.Serves(rt.Steered) == nil)
		tun := rt.Interface
		be := &fakeBackend{}
		var now step
		onHost(&rt, &now)
		var members []netip.Prefix
		var host map[netip.Addr]hostAnswer
		var whole error
		var short bool
		var asked []Lookup
		rt.Members = func() []netip.Prefix { return slices.Clone(members) }
		rt.Sysctl = func(string) string { return "" }
		rt.Lookup = func(lookups []Lookup) ([]Answer, error) {
			if asked != nil {
				ht.Fatalf("a pass asked for lookups twice, %v and then %v", asked, lookups)
			}
			asked = slices.Clone(lookups)
			if whole != nil {
				return nil, whole
			}
			answers := make([]Answer, len(lookups))
			for i, lookup := range lookups {
				answers[i] = host[lookup.Destination].answer(lookup)
			}
			if short {
				answers = answers[:len(answers)-1]
			}
			return answers, nil
		}
		var calls [][3]bool
		rt.Ready = func(v4, v6, serves bool) { calls = append(calls, [3]bool{v4, v6, serves}) }
		tr := newTranslator(cfg, rt, be)
		desired := tr.desired()
		var destinations []netip.Addr
		for _, prefix := range append(plain(cfg.Advertise), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")) {
			if address, ok := readAddress(prefix); ok && !slices.Contains(destinations, address) {
				destinations = append(destinations, address)
			}
		}
		for pass := range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			now = hegel.Draw(ht, steps(desired))
			now.load(be)
			members = pbt.Subset(ht, memberPool, 0, 4)
			host = map[netip.Addr]hostAnswer{}
			for _, destination := range destinations {
				host[destination] = hegel.Draw(ht, hostAnswers(tun))
			}
			whole, short = nil, false
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/12)) {
				whole = errors.New("kernel: open a netlink socket: too many open files")
			} else {
				short = hegel.Draw(ht, hegel.WeightedBooleans(1.0/12))
			}
			asked = nil
			if now.enabled {
				_ = tr.reconcile()
			} else {
				_ = tr.stop()
			}

			written := writtenAfter(now, desired)
			var want [2]bool
			var wantAsked []Lookup
			skips := false
			for i, family := range []uint8{FamilyIPv4, FamilyIPv6} {
				advertised := slices.ContainsFunc(plain(cfg.Advertise), func(prefix netip.Prefix) bool { return prefix.Addr().Is4() == (i == 0) })
				forwards := []bool{now.forward4, now.forward6}[i]
				if !now.enabled || !(rt.Steered || advertised) || !written[family] || !forwards {
					continue
				}
				lookups := modelLookups(cfg, tun, members, family)
				if len(lookups) == 0 {
					want[i], skips = true, true
					continue
				}
				wantAsked = append(wantAsked, lookups...)
				want[i] = whole == nil && !short && modelPasses(lookups, host, tun)
			}
			if !slices.Equal(asked, wantAsked) {
				ht.Fatalf("pass %d over %+v with members %v asked for %v, want %v", pass, now, members, asked, wantAsked)
			}
			stats := tr.Stats()
			if [2]bool{stats.Ready4, stats.Ready6} != want {
				ht.Fatalf("pass %d over %+v with members %v and %v reports ready %v and %v (%q), want %v",
					pass, now, members, host, stats.Ready4, stats.Ready6, stats.Unready, want)
			}
			var announced []netip.Prefix
			for _, prefix := range plain(cfg.Advertise) {
				if want[0] && prefix.Addr().Is4() || want[1] && prefix.Addr().Is6() {
					announced = append(announced, prefix)
				}
			}
			if got := tr.Announce(); !slices.Equal(got, announced) {
				ht.Fatalf("pass %d ready %v announces %v, want %v", pass, want, got, announced)
			}
			serves := (want[0] || want[1]) && (want[0] || !now.forward4) && (want[1] || !now.forward6)
			got := [3]bool{}
			if len(calls) > 0 {
				got = calls[len(calls)-1]
			}
			if wantCall := [3]bool{want[0], want[1], serves}; got != wantCall {
				ht.Fatalf("pass %d over %+v left Ready holding %v, want %v", pass, now, got, wantCall)
			}
			if (stats.Skipped != "") != skips {
				ht.Fatalf("pass %d with members %v says it skipped %q, want a skip %v", pass, members, stats.Skipped, skips)
			}
		}
		for i := 1; i < len(calls); i++ {
			if calls[i] == calls[i-1] {
				ht.Fatalf("Ready was told %v twice in a row, in %v", calls[i], calls)
			}
		}
	})
}
