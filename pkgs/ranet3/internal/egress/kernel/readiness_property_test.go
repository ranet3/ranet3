// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// memberPool is the members a pass draws from, of both families, a host route
// and wider prefixes among them
var memberPool = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.64/26"), netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("3fff:20::/48"), netip.MustParsePrefix("3fff:20::1/128"), netip.MustParsePrefix("2001:db8:5::/48"),
}

// moved is members with each family's moved, so a family that had members has
// none and one that had none has some of its part of the pool
func moved(tc hegel.TestCase, members []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, is4 := range []bool{true, false} {
		of := func(prefix netip.Prefix) bool { return prefix.Addr().Is4() == is4 }
		if slices.ContainsFunc(members, of) {
			continue
		}
		pool := slices.DeleteFunc(slices.Clone(memberPool), func(prefix netip.Prefix) bool { return !of(prefix) })
		out = append(out, pbt.Subset(tc, pool, 1, len(pool))...)
	}
	return out
}

// lookupErrors answers a lookup the kernel refuses: the errnos of forwarding
// off, of reverse path filtering before and after Linux 6.13 and of no route,
// and the batch's own error for a nexthop object holding no hop
var lookupErrors = []error{
	syscall.EHOSTUNREACH, syscall.EXDEV, syscall.EINVAL, syscall.ENETUNREACH,
	errors.New("kernel: the route to 198.51.100.0/24 names nexthop object 7 without its hops"),
}

// routeType draws a route's type: unicast three times in four and otherwise
// another type ip-route(8) names
func routeType(tc hegel.TestCase) string {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		return hegel.Draw(tc, hegel.SampledFrom([]string{"blackhole", "unreachable", "prohibit", "throw", "local"}))
	}
	return "unicast"
}

// hostRoute draws a route a lookup finds, of a drawn type, with up to three
// hops, none among them as often as a nexthop object holding none would read,
// each on the tun or another device and now and then dead or link-down
func hostRoute(tc hegel.TestCase, tun string) Route {
	route := Route{Type: routeType(tc)}
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

// notLive is each way the kernel marks a hop that carries nothing
var notLive = []Hop{{Dead: true}, {LinkDown: true}, {Dead: true, LinkDown: true}}

// beside is route with, half the time, another hop on device, marked in one of
// the notLive ways, so the route still takes a packet only where it did
func beside(tc hegel.TestCase, route Route, device string) Route {
	if hegel.Draw(tc, hegel.Booleans()) {
		hop := hegel.Draw(tc, hegel.SampledFrom(notLive))
		hop.Device = device
		route.Hops = append(slices.Clone(route.Hops), hop)
	}
	return route
}

// hostAnswers draws a host's answer to one destination: the forward route
// leaving by the uplink and the reply by the tun each half the time, half of
// those with a hop on the other device beside it that is not live, and
// otherwise a drawn route or error. Such a hop is the nearest miss, since
// taken as live it sends a translated packet or its reply the wrong way, and
// so is a route of another type whose hops pass, which the type is drawn for
func hostAnswers(tun string) hegel.Generator[hostAnswer] {
	return hegel.Composite(func(tc hegel.TestCase) hostAnswer {
		var a hostAnswer
		switch {
		case hegel.Draw(tc, hegel.Booleans()):
			a.route = beside(tc, Route{Type: routeType(tc), Hops: []Hop{{Device: "eth0"}}}, tun)
		case hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)):
			a.err = hegel.Draw(tc, hegel.SampledFrom(lookupErrors))
		default:
			a.route = hostRoute(tc, tun)
		}
		switch {
		case hegel.Draw(tc, hegel.Booleans()):
			a.reply = beside(tc, Route{Type: routeType(tc), Hops: []Hop{{Device: tun}}}, "eth0")
		case hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)):
			a.replyErr = hegel.Draw(tc, hegel.SampledFrom(lookupErrors))
		default:
			a.reply = hostRoute(tc, tun)
		}
		return a
	})
}

// heldAnswers draws a host's answer to the lookup of an address a class
// translates to: its local route three times in four, and otherwise an error
// or a route of a drawn type, local among them
func heldAnswers() hegel.Generator[Answer] {
	return hegel.Composite(func(tc hegel.TestCase) Answer {
		switch {
		case hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)):
			return Answer{Route: Route{Type: "local", Hops: []Hop{{Device: "lo"}}}}
		case hegel.Draw(tc, hegel.Booleans()):
			return Answer{Err: hegel.Draw(tc, hegel.SampledFrom(lookupErrors))}
		}
		return Answer{Route: hostRoute(tc, "lo")}
	})
}

// modelClassAddresses is the addresses the classes of family translate to,
// each once, in order
func modelClassAddresses(cfg egress.Egress, family uint8) []netip.Addr {
	var out []netip.Addr
	for _, class := range cfg.Translate {
		if egress.AddressFamily(class.From.Addr()) == family && class.To.Addr.IsValid() && !slices.Contains(out, class.To.Addr) {
			out = append(out, class.To.Addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// modelUnheld is the reason of the first of addresses the host does not hold,
// whose lookup failed or found a route of a type other than local, and empty
// where it holds each
func modelUnheld(addresses []netip.Addr, held map[netip.Addr]Answer) string {
	for _, address := range addresses {
		named := "the lookup of " + address.String() + ", an address cap.egress translate names,"
		switch answer := held[address]; {
		case answer.Err != nil:
			return named + " failed: " + answer.Err.Error()
		case answer.Route.Type != "local":
			return named + " found a route of type " + answer.Route.Type + ", so this host does not hold it"
		}
	}
	return ""
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
// for its reply, with the prefix each reads. A family with no such member reads
// nothing
func modelLookups(cfg egress.Egress, tun string, members []netip.Prefix, family uint8) ([]Lookup, []netip.Prefix) {
	of := func(prefix netip.Prefix) bool { return prefix.Addr().Is4() == (family == egress.FamilyIPv4) }
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
		return nil, nil
	}
	var prefixes []netip.Prefix
	for _, prefix := range cfg.Advertise {
		if of(prefix.Prefix) {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}
	if len(prefixes) == 0 {
		prefixes = map[uint8][]netip.Prefix{egress.FamilyIPv4: {netip.MustParsePrefix("0.0.0.0/0")}, egress.FamilyIPv6: {netip.MustParsePrefix("::/0")}}[family]
	}
	var lookups []Lookup
	var read []netip.Prefix
	for _, prefix := range prefixes {
		if address, ok := readAddress(prefix); ok {
			lookups = append(lookups, Lookup{Source: source, Destination: address, IIF: tun, Reply: len(lookups) == 0})
			read = append(read, prefix)
		}
	}
	return lookups, read
}

// modelUnusable is how the reason of a lookup ends where its answer carries
// nothing whatever its devices: an error, as the kernel words it, since the
// property's host holds no setting that names one, a type other than unicast,
// or no live hop, naming the devices of the hops there are
func modelUnusable(route Route, err error) string {
	switch {
	case err != nil:
		return " failed: " + err.Error()
	case route.Type != "unicast":
		return " found a route of type " + route.Type
	case len(modelLive(route)) > 0:
		return ""
	case len(route.Hops) == 0:
		return " found no live next hop"
	}
	var devices []string
	for _, hop := range route.Hops {
		devices = append(devices, hop.Device)
	}
	return " found no live next hop among " + strings.Join(devices, " ")
}

// modelFailure is the reason of the first of a family's lookups that does not
// take a translated packet's path on host, read for prefixes in order, and
// empty where every lookup takes it. Each forward lookup, in order, must find
// a unicast route with a live hop and none of its live hops on the tun, and
// then the first one's reply, arriving on that lookup's first live hop, a
// unicast route whose live hops, at least one, are all the tun
func modelFailure(lookups []Lookup, prefixes []netip.Prefix, host map[netip.Addr]hostAnswer, tun string) string {
	for i, lookup := range lookups {
		a := host[lookup.Destination]
		named := "the lookup of " + lookup.Destination.String() + " for " + prefixes[i].String() + " from " + lookup.Source.String() + " arriving on " + tun
		if why := modelUnusable(a.route, a.err); why != "" {
			return named + why
		}
		if slices.Contains(modelLive(a.route), tun) {
			return named + " leaves by " + tun + " again"
		}
	}
	first := host[lookups[0].Destination]
	named := "the reply lookup of " + lookups[0].Source.String() + " for " + prefixes[0].String() + " from " + lookups[0].Destination.String() +
		" arriving on " + modelLive(first.route)[0]
	if why := modelUnusable(first.reply, first.replyErr); why != "" {
		return named + why
	}
	if other := slices.DeleteFunc(modelLive(first.reply), func(device string) bool { return device == tun }); len(other) > 0 {
		return named + " leaves by " + strings.Join(other, " ") + " rather than " + tun
	}
	return ""
}

// holdsReason reports unready holding why as one family's whole reason in each
// form unreadyText writes: alone, after its family's name, or as the IPv4 or the
// IPv6 one of both
func holdsReason(unready, why string) bool {
	return unready == why || unready == "ipv4 "+why || unready == "ipv6 "+why ||
		strings.HasPrefix(unready, "ipv4 "+why+", ipv6 ") || strings.HasSuffix(unready, ", ipv6 "+why)
}

// Over a run of pairs of passes, the first of each on a host drawn anew, the
// rule and forwarding drawn as the egress segments' property draws them, the
// members drawn from a pool, none at all among them, each destination's
// forward and reply answers drawn and so the answer to the lookup of each
// address a class translates to, the batch now and then failing whole or
// answering short: a family is ready exactly when the model says, the lookups
// handed to the batch are the model's, and the readiness kept for Status, the
// prefixes announced and the pair and SID word handed to Ready move together.
// A family the model reads no lookup for, with no address of a class and no
// member to read from, is judged by its rule and forwarding alone, and a pass
// with no member of a family says it skipped that family's forward lookups.
//
// A family the lookups hold not ready gives the whole reason of the first
// lookup the model finds failing, a class's address first, so a lookup judged
// wrongly shows even where a later one fails as well, as the reply does after a
// forward route with no live hop, and so does a reason right in its first words
// alone. The second pass of a pair runs over the host, the answers and the
// batch of the first with each family's members moved, so the skip moves and,
// where the lookups of the families moved pass, nothing else does
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
		var held map[netip.Addr]Answer
		var whole error
		var short bool
		var asked []Lookup
		rt.Members = func() []netip.Prefix { return slices.Clone(members) }
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
				if !lookup.Source.IsValid() {
					answers[i] = held[lookup.Destination]
					continue
				}
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
		for pass := range 2 * hegel.Draw(ht, pbt.Spanning(1, 4)) {
			if pass%2 == 0 {
				now = hegel.Draw(ht, steps(desired))
				host = map[netip.Addr]hostAnswer{}
				for _, destination := range destinations {
					host[destination] = hegel.Draw(ht, hostAnswers(tun))
				}
				held = map[netip.Addr]Answer{}
				for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
					for _, address := range modelClassAddresses(cfg, family) {
						held[address] = hegel.Draw(ht, heldAnswers())
					}
				}
				whole, short = nil, false
				if hegel.Draw(ht, hegel.WeightedBooleans(1.0/12)) {
					whole = errors.New("kernel: open a netlink socket: too many open files")
				} else {
					short = hegel.Draw(ht, hegel.WeightedBooleans(1.0/12))
				}
				members = pbt.Subset(ht, memberPool, 0, 4)
			} else {
				members = moved(ht, members)
			}
			now.load(be)
			asked = nil
			if now.enabled {
				_ = tr.reconcile()
			} else {
				_ = tr.stop()
			}

			written := writtenAfter(now, desired)
			var want [2]bool
			var wantAsked []Lookup
			var named []string
			skips := false
			for i, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
				advertised := slices.ContainsFunc(plain(cfg.Advertise), func(prefix netip.Prefix) bool { return prefix.Addr().Is4() == (i == 0) })
				forwards := []bool{now.forward4, now.forward6}[i]
				if !now.enabled || !(rt.Steered || advertised) || !written[family] || !forwards {
					continue
				}
				addresses := modelClassAddresses(cfg, family)
				for _, address := range addresses {
					wantAsked = append(wantAsked, Lookup{Destination: address})
				}
				lookups, prefixes := modelLookups(cfg, tun, members, family)
				wantAsked = append(wantAsked, lookups...)
				skips = skips || len(lookups) == 0
				failed := modelUnheld(addresses, held)
				if failed == "" && len(lookups) > 0 {
					failed = modelFailure(lookups, prefixes, host, tun)
				}
				switch {
				case len(addresses) == 0 && len(lookups) == 0:
					want[i] = true
				case whole != nil || short:
				case failed != "":
					named = append(named, failed)
				default:
					want[i] = true
				}
			}
			if !slices.Equal(asked, wantAsked) {
				ht.Fatalf("pass %d over %+v with members %v asked for %v, want %v", pass, now, members, asked, wantAsked)
			}
			stats := tr.lastPass()
			if [2]bool{stats.Ready4, stats.Ready6} != want {
				ht.Fatalf("pass %d over %+v with members %v, %v and %v reports ready %v and %v (%q), want %v",
					pass, now, members, host, held, stats.Ready4, stats.Ready6, stats.Unready, want)
			}
			for _, why := range named {
				if !holdsReason(stats.Unready, why) {
					ht.Fatalf("pass %d over %+v with members %v, %v and %v gives the reason %q, which does not hold %q whole",
						pass, now, members, host, held, stats.Unready, why)
				}
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
