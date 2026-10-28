// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"cmp"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// walkedTable is one table's answer to the drawn packet: a route of a kind
// and a length, or none, and for IPv6 whether the lookup returns an exception
// cached under that route for the packet's destination
type walkedTable struct {
	// kind is unicast, unreachable, prohibit, blackhole, throw, or none
	kind   string
	bits   int
	cached bool
}

// walkedHost is a drawn host: its rules of every family in the order the
// kernel lists them, each table's answer for each destination, and whether
// what a rule carries of Unread holds: a selector matching the packet, or
// suppress_ifgroup naming the group of the device its lookup's route leaves by
type walkedHost struct {
	rules  []DumpedRule
	tables map[netip.Addr]map[uint32]walkedTable
	holds  map[DumpedRule]bool
}

// walkedPacket is a packet the host is checked against, iif the loopback for
// this host's own, and the errno a check outside the walk refused it with, 0
// for none
type walkedPacket struct {
	src, dst netip.Addr
	iif      string
	outside  syscall.Errno
}

// refusals is each errno a check outside fib_rules_lookup answers for the
// packet: IPv4's EINVAL, inet_rtm_getroute's for every drop of an arrival and
// the output path's for a source or destination it refuses, and IPv4's
// ENETUNREACH for this host's own packet from a source it does not hold
// (ip_route_output_key_hash_rcu)
func (p walkedPacket) refusals() []syscall.Errno {
	switch {
	case p.dst.Is6():
		return nil
	case p.iif == loopback && p.src.IsValid():
		return []syscall.Errno{syscall.EINVAL, syscall.ENETUNREACH}
	}
	return []syscall.Errno{syscall.EINVAL}
}

// walkedEnd is where the model's walk ended: the rule, or none past the last,
// and the route it answered or its errno
type walkedEnd struct {
	rule   DumpedRule
	ended  bool
	table  uint32
	bits   int
	cached bool
	errno  syscall.Errno
	// kind is the kind of the route the lookup that ended the walk found,
	// empty where an action ended it
	kind string
	// turned is the first rule that what it carries of Unread made jump or
	// end the walk, nil where none did
	turned *DumpedRule
}

// the errno of each terminal action (fib4_rule_action, __fib6_rule_action)
// and of each route type a table answers with (fib_props, fib6_prop)
var (
	walkedActionErrno = map[string]syscall.Errno{"unreachable": syscall.ENETUNREACH, "prohibit": syscall.EACCES, "blackhole": syscall.EINVAL}
	walkedRouteErrno  = map[string]syscall.Errno{"unreachable": syscall.EHOSTUNREACH, "prohibit": syscall.EACCES, "blackhole": syscall.EINVAL}
)

// match is fib_rule_match for a packet of no mark and no output device on a
// link no l3mdev master holds, then fib4_rule_match or fib6_rule_match, with
// a selector of Unread as holds says, then FIB_RULE_INVERT, which inverts
// them all. byUnread is the selector of Unread having made the rule match.
// suppress_ifgroup is no selector.
func (h walkedHost) match(p walkedPacket, rule DumpedRule) (matched, byUnread bool) {
	matched = p.selects(rule)
	decided := matched && rule.Unread&^SelectorSuppressIfgroup != 0
	if decided {
		matched = h.holds[rule]
	}
	if rule.Invert {
		matched = !matched
	}
	return matched, decided && matched
}

// selects is the selectors DumpedRule holds a value of
func (p walkedPacket) selects(rule DumpedRule) bool {
	ret := false
	switch {
	case rule.IIF != "" && rule.IIF != p.iif:
	case rule.OIF != "":
	case rule.FWMark&rule.FWMask != 0:
		// (rule->mark ^ fl->flowi_mark) & rule->mark_mask with the packet's
		// mark 0, under the mask a dump reads
	case rule.L3mdev:
	case rule.To.IsValid() && !rule.To.Contains(p.dst):
	case rule.From.IsValid() && p.dst.Is4():
		// the output lookup matches a packet with no source as from 0.0.0.0
		ret = rule.From.Contains(cmp.Or(p.src, netip.IPv4Unspecified()))
	case rule.From.IsValid():
		// without RT6_LOOKUP_F_HAS_SADDR a source selector never matches
		ret = p.src.IsValid() && rule.From.Contains(p.src)
	default:
		ret = true
	}
	return ret
}

// walk is fib_rules_lookup over the rules of the packet's family: a goto
// jumps to its ctarget, the first rule of its target's priority, and
// continues there, a nop continues, a terminal action ends with its errno, a
// lookup that finds no route or a throw answers EAGAIN and continues, one
// that finds a route of an error type ends with its errno, and one that finds
// a unicast route ends unless the rule suppresses its length. Past the last
// rule the lookup answers ESRCH, which both families report as ENETUNREACH.
// The end says the first rule its selector of Unread made the walk jump at or
// end on.
func (h walkedHost) walk(p walkedPacket) walkedEnd {
	var rules []DumpedRule
	for _, rule := range h.rules {
		if rule.Family == familyOf(p.dst) {
			rules = append(rules, rule)
		}
	}
	var turned *DumpedRule
	// end is the walk ended on rule, the first turned by its selector of
	// Unread where none before it was
	end := func(e walkedEnd, rule DumpedRule, byUnread bool) walkedEnd {
		if turned == nil && byUnread {
			turned = &rule
		}
		e.rule, e.ended, e.turned = rule, true, turned
		return e
	}
	i := 0
	for i < len(rules) {
		rule := rules[i]
		next := i + 1
		if matched, byUnread := h.match(p, rule); matched {
			switch rule.Action {
			case "goto":
				if target := slices.IndexFunc(rules, func(r DumpedRule) bool { return r.Priority == rule.Goto }); target >= 0 {
					next = target
					if turned == nil && byUnread {
						turned = &rule
					}
				}
			case "nop":
			case "lookup":
				answer := h.tables[p.dst][rule.Table]
				switch answer.kind {
				case "", "none", "throw":
				case "unicast":
					// fib4_rule_suppress and fib6_rule_suppress: the length of
					// the route returned, a /128 for an exception
					// (ip6_rt_cache_alloc), then the group of its device
					returned := answer.bits
					if answer.cached {
						returned = 128
					}
					grouped := rule.Unread&SelectorSuppressIfgroup != 0
					if bits, ok := rule.Suppress.Bits(); (!ok || returned > bits) && !(grouped && h.holds[rule]) {
						return end(walkedEnd{table: rule.Table, bits: answer.bits, cached: answer.cached, kind: answer.kind}, rule, byUnread || grouped)
					}
				default:
					return end(walkedEnd{errno: walkedRouteErrno[answer.kind], kind: answer.kind}, rule, byUnread)
				}
			default:
				return end(walkedEnd{errno: walkedActionErrno[rule.Action]}, rule, byUnread)
			}
		}
		i = next
	}
	return walkedEnd{errno: syscall.ENETUNREACH, turned: turned}
}

// walkedPools is each family's addresses and selectors: the destinations,
// the sources, and prefixes holding some of them
var walkedPools = map[bool]struct{ dst, src, prefixes []string }{
	false: {
		dst:      []string{"203.0.113.10", "192.0.2.20"},
		src:      []string{"192.0.2.1", "198.51.100.140"},
		prefixes: []string{"192.0.2.0/24", "203.0.113.0/24", "0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/8", "0.0.0.0/8", "198.51.100.128/25", "192.0.2.1/32"},
	},
	true: {
		dst:      []string{"2001:db8::10", "3fff::20"},
		src:      []string{"3fff::1", "2001:db8:2::5"},
		prefixes: []string{"3fff::/48", "2001:db8::/32", "::/1", "8000::/1", "::/8", "2001:db8:2::/64", "3fff::1/128"},
	},
}

// walkedTables are the tables a drawn host answers from: main and two of
// other programs, few enough that two lookups often read one
var walkedTables = []uint32{254, 100, 200}

// walkedLooked is the table a drawn rule reads, main as often as the two
// others together, so that a lookup ahead of the kernel's 32766 often reads
// the table the walk ends in
var walkedLooked = []uint32{254, 254, 100, 200}

// walkedPackets is every packet of a family's pools: to each destination,
// this host's own from no source and from each source, and an arrival on eth1
// from each source, each also refused by each check outside the walk that
// answers for it
func walkedPackets(v6 bool) []walkedPacket {
	pool := walkedPools[v6]
	var packets []walkedPacket
	for _, dst := range pool.dst {
		sweep := []walkedPacket{{dst: addr(dst), iif: loopback}}
		for _, src := range pool.src {
			for _, iif := range []string{loopback, "eth1"} {
				sweep = append(sweep, walkedPacket{src: addr(src), dst: addr(dst), iif: iif})
			}
		}
		for _, packet := range sweep {
			packets = append(packets, packet)
			for _, errno := range packet.refusals() {
				packet.outside = errno
				packets = append(packets, packet)
			}
		}
	}
	return packets
}

// drawWalked draws a host of one family: each table's answer for each
// destination, an IPv6 route now and then through an exception, one to eight
// rules of priorities that tie often, each a lookup, goto, nop or terminal
// action, with its selectors, its suppress length at, under or over its
// table's answer for one destination, and a goto's target a later priority or
// one where no rule sits, now and then a rule of the other family, an l3mdev
// lookup, a table on a rule of another action, or a selector or
// suppress_ifgroup the finder does not read, the rule inverted half the time
// and what it carries drawn to hold or not, and mostly the kernel's lookup of
// main at 32766 behind them. Most rules select every packet, so that a
// suppress, a goto, a nop or a source selector a packet with no source meets
// decides where the walk ends rather than a selector that passes the rule
// over. It returns the packets of the family's pools.
func drawWalked(ht *hegel.T) (walkedHost, []walkedPacket) {
	v6 := hegel.Draw(ht, hegel.Booleans())
	pool, width := walkedPools[v6], 32
	if v6 {
		width = 128
	}
	host := walkedHost{tables: map[netip.Addr]map[uint32]walkedTable{}, holds: map[DumpedRule]bool{}}
	for _, dst := range pool.dst {
		answers := map[uint32]walkedTable{}
		for _, table := range walkedTables {
			kind := hegel.Draw(ht, hegel.SampledFrom([]string{"unicast", "unicast", "unicast", "unicast", "none", "throw", "unreachable", "prohibit", "blackhole"}))
			answers[table] = walkedTable{kind: kind, bits: hegel.Draw(ht, pbt.Spanning(0, width)), cached: v6 && kind == "unicast" && hegel.Draw(ht, hegel.WeightedBooleans(0.2))}
		}
		host.tables[addr(dst)] = answers
	}
	other := FamilyIPv6
	family := FamilyIPv4
	if v6 {
		family, other = other, family
	}
	// half the IPv4 hosts meet a packet with no source with a source selector
	// holding 0.0.0.0 on every other rule
	unsourced := !v6 && hegel.Draw(ht, hegel.Booleans())
	selector := func(from bool) netip.Prefix {
		switch {
		case from && unsourced:
			if hegel.Draw(ht, hegel.Booleans()) {
				return prefix(hegel.Draw(ht, hegel.SampledFrom([]string{"0.0.0.0/1", "0.0.0.0/8"})))
			}
			return netip.Prefix{}
		case !hegel.Draw(ht, hegel.WeightedBooleans(0.25)):
			return netip.Prefix{}
		}
		return prefix(hegel.Draw(ht, hegel.SampledFrom(pool.prefixes)))
	}
	var drawn []walkedDraw
	for range hegel.Draw(ht, hegel.Integers(1, 8)) {
		rule := DumpedRule{Family: family, Priority: 10 * hegel.Draw(ht, pbt.Spanning[uint32](0, 8))}
		if hegel.Draw(ht, hegel.WeightedBooleans(0.1)) {
			rule.Family = other
		}
		rule.Action = hegel.Draw(ht, hegel.SampledFrom([]string{"lookup", "goto", "nop", "lookup", "goto", "nop", "lookup", "unreachable", "prohibit", "blackhole"}))
		rule.From, rule.To = selector(true), selector(false)
		rule.IIF = hegel.Draw(ht, hegel.SampledFrom([]string{"", "", "", "", "", "", "", loopback, loopback, "eth1", "eth2"}))
		if hegel.Draw(ht, hegel.WeightedBooleans(0.05)) {
			rule.OIF = "eth0"
		}
		marks := hegel.Draw(ht, hegel.SampledFrom([][2]uint32{{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0x72, 0}, {0x72, ^uint32(0)}, {0x72, 0xff}, {0, 0xff}}))
		rule.FWMark, rule.FWMask = marks[0], marks[1]
		switch {
		case rule.Action == "lookup" && hegel.Draw(ht, hegel.WeightedBooleans(0.1)):
			rule.L3mdev = true
		case rule.Action == "lookup":
			rule.Table = hegel.Draw(ht, hegel.SampledFrom(walkedLooked))
			if hegel.Draw(ht, hegel.WeightedBooleans(0.75)) {
				aimed := addr(hegel.Draw(ht, hegel.SampledFrom(pool.dst)))
				rule.Suppress = SuppressUpTo(max(0, host.tables[aimed][rule.Table].bits+hegel.Draw(ht, pbt.Spanning(-1, 1))))
			}
			rule.Invert = hegel.Draw(ht, hegel.WeightedBooleans(0.1))
		default:
			// the kernel holds a rule's table whatever its action, and one
			// of main's names the table a walk ending at 32766 reads
			if hegel.Draw(ht, hegel.WeightedBooleans(0.75)) {
				rule.Table = hegel.Draw(ht, hegel.SampledFrom([]uint32{254, 254, 254, 100, 200}))
			}
			rule.Invert = hegel.Draw(ht, hegel.WeightedBooleans(0.1))
		}
		// a selector or suppress_ifgroup, which the finder does not read, the
		// rule inverted half the time, and whether it holds
		holds := false
		if hegel.Draw(ht, hegel.WeightedBooleans(0.15)) {
			rule.Unread = hegel.Draw(ht, hegel.SampledFrom([]Selectors{SelectorIPProto, SelectorSuppressIfgroup}))
			rule.Invert = hegel.Draw(ht, hegel.Booleans())
			holds = hegel.Draw(ht, hegel.Booleans())
		}
		drawn = append(drawn, walkedDraw{rule, holds})
	}
	if hegel.Draw(ht, hegel.WeightedBooleans(0.9)) {
		drawn = append(drawn, walkedDraw{rule: DumpedRule{Family: family, Priority: 32766, Action: "lookup", Table: 254, Protocol: 2}})
	}
	slices.SortStableFunc(drawn, func(a, b walkedDraw) int { return cmp.Compare(a.rule.Priority, b.rule.Priority) })
	for i, d := range drawn {
		rule := d.rule
		if rule.Action == "goto" {
			// the kernel takes a goto only to a later priority
			var later []uint32
			for _, r := range drawn[i+1:] {
				if r.rule.Family == rule.Family && r.rule.Priority > rule.Priority {
					later = append(later, r.rule.Priority)
				}
			}
			rule.Goto = rule.Priority + 5
			if len(later) > 0 && hegel.Draw(ht, hegel.WeightedBooleans(0.9)) {
				rule.Goto = hegel.Draw(ht, hegel.SampledFrom(later))
			}
		}
		host.rules = append(host.rules, rule)
		host.holds[rule] = d.holds
	}
	return host, walkedPackets(v6)
}

// walkedDraw is a drawn rule and whether what it carries of Unread holds
type walkedDraw struct {
	rule  DumpedRule
	holds bool
}

// without is the host with each one of its rules deleted in turn, as the root
// test deletes the rule it names
func (h walkedHost) without() []walkedHost {
	var hosts []walkedHost
	for i := range h.rules {
		less := h
		less.rules = slices.Delete(slices.Clone(h.rules), i, i+1)
		hosts = append(hosts, less)
	}
	return hosts
}

// The finder sees only the kernel's answer, the model walks the tables
// themselves, for every packet of the host's family, on the drawn host and on
// it with each one of its rules deleted. Where a check outside the walk refused
// the packet, the finder names no rule as taken, at most a candidate. Where
// what the finder does not read, a selector or suppress_ifgroup, made the walk
// jump at or end on a rule, the finder lists that rule among those it assumed
// did not take the packet. Otherwise, where the walk ended on a rule by a
// unicast route or an action, the finder names exactly that rule, as a
// candidate where a check outside the walk answers the same errno for the
// packet. Where it ended on a route of an error type, the finder says that
// type, and names at most a terminal action of the same errno no earlier in
// the list. Where it ended on no rule, the finder names none.
func TestTakeRuleNamesTheRuleTheModelsWalkEndedOn(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn, packets := drawWalked(ht)
		for _, host := range append([]walkedHost{drawn}, drawn.without()...) {
			for _, packet := range packets {
				checkTaken(ht, host, packet)
			}
		}
	})
}

// checkTaken is the property for one host and one packet
func checkTaken(ht *hegel.T, host walkedHost, packet walkedPacket) {
	end := host.walk(packet)
	var route MatchedRoute
	var err error
	switch {
	case packet.outside != 0:
		err = lookupError(packet.outside)
	case end.errno != 0:
		err = lookupError(end.errno)
	default:
		route = MatchedRoute{Prefix: netip.PrefixFrom(packet.dst, end.bits).Masked(), Table: end.table, Type: "unicast", Exception: end.cached}
	}
	iif := packet.iif
	if iif == loopback {
		iif = ""
	}
	got := TakeRule(host.rules, packet.src, packet.dst, iif, route, err)
	switch {
	case packet.outside != 0:
		if got.Found && !got.Candidate {
			ht.Fatalf("over %+v a check outside the walk refused %+v with %v, and the finder took %+v", host.rules, packet, packet.outside, got)
		}
	case end.turned != nil:
		if !slices.Contains(got.Unread, *end.turned) {
			ht.Fatalf("over %+v the walk took %+v for %+v by a selector the finder does not read, and the finder answered %+v without listing it", host.rules, *end.turned, packet, got)
		}
	case !end.ended:
		if got.Found || got.RouteType != "" {
			ht.Fatalf("over %+v the walk of %+v ended past the last rule with %v, and the finder answered %+v", host.rules, packet, end.errno, got)
		}
	case end.kind == "unicast" || end.kind == "":
		if !got.Found || got.Rule != end.rule || got.Candidate != slices.Contains(packet.refusals(), end.errno) {
			ht.Fatalf("over %+v the walk of %+v ended on %+v with %+v, and the finder answered %+v", host.rules, packet, end.rule, end, got)
		}
	default:
		errno, terminal := walkedActionErrno[got.Rule.Action]
		if got.RouteType != end.kind || got.Found && (!terminal || errno != end.errno || got.Rule.Priority < end.rule.Priority) {
			ht.Fatalf("over %+v the walk of %+v ended on %+v by a route of type %s, and the finder answered %+v", host.rules, packet, end.rule, end.kind, got)
		}
	}
}
