// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"syscall"

	"ranet3.com/pkgs/ranet3/schema"
)

// TakenRule is the rule TakeRule finds a lookup ended on
type TakenRule struct {
	// Rule is the rule named, set where Found
	Rule  DumpedRule
	Found bool
	// Candidate is Rule named only as the terminal rule the walk ends on if
	// the walk raised the kernel's errno: a check outside the walk answers
	// that errno for this packet too, so the walk may not have reached Rule
	Candidate bool
	// RouteType is the type of route whose errno the kernel answered with,
	// unreachable, prohibit or blackhole, empty for any other answer. A table
	// a lookup ahead of Rule reads, or ahead of the walk's end where none is
	// found, may hold such a route and have ended the walk there
	RouteType string
	// Unread is each rule the walk reached ahead of its end whose taking the
	// packet turns on what DumpedRule holds no value of, in walk order: a
	// selector, where every selector it reads holds, or suppress_ifgroup on a
	// lookup that would be named. The answer assumed none of them took the
	// packet.
	Unread []DumpedRule
}

// errnoRouteTypes is the route type whose lookup answers each errno, the
// same in fib_props and ip6_rt_type_to_error
var errnoRouteTypes = map[syscall.Errno]string{
	syscall.EHOSTUNREACH: "unreachable",
	syscall.EACCES:       "prohibit",
	syscall.EINVAL:       "blackhole",
}

// actionErrno is the errno a rule of a terminal action ends the walk with, as
// fib4_rule_action and __fib6_rule_action answer it, EINVAL for an action
// either names nothing for
func actionErrno(action string) syscall.Errno {
	switch action {
	case "unreachable":
		return syscall.ENETUNREACH
	case "prohibit":
		return syscall.EACCES
	}
	return syscall.EINVAL
}

// raisedOutside reports errno being one a check outside fib_rules_lookup
// answers for the packet too: IPv4's EINVAL, which inet_rtm_getroute answers
// for every drop of an arrival and the output path for a source or
// destination it refuses (ip_route_output_key_hash_rcu, __mkroute_output), and
// IPv4's ENETUNREACH for this host's own packet from a source it does not hold
func raisedOutside(family Family, errno syscall.Errno, src netip.Addr, own bool) bool {
	return family == FamilyIPv4 && (errno == syscall.EINVAL || errno == syscall.ENETUNREACH && own && src.IsValid())
}

// TakeRule names the rule the kernel's walk ended on, as far as its answer
// tells, for an unmarked packet from src to dst, arriving on iif or this
// host's own where iif is empty, given the route the kernel matched or the
// error it answered with. The kernel names no rule, so this walks the rules
// of dst's family in the order a dump lists them, stably by priority, as
// fib_rules_lookup does:
//   - a rule matches as fib_rule_match matches it: iif, the loopback for this
//     host's own packet, an oif never, the mark under its mask against none,
//     from and to, then invert. An IPv4 packet with no source is matched as
//     from 0.0.0.0 and an IPv6 one as from no address, as the output lookup
//     matches them before it picks the source
//   - a goto continues at the first rule of its target's priority, and is
//     passed over where none sits there, and a nop continues
//   - a lookup of another table than the answered one is passed over, the
//     kernel having found no route there, or a throw, or a suppressed one
//   - a lookup of the answered table whose suppress length is at least the
//     answered prefix's, 128 for an IPv6 exception, is passed over, and the
//     first that is not is named
//   - an l3mdev lookup is passed over and never named: its table is that of
//     the master the packet's device belongs to, which no dump names, so a
//     packet arriving on a device of an l3mdev master is outside this reading
//   - an unreachable, prohibit or blackhole rule ends the walk, and is named
//     where the kernel's errno is the one its action answers, as a Candidate
//     where a check outside the walk answers that errno for the packet too
//
// A route of type unreachable, prohibit or blackhole ends the walk at its
// lookup with EHOSTUNREACH, EACCES or EINVAL whatever the rule's suppress
// length, and RouteType says when one may have. Where no rule fits the answer,
// Found is false and no nearest rule is named. A rule carrying a selector
// DumpedRule holds no value of, such as uidrange, ipproto, a port, a dscp, a
// flowlabel or a tun_id, is listed in Unread and passed over where every
// selector it reads holds, inverted or not, since the unread one then decides
// its match. Where a read one fails, it matches if inverted and is walked, and
// is passed over if not. A lookup carrying suppress_ifgroup that would be
// named is listed in Unread and passed over, its answer taken as suppressed.
// A route of no table entry, NoEntry, is no lookup's, and names no rule. Nor
// does an IPv4 arrival to a group or to 0.0.0.0/8, for which the kernel walks
// no rule (ip_route_input_rcu, ip_route_input_slow).
func TakeRule(rules []DumpedRule, src, dst netip.Addr, iif string, route MatchedRoute, err error) TakenRule {
	if err == nil && route.NoEntry {
		return TakenRule{}
	}
	family := familyOf(dst)
	own := iif == ""
	if !own && family == FamilyIPv4 && (dst.IsMulticast() || dst.As4()[0] == 0) {
		return TakenRule{}
	}
	rules = slices.DeleteFunc(slices.Clone(rules), func(rule DumpedRule) bool { return rule.Family != family })
	slices.SortStableFunc(rules, func(a, b DumpedRule) int { return cmp.Compare(a.Priority, b.Priority) })
	if own {
		iif = loopback
	}
	var errno syscall.Errno
	if err != nil && !errors.As(err, &errno) {
		return TakenRule{}
	}
	table := route.Table
	// IPv4 keeps local and main in one trie, answered as main, until the
	// first rule beside the kernel's own three is added (fib_unmerge). The
	// limited broadcast is answered as a broadcast whatever entry it matched
	// (__mkroute_output)
	if err == nil && family == FamilyIPv4 && table == uint32(schema.TableMain) && (route.Type == "local" || route.Type == "broadcast" && dst != limitedBroadcast.Addr()) && onlyKernelRules(rules) {
		table = uint32(schema.TableLocal)
	}
	// fib6_rule_suppress reads the length of the route the lookup returns,
	// an exception's /128 rather than the length of the route it hangs off
	answered := route.Prefix.Bits()
	if route.Exception {
		answered = 128
	}
	looked := false
	var unread []DumpedRule
	ended := func(taken TakenRule) TakenRule {
		taken.Unread = unread
		if err != nil && looked {
			taken.RouteType = errnoRouteTypes[errno]
		}
		return taken
	}
	for i := 0; i < len(rules); i++ {
		rule := rules[i]
		// the kernel inverts the match of every selector, read or not
		held := selectorsHold(rule, src, dst, iif)
		if rule.Unread&^SelectorSuppressIfgroup != 0 && held {
			unread = append(unread, rule)
			continue
		}
		if held == rule.Invert {
			continue
		}
		switch rule.Action {
		case actionGoto.String():
			if target := slices.IndexFunc(rules, func(r DumpedRule) bool { return r.Priority == rule.Goto }); target > i {
				i = target - 1
			}
			continue
		case actionNop.String():
			continue
		case actionLookup.String():
			looked = true
			if err != nil || rule.L3mdev || rule.Table != table {
				continue
			}
			if bits, ok := rule.Suppress.Bits(); ok && answered <= bits {
				continue
			}
			if rule.Unread&SelectorSuppressIfgroup != 0 {
				unread = append(unread, rule)
				continue
			}
			return ended(TakenRule{Rule: rule, Found: true})
		}
		if err != nil && actionErrno(rule.Action) == errno {
			return ended(TakenRule{Rule: rule, Found: true, Candidate: raisedOutside(family, errno, src, own)})
		}
		return ended(TakenRule{})
	}
	return ended(TakenRule{})
}

// selectorsHold is fib_rule_match short of its invert, with the families' own
// match, over the selectors DumpedRule holds for a packet with no mark and no
// output device. The mark compares under the mask as dumped, which the kernel
// filled with every bit where the rule's request named none.
func selectorsHold(rule DumpedRule, src, dst netip.Addr, iif string) bool {
	if !src.IsValid() && dst.Is4() {
		src = netip.IPv4Unspecified()
	}
	return (rule.IIF == "" || rule.IIF == iif) && rule.OIF == "" && rule.FWMark&rule.FWMask == 0 &&
		(!rule.To.IsValid() || rule.To.Contains(dst)) && (!rule.From.IsValid() || rule.From.Contains(src))
}

// onlyKernelRules reports rules being the three a family starts with, a lookup
// of local at 0, of main at 32766 and of default at 32767, selecting all
func onlyKernelRules(rules []DumpedRule) bool {
	start := []DumpedRule{
		{Priority: 0, Table: uint32(schema.TableLocal)},
		{Priority: 32766, Table: uint32(schema.TableMain)},
		{Priority: 32767, Table: uint32(schema.TableDefault)},
	}
	return slices.EqualFunc(rules, start, func(held, want DumpedRule) bool {
		held.Family, held.Protocol = "", 0
		want.Action = actionLookup.String()
		return held == want
	})
}
