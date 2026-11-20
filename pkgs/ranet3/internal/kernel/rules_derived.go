// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// derivedRules is the policy rules routing.md's "Policy rules on Linux" lists,
// for the mesh's table id, the overlay and this node's own prefixes, in both
// families. Each nop comes ahead of the goto that lands on it, so a pass adding
// them in this order holds a goto with nothing to land on only where the add of
// its nop failed. The kernel passes such a goto over, as it would a missing
// one, so the underlay's marked packets meet the block's lookups until a later
// pass adds the nop.
//
// 5420 suppresses a route as long as the family's floor less one or shorter,
// the length of a route that counts as a default by its length, but never an
// unreachable, blackhole or prohibit one.
// routing.md's "Where a lookup ends on Linux" gives where each lookup ends.
//
// Mode 2 (exit.on) adds 5405, 5435 and 5440 to each family the tun holds an
// overlay address of, and a family it holds none of runs mode off's rules.
// Mode 3 sets exit.on too, so every rule this comment gives for mode 2 holds
// for it.
// Neither 5405 nor 5435 selects a source overlapping the overlay or this
// node's own prefixes: 5405 comes ahead of 5430, so an overlay address on lo,
// or an address in a LAN this node announces, would otherwise leave by main
// where mode off sends it into the mesh. A selector overlapping either is left
// out whole. One that a carve-out holds whole and no entry of the mesh's table
// inside that carve-out holds is not left out for the overlay, since the link's
// neighbors hold its addresses.
//
// Under fallback = "none" (exit.fallback) mode 2 adds two more to both
// families, so a family the tun holds no overlay address of runs mode off's
// rules and these two:
//   - 5445 looks main up to each of this node's own prefixes and each
//     carve-out the mesh's table throws, which its lookups pass on, so the host
//     reaches its own prefix beyond the gateway and a carved link's neighbors
//   - 5450 fails as unreachable every unmarked lookup of the host's own
//     traffic and of what it forwards from each link forward expands to that
//     no rule above answered, so a connect meets ENETUNREACH at once while
//     the mesh holds no default, where the filter's drop alone would leave it
//     waiting
//
// While the kill switch does not hold (exit.unheld) it leaves 5405
// and 5435 out, so the host's own unmarked lookups from the uplink's addresses
// and networks meet 5440, 5445 and 5450 rather than main, but for a route of
// main longer than /0, which 5410 still takes.
func derivedRules(id schema.TableID, overlay []schema.Prefix, own []netip.Prefix, exit exitView) []Rule {
	var out []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		floor := schema.MinSubnetBits4
		if family == FamilyIPv6 {
			floor = schema.MinSubnetBits6
		}
		out = append(out,
			Rule{Family: family, Priority: priorityOverlayEnd, action: actionNop},
			Rule{Family: family, Priority: priorityMeshEnd, action: actionNop},
			Rule{Family: family, Priority: priorityUnderlayPastOverlay, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityOverlayEnd},
		)
		for _, prefix := range familyPrefixes(family, SchemaPrefixes(overlay)) {
			out = append(out, Rule{Family: family, Priority: priorityOverlay, To: schema.PrefixFrom(prefix), Table: id})
		}
		out = append(out, Rule{Family: family, Priority: priorityUnderlayPastMesh, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityMeshEnd})
		addresses, networks := exit.sources(family, SchemaPrefixes(overlay), own)
		for _, address := range addresses {
			out = append(out, Rule{Family: family, Priority: priorityUplinkSource, From: schema.PrefixFrom(address), IIF: linuxLoopback, Table: schema.TableMain})
		}
		out = append(out,
			Rule{Family: family, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)},
			Rule{Family: family, Priority: priorityMesh, Table: id, suppress: SuppressUpTo(floor - 1)},
		)
		for _, prefix := range outermost(familyPrefixes(family, own)) {
			out = append(out, Rule{Family: family, Priority: priorityOwn, From: schema.PrefixFrom(prefix), Table: id})
		}
		if !exit.on {
			continue
		}
		if !slices.Contains(exit.unaddressed, family) {
			for _, network := range networks {
				out = append(out, Rule{Family: family, Priority: priorityLinkSource, From: schema.PrefixFrom(network), IIF: linuxLoopback, Table: schema.TableMain})
			}
			out = append(out, Rule{Family: family, Priority: priorityCatchAll, IIF: linuxLoopback, Table: id})
			for _, link := range exit.forwarded {
				out = append(out, Rule{Family: family, Priority: priorityCatchAll, IIF: link, Table: id})
			}
		}
		if !exit.fallback {
			continue
		}
		for _, prefix := range familyPrefixes(family, exit.own) {
			out = append(out, Rule{Family: family, Priority: priorityOwnPastMesh, To: schema.PrefixFrom(prefix), Table: schema.TableMain})
		}
		out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: linuxLoopback, action: actionUnreachable})
		for _, link := range exit.forwarded {
			out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: link, action: actionUnreachable})
		}
	}
	return out
}

// downRules is the pair of down rules of each prefix of overlay, the down set where overlay is as heldOverlay leaves it: for each
// prefix of length n, in its family, 32765 refusing it and 32764 looking main up to it for a route of length n or longer, the refusal
// first, the order a stop adds them in, so once the refusal's add succeeds no
// lookup to the prefix meets 32764 alone and leaves by a shorter route of main. familyPrefixes holds no /0, so
// n-1 is never negative.
func downRules(overlay []schema.Prefix) []Rule {
	var out []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, prefix := range familyPrefixes(family, SchemaPrefixes(overlay)) {
			to := schema.PrefixFrom(prefix)
			out = append(out,
				Rule{Family: family, Priority: priorityDownRefused, To: to, action: actionUnreachable},
				Rule{Family: family, Priority: priorityDownMain, To: to, Table: schema.TableMain, suppress: SuppressUpTo(prefix.Bits() - 1)},
			)
		}
	}
	return out
}

// heldOverlay is the prefixes of overlay the down set holds: each but one a
// carve-out of carved equals, which gets no hold while the node runs
// (overlayHolds), so its addresses go onto the carve-out's link while down as
// they do then
func heldOverlay(overlay []schema.Prefix, carved []netip.Prefix) []schema.Prefix {
	return slices.DeleteFunc(slices.Clone(overlay), func(prefix schema.Prefix) bool {
		destination, ok := canonicalPrefix(prefix.Prefix)
		return ok && slices.Contains(carved, destination)
	})
}

// downSet is the down set a stop writes, of the overlay in force against the
// host's network as the watch last read it, so a carve-out the watch sees come
// or go while the node is down moves it at the next stopped pass
func (r *Reconciler) downSet() []Rule {
	return downRules(heldOverlay(r.rt.Overlay, r.readNetwork().carved))
}

// holdsOverlay reports whether the kernel, as the last route listing and its
// writes left it, holds for every source the hold of wanted, the routes that
// pass was handed, at the prefix of each refusal of down. A route the pass is
// deleting, a throw and the mesh's own route hold nothing.
func (r *Reconciler) holdsOverlay(down []Rule, wanted []Route) bool {
	at := make(map[netip.Prefix]bool, len(wanted))
	for _, route := range wanted {
		if !route.Source.IsValid() && route.Unreachable && r.installed[route] {
			at[route.Destination] = true
		}
	}
	return !slices.ContainsFunc(down, func(rule Rule) bool { return rule.Priority == priorityDownRefused && !at[rule.To.Prefix] })
}

// heldPairs counts the distinct overlay prefixes whose pair of down rules, the
// refusal at 32765 and the lookup of main at 32764, is among rules, a second
// copy of either counting nothing more
func heldPairs(rules []Rule) int {
	refused, looked := map[schema.Prefix]bool{}, map[schema.Prefix]bool{}
	for _, rule := range rules {
		if !isDownRule(rule) {
			continue
		}
		switch rule.Priority {
		case priorityDownRefused:
			refused[rule.To] = true
		case priorityDownMain:
			looked[rule.To] = true
		}
	}
	held := 0
	for to := range refused {
		if looked[to] {
			held++
		}
	}
	return held
}

// isDownRule reports whether rule is one of the down set of its own
// destination, which a stop left for this overlay or an earlier one
func isDownRule(rule Rule) bool {
	return rule.To.Prefix.IsValid() && slices.Contains(downRules([]schema.Prefix{rule.To}), rule)
}

// withdrawOrder is the order a withdrawal deletes rules in: from the last
// priority to the first, each nop just after the goto that lands on it. A
// marked lookup then jumps over the rules between a goto and its nop for as
// long as the goto stands, and every rule that looks main up goes ahead of
// 5110.
func withdrawOrder(rules []Rule) []Rule {
	// at is the priority a rule goes at, each nop's that of its goto, and after it
	// derivedRules writes two pairs of a goto and its nop, 5100 to 5190 and 5400 to 5490, and a third pair needs its case
	// here, or its nop goes at its own priority, ahead of the rules its goto jumps over
	at := func(rule Rule) (uint32, int) {
		switch rule.Priority {
		case priorityOverlayEnd:
			return priorityUnderlayPastOverlay, 1
		case priorityMeshEnd:
			return priorityUnderlayPastMesh, 1
		}
		return rule.Priority, 0
	}
	out := slices.Clone(rules)
	slices.SortStableFunc(out, func(a, b Rule) int {
		ap, an := at(a)
		bp, bn := at(b)
		return cmp.Or(cmp.Compare(bp, ap), cmp.Compare(an, bn))
	})
	return out
}

// WarnHeldOverlay warns once, for a start that runs no reconciler to remove
// them, of each rule of overlay's down set under the default protocol that a
// stop left, with the command that deletes it, and removes nothing. Only linux
// holds policy rules.
func WarnHeldOverlay(overlay []schema.Prefix) {
	dumped, err := DumpRules()
	if errors.Is(err, ErrUnsupported) {
		return
	}
	if err != nil {
		slog.Warn("kernel could not list the policy rules to find a down set an earlier instance may have left", "err", err)
		return
	}
	warnOfDownSet(dumped, overlay)
}

// warnOfDownSet is WarnHeldOverlay's warning, of the rules of overlay's down
// set that dumped holds
func warnOfDownSet(dumped []DumpedRule, overlay []schema.Prefix) {
	var rules, fix []string
	for _, rule := range downRules(overlay) {
		if !slices.Contains(dumped, rule.dumped(DefaultProtocol)) {
			continue
		}
		version := "4"
		if rule.Family == FamilyIPv6 {
			version = "6"
		}
		rules = append(rules, fmt.Sprintf("%s protocol %d", rule, DefaultProtocol))
		fix = append(fix, fmt.Sprintf("ip -%s rule del priority %d to %s protocol %d", version, rule.Priority, rule.To, DefaultProtocol))
	}
	if len(rules) > 0 {
		slog.Warn("kernel found rules an earlier instance left to hold overlay prefixes, which refuse each prefix whose 32765 rule stands until they are deleted",
			"rules", strings.Join(rules, ", "), "fix", strings.Join(fix, " && "))
	}
}

// exitView is mode 2 or 3 as a pass derives its rules: the host's links
// outside the mesh as the network watch reads them, the names forward expands
// to among them (see expandForward), the carve-outs of those links, the
// destinations of the mesh's table, and each family the tun holds no overlay
// address of. The zero value is mode off, whatever it holds beside. fallback
// is cap.exit fallback = "none", written or unwritten in mode 3, own is the
// prefixes the mesh's table throws (see thrown), which a pass reads only under
// it, lan is the prefixes cap.exit lan lists, and unheld is the kill switch
// not holding, which a pass reads only under fallback.
type exitView struct {
	on          bool
	network     NetworkState
	forwarded   []string
	carved      []netip.Prefix
	table       []netip.Prefix
	unaddressed []Family
	fallback    bool
	own         []netip.Prefix
	lan         []netip.Prefix
	unheld      bool
}

// thrown is the destination of each throw of the mirror's desired routes that
// holds no source, each of this node's own prefixes outside the overlay that
// counts as no default and each carve-out whose own prefix the mesh's table
// does not hold for every source. A source-specific one is left out,
// so the host's own unmarked lookup from its source the mesh's table passes on
// meets 5450.
func thrown(desired []Route) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range desired {
		if route.Throw && !route.Source.IsValid() {
			out = append(out, route.Destination)
		}
	}
	return out
}

// sources is the selectors of one family's 5405 and 5435: each address of a
// link outside the mesh as a host prefix, and each connected network shorter
// than a host prefix and each point-to-point far end outside those networks of
// a link forward leaves out, masked, each sorted and once, none refused. Mode
// off, a family the tun holds no overlay address of and fallback = "none"
// while its table does not hold have none.
func (v exitView) sources(family Family, overlay, own []netip.Prefix) (addresses, networks []netip.Prefix) {
	if !v.on || slices.Contains(v.unaddressed, family) || v.fallback && v.unheld {
		return nil, nil
	}
	links := v.network.IPv4.Links
	if family == FamilyIPv6 {
		links = v.network.IPv6.Links
	}
	for _, link := range links {
		forwarded := slices.Contains(v.forwarded, link.Name)
		for _, peer := range link.Peers {
			// a far end inside a network of its own link takes that network's rule
			inside := slices.ContainsFunc(link.Prefixes, func(prefix netip.Prefix) bool {
				return prefix.Bits() < prefix.Addr().BitLen() && encloses(prefix, peer)
			})
			if !forwarded && !inside {
				networks = append(networks, peer)
			}
		}
		for _, prefix := range link.Prefixes {
			address := prefix.Addr()
			addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()))
			// a host prefix's network is its address, which 5405 already selects
			if !forwarded && prefix.Bits() < address.BitLen() {
				networks = append(networks, prefix)
			}
		}
	}
	own = familyPrefixes(family, own)
	refused := func(selector netip.Prefix) bool { return v.refused(selector, overlay, own) }
	return slices.DeleteFunc(familyPrefixes(family, addresses), refused), slices.DeleteFunc(familyPrefixes(family, networks), refused)
}

// refused reports whether 5405 and 5435 leave a selector out: one overlapping
// the overlay, unless the link holds it, or one overlapping this node's own
// prefixes, whose sources 5430 sends into the mesh in every mode
func (v exitView) refused(selector netip.Prefix, overlay, own []netip.Prefix) bool {
	return slices.ContainsFunc(overlay, selector.Overlaps) && !v.linkHolds(selector) ||
		slices.ContainsFunc(own, selector.Overlaps)
}

// linkHolds reports whether a carve-out holds a selector whole and no entry of
// the mesh's table inside that carve-out does, since the link's neighbors hold
// such a carve-out's addresses and the mesh holds the rest. An entry wider than
// the carve-out, an exit's default among them, is the route the carve-out
// takes the link's addresses back from, so linkHolds passes over it.
func (v exitView) linkHolds(selector netip.Prefix) bool {
	return slices.ContainsFunc(v.carved, func(carve netip.Prefix) bool {
		return encloses(carve, selector) && !slices.ContainsFunc(v.table, func(entry netip.Prefix) bool { return encloses(carve, entry) && encloses(entry, selector) })
	})
}

// SchemaPrefixes is prefixes as netip holds them, in order
func SchemaPrefixes(prefixes []schema.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.Prefix)
	}
	return out
}

// familyPrefixes is the prefixes of one family longer than /0, masked, each
// once and in order, as a rule's selector reads back
func familyPrefixes(family Family, prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if prefix, ok := canonicalPrefix(prefix); ok && prefix.Bits() > 0 && familyOf(prefix.Addr()) == family {
			out = append(out, prefix)
		}
	}
	slices.SortFunc(out, comparePrefixes)
	return slices.Compact(out)
}

// outermost is distinct prefixes less each one another of them holds, in order
// 5430's rules share a priority and a table, so a held prefix's rule selects no source its holder's does not
func outermost(prefixes []netip.Prefix) []netip.Prefix {
	return slices.DeleteFunc(slices.Clone(prefixes), func(inner netip.Prefix) bool {
		return slices.ContainsFunc(prefixes, func(outer netip.Prefix) bool { return outer != inner && encloses(outer, inner) })
	})
}

// ownPrefixes is this node's own prefixes as the snapshot holds them, the
// sources OwnedSources owns less three kinds: a prefix the mesh cannot carry,
// which a class schema.Unroutable names holds whole, a LAN cap.egress
// advertises, whose hosts are no sources of this node's own, and a
// source-specific announcement D from S, which under RFC 9079 section 4's
// destination-first lookup routes D to this node only for packets from S, so a
// reply to D from outside S never comes back through the mesh.
func (r *Reconciler) ownPrefixes(snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range ownedEntries(snapshot, r.rt.Overlay) {
		prefix := entry.Destination
		if _, whole := schema.Unroutable(prefix); !entry.Source.IsValid() && !whole && !slices.Contains(r.rt.Advertised, prefix) {
			out = append(out, prefix)
		}
	}
	return out
}
