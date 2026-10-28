// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// Lookup, Answer, Route and Hop are a pass's route lookups as package egress
// states them, which a debug read carries as the pass read them
type (
	Lookup = egress.Lookup
	Answer = egress.Answer
	Route  = egress.Route
	Hop    = egress.Hop
)

// judgment is one family's readiness after a pass and what it was judged
// from: the chains' readback, forwarding, and the family's lookups in the
// order the batch asked them, with their answers where the batch gave each
type judgment struct {
	ready      bool
	why        string
	noMember   bool
	unread     []netip.Prefix
	unwritten  string
	forwarding bool
	lookups    []Lookup
	answers    []Answer
}

type forwardRead struct {
	prefix  netip.Prefix
	address netip.Addr
}

type familyReads struct {
	// held is the addresses the family's classes translate to, and heldAt
	// where the first of their lookups sits in the pass's batch
	held   []netip.Addr
	heldAt int
	source netip.Addr
	reads  []forwardRead
	// first is where the first of reads sits in the pass's batch
	first int
}

// judge is each family's readiness after a pass. A family this node does not
// translate has no judgment, so it reads as not ready with no reason
func (t *Translator) judge(unwritten map[uint8]string, forwards map[uint8]bool) map[uint8]judgment {
	judged := map[uint8]judgment{}
	var members []netip.Prefix
	if t.rt.Members != nil {
		members = t.rt.Members()
	}
	families := map[uint8]familyReads{}
	var lookups []Lookup
	for _, family := range t.cfg.Translated(t.rt.Steered) {
		read := judgment{unwritten: unwritten[family], forwarding: forwards[family]}
		switch {
		case read.unwritten != "":
			read.why = read.unwritten
			judged[family] = read
			continue
		case !read.forwarding:
			read.why = "the kernel does not forward " + egress.FamilyName(family)
			judged[family] = read
			continue
		}
		reads := familyReads{held: t.classAddresses(family), heldAt: len(lookups)}
		for _, address := range reads.held {
			lookups = append(lookups, Lookup{Destination: address})
		}
		source, ok := memberSource(members, family)
		if !ok {
			read.ready, read.noMember = true, true
			judged[family] = read
		} else {
			reads.source, reads.first = source, len(lookups)
			var unread []netip.Prefix
			for _, prefix := range t.readPrefixes(family) {
				address, ok := readAddress(prefix)
				if !ok {
					unread = append(unread, prefix)
					continue
				}
				lookups = append(lookups, Lookup{Source: source, Destination: address, IIF: t.rt.Interface, Reply: len(reads.reads) == 0})
				reads.reads = append(reads.reads, forwardRead{prefix, address})
			}
			read.ready, read.unread = true, unread
			judged[family] = read
		}
		if len(reads.held) > 0 || len(reads.reads) > 0 {
			families[family] = reads
		}
	}
	if len(lookups) == 0 {
		return judged
	}
	answers, err := t.rt.Lookup(lookups)
	for family, reads := range families {
		j := judged[family]
		held, forward := lookups[reads.heldAt:reads.heldAt+len(reads.held)], lookups[reads.first:reads.first+len(reads.reads)]
		j.lookups = append(slices.Clone(held), forward...)
		switch {
		case err != nil:
			j.why = "the route lookups failed: " + err.Error()
		case len(answers) != len(lookups):
			j.why = fmt.Sprintf("the route lookups answered %d of %d", len(answers), len(lookups))
		default:
			j.answers = append(slices.Clone(answers[reads.heldAt:reads.heldAt+len(reads.held)]), answers[reads.first:reads.first+len(reads.reads)]...)
			j.why = t.unheld(reads.held, answers[reads.heldAt:reads.heldAt+len(reads.held)])
			if j.why == "" && len(reads.reads) > 0 {
				j.why = t.readsFail(reads, answers[reads.first:reads.first+len(reads.reads)])
			}
		}
		j.ready = j.why == ""
		judged[family] = j
	}
	return judged
}

func (t *Translator) classAddresses(family uint8) []netip.Addr {
	var out []netip.Addr
	for _, class := range t.cfg.Classes(family) {
		if class.To.Addr.IsValid() {
			out = append(out, class.To.Addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// unheld is why a family is not ready while this host does not hold an address
// its classes translate to, the first in order, and empty where it holds each.
// The kernel answers the lookup of an address it holds with the address's local
// route, whatever the state of its link, and of a tentative IPv6 address with
// another route until duplicate address detection has ended. A reply to an
// address answered otherwise is not delivered here
func (t *Translator) unheld(held []netip.Addr, answers []Answer) string {
	for i, address := range held {
		lookup := "the lookup of " + address.String() + ", an address cap.egress translate names,"
		switch answer := answers[i]; {
		case answer.Err != nil:
			return lookup + " failed" + t.failure(address, "", answer.Err)
		case answer.Route.Type != "local":
			return lookup + " found a route of type " + answer.Route.Type + ", so this host does not hold it"
		}
	}
	return ""
}

func memberSource(members []netip.Prefix, family uint8) (netip.Addr, bool) {
	members = slices.DeleteFunc(slices.Clone(members), func(member netip.Prefix) bool { return egress.AddressFamily(member.Addr()) != family })
	slices.SortFunc(members, func(a, b netip.Prefix) int {
		return cmp.Or(a.Masked().Addr().Compare(b.Masked().Addr()), cmp.Compare(b.Bits(), a.Bits()))
	})
	for _, member := range members {
		if address, ok := readAddress(member); ok {
			return address, true
		}
	}
	return netip.Addr{}, false
}

// readPrefixes is the prefixes a family's forward lookups read, those it
// advertises, or its default where it advertises none, which only a family
// translated beside an egress segment does
func (t *Translator) readPrefixes(family uint8) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range t.cfg.Advertise {
		if egress.AddressFamily(entry.Addr()) == family {
			prefixes = append(prefixes, entry.Prefix)
		}
	}
	if len(prefixes) == 0 {
		unspecified := netip.IPv6Unspecified()
		if family == egress.FamilyIPv4 {
			unspecified = netip.IPv4Unspecified()
		}
		prefixes = []netip.Prefix{netip.PrefixFrom(unspecified, 0)}
	}
	return prefixes
}

// readsFail is why a family's lookups found a path a translated packet cannot
// take, empty where they found none: each forward lookup in its prefix's order,
// then the first one's reply
func (t *Translator) readsFail(reads familyReads, answers []Answer) string {
	for i, read := range reads.reads {
		lookup := fmt.Sprintf("the lookup of %s for %s from %s arriving on %s", read.address, read.prefix, reads.source, t.rt.Interface)
		why, live := t.unusable(answers[i].Route, answers[i].Err, read.address, t.rt.Interface)
		switch {
		case why != "":
			return lookup + why
		case slices.Contains(live, t.rt.Interface):
			return lookup + " leaves by " + t.rt.Interface + " again"
		}
	}
	first, answer := reads.reads[0], answers[0]
	lookup := fmt.Sprintf("the reply lookup of %s for %s from %s arriving on %s", reads.source, first.prefix, first.address, answer.ReplyIIF)
	why, live := t.unusable(answer.Reply, answer.ReplyErr, reads.source, answer.ReplyIIF)
	if why != "" {
		return lookup + why
	}
	if other := slices.DeleteFunc(live, func(device string) bool { return device == t.rt.Interface }); len(other) > 0 {
		return lookup + " leaves by " + strings.Join(other, " ") + " rather than " + t.rt.Interface
	}
	return ""
}

// unusable is the end of a lookup's reason where its route can carry nothing
// whatever its devices. A route with no hop at all, which a nexthop object
// holding none would read as, has no live hop either
func (t *Translator) unusable(route Route, err error, destination netip.Addr, iif string) (string, []string) {
	live := liveDevices(route)
	switch {
	case err != nil:
		return " failed" + t.failure(destination, iif, err), nil
	case route.Type != "unicast":
		return " found a route of type " + route.Type, nil
	case len(live) == 0:
		return noLiveHop(route), nil
	}
	return "", live
}

func liveDevices(route Route) []string {
	var devices []string
	for _, hop := range route.Hops {
		if !hop.Dead && !hop.LinkDown {
			devices = append(devices, hop.Device)
		}
	}
	return devices
}

// noLiveHop ends the reason of a lookup whose route has no live hop, naming the
// devices of the hops it has
func noLiveHop(route Route) string {
	if len(route.Hops) == 0 {
		return " found no live next hop"
	}
	devices := make([]string, len(route.Hops))
	for i, hop := range route.Hops {
		devices[i] = hop.Device
	}
	return " found no live next hop among " + strings.Join(devices, " ")
}

// failure ends a failed lookup's reason with the kernel's error and, for an
// IPv4 lookup, the setting of the device it arrived on that refuses it: the
// input lookup refuses every packet arriving where forwarding is off, and one
// failing reverse path filtering. The kernel answers each with an errno it
// answers for other causes too, so the setting is read rather than the errno
func (t *Translator) failure(destination netip.Addr, device string, err error) string {
	text := ": " + err.Error()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		text = ": " + errno.Error()
	}
	if !destination.Is4() || device == "" {
		return text
	}
	if t.rt.Sysctl("net/ipv4/conf/"+device+"/forwarding") == "0" {
		// sysctl(8) writes a dot in a device's name as a slash
		return text + ", with net.ipv4.conf." + strings.ReplaceAll(device, ".", "/") + ".forwarding at 0"
	}
	if filter := max(t.sysctlInt("net/ipv4/conf/all/rp_filter"), t.sysctlInt("net/ipv4/conf/"+device+"/rp_filter")); filter > 0 {
		return text + fmt.Sprintf(", with reverse path filtering at %d on %s", filter, device)
	}
	return text
}

func (t *Translator) sysctlInt(path string) int {
	n, _ := strconv.Atoi(t.rt.Sysctl(path))
	return n
}

func skippedText(v4, v6 judgment) string {
	var parts, families, unread []string
	for _, family := range []struct {
		name string
		judgment
	}{{"ipv4", v4}, {"ipv6", v6}} {
		if family.noMember {
			families = append(families, family.name)
		}
		for _, prefix := range family.unread {
			unread = append(unread, prefix.String())
		}
	}
	if len(families) > 0 {
		parts = append(parts, "lookup skipped, the mesh routes no other node's "+strings.Join(families, " or ")+" prefix inside cap.border.overlay")
	}
	switch len(unread) {
	case 0:
	case 1:
		parts = append(parts, "lookup skipped for "+unread[0]+", which holds no address the kernel takes as a unicast destination")
	default:
		parts = append(parts, "lookup skipped for "+strings.Join(unread, " ")+", which hold no address the kernel takes as a unicast destination")
	}
	return strings.Join(parts, ", ")
}
