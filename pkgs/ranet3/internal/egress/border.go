// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/pf"
	"ranet3.com/pkgs/ranet3/schema"
)

// Antispoof is the cap.antispoof capability. The filter runs wherever overlay
// is written, with no block, and the block only exempts: it is the one
// protection on by default.
type Antispoof struct {
	// Exempt is the overlay prefixes whose sources pass from every interface outside the mesh
	Exempt []schema.Prefix `yaml:"exempt,omitempty" json:"exempt,omitempty" toml:"exempt,omitempty"`
	// Interface is the prefixes whose sources pass from the interfaces a name
	// matches, beside Exempt: the name itself, or with one trailing * every
	// interface whose name starts with what comes before it
	Interface map[string]AntispoofInterface `yaml:"interface,omitempty" json:"interface,omitempty" toml:"interface,omitempty"`
}

// AntispoofInterface is one entry of cap.antispoof.interface
type AntispoofInterface struct {
	Exempt []schema.Prefix `yaml:"exempt" json:"exempt" toml:"exempt"`
}

// Border is the antispoof filter's configuration: the overlay, the
// exemptions of cap.antispoof, its zero block where it is not written, and
// what the exemptions take as this node's own. A pass derives every set it
// carves from the one Border it runs.
type Border struct {
	Overlay   []schema.Prefix
	Antispoof Antispoof
	// Own is each range cap.route announces inside the overlay, which an
	// exemption inside it admits
	Own []netip.Prefix
	// Addresses is each address of this node's as a host prefix, which the
	// filter drops inside any exemption
	Addresses []netip.Prefix
}

// Exemption is one prefix the filter passes from the interfaces Interface
// matches, every one outside the mesh where it is empty
type Exemption struct {
	Interface string
	Prefix    netip.Prefix
}

// InterfacePattern splits a name of cap.antispoof.interface into the pattern
// it matches an interface's name by and whether that is a wildcard: for a name
// with a trailing *, the bytes before it, which start each name it matches,
// and for any other the name, which each name it matches equals
func InterfacePattern(name string) (pattern string, wildcard bool) {
	return strings.CutSuffix(name, "*")
}

// Names reports e naming link, as its accept's iifname match does. The shared
// list, under no interface, names none, since every link has a name.
func (e Exemption) Names(link string) bool {
	pattern, wildcard := InterfacePattern(e.Interface)
	if wildcard {
		return strings.HasPrefix(link, pattern)
	}
	return pattern == link
}

// Normalized is the configuration as the filter runs it: each list in one
// order, an omitted list and an empty one the same. The order is not
// meaningful: a packet may match nested exemptions, or one prefix in the
// shared list and an interface's, but every exemption accepts and every
// overlay prefix drops, so it meets the same verdict in any order.
func (b Border) Normalized() Border {
	b.Overlay = sortedPrefixes(b.Overlay)
	b.Antispoof.Exempt = sortedPrefixes(b.Antispoof.Exempt)
	if len(b.Antispoof.Interface) == 0 {
		b.Antispoof.Interface = nil
		return b
	}
	byName := make(map[string]AntispoofInterface, len(b.Antispoof.Interface))
	for name, entry := range b.Antispoof.Interface {
		byName[name] = AntispoofInterface{Exempt: sortedPrefixes(entry.Exempt)}
	}
	b.Antispoof.Interface = byName
	return b
}

func sortedPrefixes(list []schema.Prefix) []schema.Prefix {
	if len(list) == 0 {
		return nil
	}
	return slices.SortedFunc(slices.Values(list), schema.ComparePrefix)
}

// Exemptions is every exemption, the shared ones first and then each
// interface's by name, each list in order
func (b Border) Exemptions() []Exemption {
	b = b.Normalized()
	var out []Exemption
	for _, prefix := range b.Antispoof.Exempt {
		out = append(out, Exemption{Prefix: prefix.Prefix})
	}
	for _, name := range slices.Sorted(maps.Keys(b.Antispoof.Interface)) {
		for _, prefix := range b.Antispoof.Interface[name].Exempt {
			out = append(out, Exemption{Interface: name, Prefix: prefix.Prefix})
		}
	}
	return out
}

// Carved is the prefixes of each carve-out and each exemption, whose families
// take a carved drop ahead of any accept by source
func (b Border) Carved(carveOuts []CarveOut) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(carveOuts))
	for _, carveOut := range carveOuts {
		out = append(out, carveOut.Prefix)
	}
	for _, exemption := range b.Exemptions() {
		out = append(out, exemption.Prefix)
	}
	return out
}

// Validate refuses an overlay list that would pass a forged mesh source, drop
// what no mesh numbers from or hold an address of a class schema.Unroutable
// names, worded as Egress.Validate words advertise, and an exemption that
// would exempt nothing
func (b Border) Validate() error {
	if len(b.Overlay) == 0 {
		return errors.New("egress: overlay is empty, so the antispoof filter would pass every forged mesh source: name the prefixes the mesh numbers its nodes from")
	}
	if err := schema.CheckPrefixes("egress: overlay", b.Overlay, func(prefix netip.Prefix) string {
		switch {
		case prefix.Bits() == 0:
			return "covers every address of its family, so the antispoof filter would drop everything arriving from outside the mesh"
		case schema.BelowSourceFloor(prefix):
			return fmt.Sprintf("is shorter than /%d for IPv4 or /%d for IPv6, the unit IANA delegates to a regional registry, so it holds addresses the mesh does not number from", schema.MinSourceBits4, schema.MinSourceBits6)
		}
		reason, _ := schema.Unroutable(prefix)
		return reason
	}); err != nil {
		return err
	}
	a := b.Antispoof
	inside := func(prefix netip.Prefix) string {
		if !schema.InsideOverlay(prefix, b.Overlay) {
			return "lies outside overlay, and the filter drops only an overlay source, so it would exempt nothing"
		}
		return ""
	}
	if err := schema.CheckPrefixes("egress: cap.antispoof exempt", a.Exempt, inside); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(a.Interface)) {
		key := fmt.Sprintf("cap.antispoof.interface.%q", name)
		pattern, _ := InterfacePattern(name)
		switch {
		case name == "*":
			return fmt.Errorf("egress: %s names every interface, which is cap.antispoof exempt", key)
		case pattern == "" || strings.Contains(pattern, "*"):
			return fmt.Errorf("egress: %s is not an interface name, nor one followed by a single trailing *, the only wildcard", key)
		// IFNAMSIZ less its terminator, on Linux and the BSDs alike
		case len(pattern) > 15:
			return fmt.Errorf("egress: %s is %d bytes before any *, and an interface name is at most 15", key, len(pattern))
		case len(a.Interface[name].Exempt) == 0:
			return fmt.Errorf("egress: %s exempts nothing: write its exempt, or leave the entry out", key)
		}
		if err := schema.CheckPrefixes("egress: "+key+" exempt", a.Interface[name].Exempt, inside); err != nil {
			return err
		}
	}
	return nil
}

// BorderRuntime holds what the command resolves at startup for the filter
type BorderRuntime struct {
	// Tun is the mesh's device, which the entry chain lets a packet leave by
	// only as a reply, toward an IPv6 link-local or multicast destination, from
	// a source this node owns or toward a destination a none class takes
	Tun string
	// Inside names the devices whose traffic the antispoof chain takes whatever
	// it carries: the mesh tun and the loopback link
	Inside []string
	// Sets derives what the filter's sets hold, on each pass, from the
	// configuration the pass runs, nil where overlay is not written. Nil holds
	// them empty.
	Sets func(cfg *Border) BorderSets
	// Routes and Network wake a pass on a change of the mesh's table and of
	// the host's links, nil for neither
	Routes, Network <-chan struct{}
	// Events records the passes that rewrote the filter or failed, readiness
	// moving and the drops each pass read, nil records nothing
	Events *events.Bus
	// StateDir is the directory for state that outlives the process, where a
	// backend records what it holds in the kernel beyond its own rules, so a
	// later start gives it back. A backend that records refuses to open
	// without it.
	StateDir string
}

// CarveOut is the part of the overlay a link outside the mesh is on, where the
// link's own neighbors hold overlay addresses no node announces
type CarveOut struct {
	Link   string
	Prefix netip.Prefix
}

// ExemptConflict is an exemption and a prefix that overlaps it, inside it or
// covering it, which another router announces. Where Own is false the prefix
// is another node's, the mesh's table routing it via a peer: Carved is their
// intersection, which the carved sets hold, Via the peer and RouterID the
// selected route's origin, empty where the speaker selected none. Where Own is
// true the prefix is a range this node announces that babel holds another
// router's offer for, which the exemption admits as this node's own: Carved
// and Via are empty and RouterID is the offer's origin. The exemption, the
// prefix and Carved are the conflict, and Via and RouterID the route a pass
// read for it.
type ExemptConflict struct {
	Exemption Exemption
	Prefix    netip.Prefix
	Carved    netip.Prefix
	Via       string
	RouterID  string
	Own       bool
}

// BorderSets holds the carve-outs and the ranges of the filter's sets, each of
// either family
type BorderSets struct {
	// CarveOuts is each carve-out of the overlay, whose sources the antispoof
	// chain accepts from the carve-out's own link, sorted by link and then by
	// prefix, each once
	CarveOuts []CarveOut
	// Carved is the sources the antispoof chain drops from every link outside
	// the mesh ahead of the carve-outs' and the exemptions' accepts: the mesh's
	// prefixes inside a carve-out, but for an address of this node's own ranges
	// that, for each carve-out holding it, an exemption naming the carve-out's
	// link holds, and of each exemption the part another node's prefix holds and
	// this node's node addresses inside it
	Carved []Range
	// Conflicts is each exemption that another node's prefix overlaps, sorted
	// and each once, and then each that a range of this node's own another
	// router announces too overlaps, the same way
	Conflicts []ExemptConflict
	// Owned is the sources this node owns, from which the entry chain lets a
	// packet into the tun, one of the passes Tun lists
	Owned []Range
	// None is the destinations of an exit's none classes, toward which the
	// entry chain lets a packet into the tun from any source, another of them
	None []Range
	// Links is the name of each up link outside the mesh the host's watch
	// reports, sorted and each once, over which a backend that matches exact
	// names alone writes an exemption under a name ending in *
	Links []string
}

// BorderDrop is one drop of the filter in one family, as the metric labels it
type BorderDrop struct{ Reason, Family string }

// Name is the drop as the status and the log spell it
func (d BorderDrop) Name() string { return d.Reason + "_" + d.Family }

// BorderDropKinds is each drop the filter counts, in the order every report
// lists them: a source in the overlay or in a carve-out's mesh prefixes from
// outside the mesh, and a packet into the tun that none of the entry chain's
// lines BorderRuntime.Tun lists passes
var BorderDropKinds = [...]BorderDrop{
	{"overlay_source", "ipv4"}, {"overlay_source", "ipv6"},
	{"carved_source", "ipv4"}, {"carved_source", "ipv6"},
	{"mesh_entry", "ipv4"}, {"mesh_entry", "ipv6"},
}

// BorderDrops counts the packets each drop of BorderDropKinds took, at its
// index, as the chains' counters read on a pass. A rewrite of the chains
// starts them from zero.
type BorderDrops [len(BorderDropKinds)]uint64

// BorderStats is one finished pass as an operator reads it
type BorderStats struct {
	At    time.Time
	Ready bool
	// Unready says why the filter is not ready, empty while it is
	Unready   string
	Installed int
	// Dropped is the counters as the last pass read them, kept from the pass
	// before over a listing that failed
	Dropped BorderDrops
	// Kinds is each drop of BorderDropKinds a rule of the last pass writes, in
	// that order, the only ones Dropped counts and a report names
	Kinds []BorderDrop
	// CarveOuts is the carve-outs the last pass asked for, written or not, as
	// Ready says
	CarveOuts []CarveOut
	// Sets is each set as the last pass asked for it
	Sets []BorderSetReading
	// PF is pf's state for the filter beside its anchor, as the last pass read
	// it, nil where the filter does not run on pf
	PF  *BorderPF
	Err string
}

// BorderPF is pf's state for the filter beside its anchor, without which pf
// evaluates none of the anchor's rules
type BorderPF struct {
	Anchor string
	// Token is this daemon's reference on pf, which keeps pf enabled, and PID
	// the process that took it
	Token uint64
	PID   int
	// Listed is whether pf lists Token under PID
	Listed bool
	// Called is whether the main ruleset calls com.apple's children, the
	// anchor among them
	Called bool
	// Enablers is every reference pf lists, which a debug read alone fills
	Enablers []pf.Enabler
}

// BorderReading is one rule of a chain as a debug read finds it
type BorderReading struct {
	Spec, Verdict, Reason, Family string
	// Held is whether the chain holds it, which a rule the configuration asks
	// for and the last pass has not written yet does not
	Held           bool
	Packets, Bytes uint64
}

// BorderChainReading is one chain of the filter as a debug read finds it: its
// hook, its priority where its backend orders chains by one, and its rules in
// order. A chain with no name holds the rules the filter's own chains, or its
// pf anchor, hold that it does not ask for.
type BorderChainReading struct {
	Name, Hook string
	Priority   *int
	Rules      []BorderReading
}

// BorderSetReading is one set of the filter and its ranges, Kind the word its
// backend calls a set by: nftables a set, pf a table
type BorderSetReading struct {
	Kind, Name string
	Elements   []Range
}

// BorderDebug is the filter as a debug read finds it: each chain's rules the
// configuration asks for in order, each with the counters read now through a
// socket of its own, then any its own chains, or its pf anchor, hold that it
// does not ask for, and
// the sets as the last pass asked for them
type BorderDebug struct {
	Where string
	// PassAt is the last pass, whose readback Ready and Unready report
	PassAt  time.Time
	Ready   bool
	Unready string
	Chains  []BorderChainReading
	Sets    []BorderSetReading
	// PF is the last pass's reading of pf beside the anchor, with the
	// references pf lists now, nil where the filter does not run on pf
	PF  *BorderPF
	Err string
}
