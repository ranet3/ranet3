// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// Border is the cap.border capability: this node drops what arrives on a link
// outside the mesh carrying a mesh source. Writing the block turns it on. The
// entry chain beside it runs without it.
type Border struct {
	// Overlay names the prefixes the mesh numbers its nodes from. A packet
	// arriving from outside the mesh with a source in one of them is forged,
	// and every entry of an exit's allow list that admits an outer source lies
	// inside them.
	Overlay []schema.Prefix `yaml:"overlay,omitempty" json:"overlay,omitempty" toml:"overlay,omitempty"`
}

// Normalized is the capability as the filter runs it: the prefixes in one
// order, an omitted list and an empty one the same. The order is not
// meaningful, since a packet matches at most one source of a valid list.
func (b Border) Normalized() Border {
	if len(b.Overlay) == 0 {
		b.Overlay = nil
	} else {
		b.Overlay = slices.SortedFunc(slices.Values(b.Overlay), schema.ComparePrefix)
	}
	return b
}

// Validate refuses an overlay list that would pass a forged mesh source or
// drop what no mesh numbers from, worded as Egress.Validate words advertise
func (b Border) Validate() error {
	if len(b.Overlay) == 0 {
		return errors.New("egress: cap.border overlay is empty, so the filter would pass every forged mesh source: name the prefixes the mesh numbers its nodes from")
	}
	return schema.CheckPrefixes("egress: cap.border overlay", b.Overlay, func(prefix netip.Prefix) string {
		switch {
		case prefix.Bits() == 0:
			return "covers every address of its family, so the filter would drop everything arriving from outside the mesh"
		case schema.BelowSourceFloor(prefix):
			return fmt.Sprintf("is shorter than /%d for IPv4 or /%d for IPv6, the unit IANA delegates to a regional registry, so it holds addresses the mesh does not number from", schema.MinSourceBits4, schema.MinSourceBits6)
		}
		return ""
	})
}

// BorderRuntime holds what the command resolves at startup for the filter
type BorderRuntime struct {
	// Tun is the mesh's device, which the entry chain lets a packet leave by
	// only as a reply, toward an IPv6 link-local or multicast destination, from
	// a source this node owns or toward a destination a none class takes
	Tun string
	// Inside names the devices whose traffic the border chain takes whatever
	// it carries: the mesh tun and lo
	Inside []string
	// Sets derives what the table's sets hold, on each pass. Nil holds them
	// empty.
	Sets func() BorderSets
	// Routes and Network wake a pass on a change of the mesh's table and of
	// the host's links, nil for neither
	Routes, Network <-chan struct{}
	// Events records the passes that rewrote the table or failed, readiness
	// moving and the drops each pass read, nil records nothing
	Events *events.Bus
}

// CarveOut is the part of the overlay a link outside the mesh is on, where the
// link's own neighbors hold overlay addresses no node announces
type CarveOut struct {
	Link   string
	Prefix netip.Prefix
}

// BorderSets holds the carve-outs and the ranges of the table's sets, each of
// either family
type BorderSets struct {
	// CarveOuts is each carve-out of cap.border's overlay, whose sources the
	// border chain accepts from the carve-out's own link, sorted by link and
	// then by prefix, each once
	CarveOuts []CarveOut
	// Carved is the mesh's prefixes inside a carve-out, whose sources the
	// border chain drops from every link outside the mesh
	Carved []Range
	// Owned is the sources this node owns, from which the entry chain lets a
	// packet into the tun, one of the passes Tun lists
	Owned []Range
	// None is the destinations of an exit's none classes, toward which the
	// entry chain lets a packet into the tun from any source, another of them
	None []Range
}

// BorderDrop is one drop of the table in one family, as the metric labels it
type BorderDrop struct{ Reason, Family string }

// Name is the drop as the status and the log spell it
func (d BorderDrop) Name() string { return d.Reason + "_" + d.Family }

// BorderDropKinds is each drop the table counts, in the order every report
// lists them: a source in the overlay or in a carve-out's mesh prefixes from
// outside the mesh, and a packet into the tun that none of the entry chain's
// lines BorderRuntime.Tun lists passes
var BorderDropKinds = [...]BorderDrop{
	{"overlay_source", "ipv4"}, {"overlay_source", "ipv6"},
	{"carved_source", "ipv4"}, {"carved_source", "ipv6"},
	{"mesh_entry", "ipv4"}, {"mesh_entry", "ipv6"},
}

// BorderDrops counts the packets each drop of BorderDropKinds took, at its
// index, as the chains' counters read on a pass. A rewrite of the table
// starts them from zero.
type BorderDrops [len(BorderDropKinds)]uint64

// BorderStats is one finished pass as an operator reads it
type BorderStats struct {
	At    time.Time
	Ready bool
	// Unready says why the table is not ready, empty while it is
	Unready   string
	Installed int
	// Dropped is the counters as the last pass read them, kept from the pass
	// before over a listing that failed
	Dropped BorderDrops
	// CarveOuts is the carve-outs the last pass asked for, written or not, as
	// Ready says
	CarveOuts []CarveOut
	// Sets is each set as the last pass asked for it
	Sets []BorderSetReading
	Err  string
}

// BorderReading is one rule of a chain as a debug read finds it
type BorderReading struct {
	Spec, Verdict, Reason, Family string
	// Held is whether the chain holds it, which a rule the configuration asks
	// for and the last pass has not written yet does not
	Held           bool
	Packets, Bytes uint64
}

// BorderChainReading is one chain of the table as a debug read finds it: its
// hook and priority and its rules in order. A chain with no name holds the
// rules the table holds that the filter does not ask for.
type BorderChainReading struct {
	Name, Hook string
	Priority   int
	Rules      []BorderReading
}

// BorderSetReading is one set of the table and its ranges
type BorderSetReading struct {
	Name     string
	Elements []Range
}

// BorderDebug is the table as a debug read finds it: each chain's rules the
// configuration asks for in order, each with the counters read now through a
// socket of its own, then any the table holds that it does not ask for, and
// the sets as the last pass asked for them
type BorderDebug struct {
	Where string
	// PassAt is the last pass, whose readback Ready and Unready report
	PassAt  time.Time
	Ready   bool
	Unready string
	Chains  []BorderChainReading
	Sets    []BorderSetReading
	Err     string
}
