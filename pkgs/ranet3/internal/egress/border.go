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
// outside the mesh carrying a mesh source, a routing header or one of this
// node's own SIDs. Writing the block turns it on.
type Border struct {
	// Overlay names the prefixes the mesh numbers its nodes from. A packet
	// arriving from outside the mesh with a source in one of them is forged,
	// and every exit's allow list lies inside them.
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
	// Inside names the devices whose traffic the filter takes whatever it
	// carries: the mesh tun and lo
	Inside []string
	// SIDs are this node's own local segments, each dropped as a destination
	// arriving from outside. SetConfig replaces them on a reload.
	SIDs []netip.Addr
	// Ready receives whether the chain reads back as the configuration asks,
	// whenever that moves, starting from false. Nil where nothing reads it,
	// which only a test does.
	Ready func(bool)
	// Events records the passes that rewrote the chain or failed, readiness
	// moving and the drops each pass read, nil records nothing
	Events *events.Bus
}

// BorderDrops counts the packets each class dropped, as the chain's counters
// read on a pass. A rewrite of the chain starts them from zero.
type BorderDrops struct {
	Source4, Source6, RoutingHeader, Destination uint64
}

// BorderStats is one finished pass as an operator reads it
type BorderStats struct {
	At    time.Time
	Ready bool
	// Unready says why the chain is not ready, empty while it is
	Unready   string
	Installed int
	// Dropped is the counters as the last pass read them, kept from the pass
	// before over a listing that failed
	Dropped BorderDrops
	Err     string
}

// BorderReading is one rule of the chain as a debug read finds it
type BorderReading struct {
	Spec, Verdict, Reason, Family string
	// Held is whether the chain holds it, which a rule the configuration asks
	// for and the last pass has not written yet does not
	Held           bool
	Packets, Bytes uint64
}

// BorderDebug is the chain as a debug read finds it: the rules the
// configuration asks for in order, each with the counters read now through a
// socket of its own, then any the chain holds that it does not ask for
type BorderDebug struct {
	Where    string
	Hook     string
	Priority int
	// PassAt is the last pass, whose readback Ready and Unready report
	PassAt  time.Time
	Ready   bool
	Unready string
	Rules   []BorderReading
	Err     string
}
