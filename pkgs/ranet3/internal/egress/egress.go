// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package egress holds the cap.egress and cap.border capabilities as a file
// writes them and the node validates them, the Exit every backend carrying
// cap.egress sits behind, and the reports the node reads from the border
// filter. cap.egress is the one action behind an exit node and a subnet
// router: an exit advertises a default and a subnet router the prefixes behind
// it, and both end at the same translation. Nothing here makes a system call
// or imports a backend.
package egress

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

// FamilyIPv4 and FamilyIPv6 are AF_INET and AF_INET6, spelled here rather than
// taken from x/sys so that this file still builds where the capability is
// refused rather than absent from the type. internal/kernel spells them the
// same way for the same reason.
const (
	FamilyIPv4 uint8 = 2
	FamilyIPv6 uint8 = 10
)

// Egress is the cap.egress capability: this node carries other nodes' traffic
// out of the mesh, the one action behind an exit node and a subnet router.
// Writing the block turns it on. There is no enable field to forget.
type Egress struct {
	// Advertise names the prefixes this node offers to carry: 0.0.0.0/0 and
	// ::/0 for an exit node, the prefixes behind it for a subnet router. It
	// decides which families the rules keyed on the mesh device cover as well
	// as which are announced, because a family this node does not offer to
	// carry is one it has no reason to translate out of the mesh.
	Advertise []schema.Prefix `yaml:"advertise,omitempty" json:"advertise,omitempty" toml:"advertise,omitempty"`
	// Source4 and Source6 are the address a translated packet leaves under,
	// per family, whether it came through an advertised prefix or an egress
	// segment: a property of the node rather than of the path a packet took. See
	// Source: "auto" is the address this node's own routes would have used,
	// which is the only answer available to a deployment that owns no address
	// block.
	Source4 Source `yaml:"source4,omitempty" json:"source4,omitzero" toml:"source4,omitempty"`
	Source6 Source `yaml:"source6,omitempty" json:"source6,omitzero" toml:"source6,omitempty"`
	// Return translates the other direction too: a packet arriving from one of
	// the advertised prefixes and leaving through the mesh goes out under this
	// node's own mesh address. A subnet router needs it where the mesh has no
	// route back to the LAN, which is every deployment that advertises a
	// prefix the far end does not hold a route for. An exit node does not:
	// nothing sits behind it to start a flow.
	Return bool `yaml:"return,omitempty" json:"return,omitempty" toml:"return,omitempty"`
	// Sweep is the periodic pass. It reinstalls a table somebody removed and
	// reads the forwarding sysctls and the route lookups again, the parts of
	// readiness that change under a running node. Zero uses DefaultSweep.
	Sweep schema.Duration `yaml:"sweep,omitempty" json:"sweep,omitempty" toml:"sweep,omitempty"`
}

// Normalized is the capability as the translator runs it: the sweep the file
// left out filled in, an omitted list and an empty one the same, the
// advertised prefixes in one order, and a source naming no address written as
// the auto it means. Two configurations are compared through this rather than
// as they were written, so neither "source4 = auto", the spelling
// examples/config.toml documents, nor the order the prefixes were listed in is
// a change, and neither costs a restart.
//
// The order is not meaningful: the list decides which families the rules
// keyed on the mesh device cover and which prefixes are announced, and both
// are sets. A rule is installed per family rather than per entry, so nothing
// here is positional.
func (e Egress) Normalized() Egress {
	if len(e.Advertise) == 0 {
		e.Advertise = nil
	} else {
		e.Advertise = slices.SortedFunc(slices.Values(e.Advertise), schema.ComparePrefix)
	}
	if e.Sweep == 0 {
		e.Sweep = schema.Duration(DefaultSweep)
	}
	e.Source4, e.Source6 = e.Source4.normalized(), e.Source6.normalized()
	return e
}

// Validate refuses a capability that cannot mean anything, in the package that
// knows what its fields mean. It runs at load, so a mistake costs a refusal to
// start rather than an exit that advertises and drops. An empty advertise list
// is an exit serving only the traffic steered to its egress segment, which
// Serves judges, since whether a node has one is not in this block.
func (e Egress) Validate() error {
	if e.Return && len(e.Advertise) == 0 {
		return errors.New("egress: cap.egress return is set and advertise is empty, so there is no prefix to translate from")
	}
	// a prefix with bits below its length is refused rather than masked, which would advertise a whole prefix where one address was written
	// and one spelling IPv4 as IPv6 rather than unmapped, which an IPv6 rule would translate for a family no packet on the wire carries
	if err := schema.CheckPrefixes("egress: cap.egress advertise", e.Advertise, nil); err != nil {
		return err
	}
	for _, named := range []struct {
		field  string
		source Source
		is4    bool
	}{{"source4", e.Source4, true}, {"source6", e.Source6, false}} {
		if !named.source.Addr.IsValid() {
			continue
		}
		if named.source.Addr.Zone() != "" {
			// Checked first, as the decoder checks it before unmapping: it
			// refuses a zone, so a capability carrying one renders to a file
			// that does not load.
			return fmt.Errorf("egress: cap.egress %s %s carries a zone, which a translated address cannot", named.field, named.source.Addr)
		}
		if named.source.Auto {
			// A file writes one or the other, and this one is written as the
			// address and read back without the auto.
			return fmt.Errorf("egress: cap.egress %s is both auto and %s, and a source is one or the other", named.field, named.source.Addr)
		}
		if named.source.Addr.Is4In6() {
			// Refused rather than judged in the family it is written in, as an
			// advertised prefix in this spelling is. The decoder unmaps it, so
			// a capability carrying one renders to a file that reads back as
			// an IPv4 source, which source6 refuses after taking the value.
			return fmt.Errorf("egress: cap.egress %s %s is an IPv4 address written as IPv6, so write it as %s", named.field, named.source.Addr, named.source.Addr.Unmap())
		}
		if named.source.Addr.Is4() != named.is4 {
			return fmt.Errorf("egress: cap.egress %s %s is not of that family", named.field, named.source.Addr)
		}
		if !named.source.Addr.IsGlobalUnicast() && !named.source.Addr.IsPrivate() {
			// A translated packet has to be answerable, and a loopback,
			// multicast or unspecified source is one nothing replies to. The
			// check is here rather than in the backend because the backend
			// would install it and the failure would only show up as a flow
			// that never completes.
			return fmt.Errorf("egress: cap.egress %s %s is not an address a reply can be sent to", named.field, named.source.Addr)
		}
	}
	if e.Sweep < 0 {
		return fmt.Errorf("egress: cap.egress sweep %s is negative", e.Sweep)
	}
	return nil
}

// Serves refuses a capability that would translate nothing and offer nothing:
// one advertising no prefix on a node with no segment delivering to egress,
// which steered reports.
func (e Egress) Serves(steered bool) error {
	if len(e.Advertise) == 0 && !steered {
		return errors.New("egress: cap.egress advertise is empty and no segment here delivers to egress, so this node would translate nothing and offer nothing: name the prefixes it carries, or 0.0.0.0/0 and ::/0 for an exit node")
	}
	return nil
}

// Translated is the address families a translator of this capability covers:
// those it advertises, and both beside an egress segment.
func (e Egress) Translated(steered bool) []uint8 {
	if steered {
		return []uint8{FamilyIPv4, FamilyIPv6}
	}
	return e.families()
}

// families is the address families this configuration advertises, derived
// from its prefixes. A family nothing is advertised for is one the mesh device
// carries nothing out of here, so no rule keyed on it is created.
func (e Egress) families() []uint8 {
	var out []uint8
	for _, prefix := range e.Advertise {
		family := FamilyIPv6
		if prefix.Addr().Is4() {
			family = FamilyIPv4
		}
		if !slices.Contains(out, family) {
			out = append(out, family)
		}
	}
	slices.Sort(out)
	return out
}

// SourceOf is the source family's translated packets leave under, Source4 or Source6
func (e Egress) SourceOf(family uint8) Source {
	if family == FamilyIPv4 {
		return e.Source4
	}
	return e.Source6
}

// SweepInterval is the interval with its default applied.
func (e Egress) SweepInterval() time.Duration {
	if e.Sweep <= 0 {
		return DefaultSweep
	}
	return e.Sweep.Duration()
}

// FamilyName is family as a log line and an operator's message name it
func FamilyName(family uint8) string {
	if family == FamilyIPv4 {
		return "ipv4"
	}
	return "ipv6"
}

// ReturnSources is the address the In direction translates to under each family the capability advertises, an auto source picked among mesh
// it refuses what New refuses, an auto source with no address or several to pick from
// without return set every one is the zero address
func (e Egress) ReturnSources(mesh []netip.Addr) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, family := range e.families() {
		source, err := e.ReturnSource(family, mesh)
		if err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	return out, nil
}

// ReturnSource is the address the In direction translates to for one family:
// the configured one, or this node's own mesh address of that family among
// mesh. A node with several is refused rather than picked from, because the
// choice decides which address every flow out of this node's LAN appears as
// and guessing it would change under an unrelated edit to the address list.
func (e Egress) ReturnSource(family uint8, mesh []netip.Addr) (netip.Addr, error) {
	if !e.Return {
		return netip.Addr{}, nil
	}
	if source := e.SourceOf(family); source.Addr.IsValid() {
		return source.Addr, nil
	}
	var candidates []netip.Addr
	for _, address := range mesh {
		if AddressFamily(address) != family || !address.IsGlobalUnicast() && !address.IsPrivate() {
			continue
		}
		if !slices.Contains(candidates, address) {
			candidates = append(candidates, address)
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries no %s mesh address to translate to, so name one in egress.source%s",
			FamilyName(family), familyDigit(family))
	default:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries %d %s mesh addresses (%s), so name the one to translate to in egress.source%s",
			len(candidates), FamilyName(family), joinAddrs(candidates), familyDigit(family))
	}
}

func familyDigit(family uint8) string {
	if family == FamilyIPv4 {
		return "4"
	}
	return "6"
}

func joinAddrs(addresses []netip.Addr) string {
	text := make([]string, 0, len(addresses))
	for _, address := range addresses {
		text = append(text, address.String())
	}
	return strings.Join(text, ", ")
}

// AddressFamily is the family of address, FamilyIPv4 or FamilyIPv6
func AddressFamily(address netip.Addr) uint8 {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}
