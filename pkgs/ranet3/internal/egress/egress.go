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
	// Translate is the classes the mesh's sources leave under: a source takes
	// the class of the longest From covering it, and auto where none covers
	// it, whether its packet came through an advertised prefix or an egress
	// segment. See Class.
	Translate []Class `yaml:"translate,omitempty" json:"translate,omitempty" toml:"translate,omitempty"`
	// Return translates the other direction too: a packet arriving from one of
	// the advertised prefixes and leaving through the mesh goes out under the
	// address of its family's class from 0.0.0.0/0 or ::/0, or this node's own
	// mesh address where that class is auto or absent. A subnet router needs it
	// where the mesh has no route back to the LAN, which is every deployment
	// that advertises a prefix the far end does not hold a route for. An exit
	// node does not: nothing sits behind it to start a flow.
	Return bool `yaml:"return,omitempty" json:"return,omitempty" toml:"return,omitempty"`
	// Sweep is the periodic pass. It reinstalls a table somebody removed and
	// reads the forwarding sysctls and the route lookups again, the parts of
	// readiness that change under a running node. Zero uses DefaultSweep.
	Sweep schema.Duration `yaml:"sweep,omitempty" json:"sweep,omitempty" toml:"sweep,omitempty"`
}

// Normalized is the capability as the translator runs it: the sweep the file
// left out filled in, an omitted list and an empty one the same, the
// advertised prefixes and the classes each in one order, and a class of auto
// from 0.0.0.0/0 or ::/0 left out, since leaving it out says the same. Two
// configurations are compared through this rather than as they were written,
// so neither such a class nor the order either list was written in is a
// change, and neither costs a restart.
//
// Neither order is meaningful. The advertised prefixes decide which families
// the rules keyed on the mesh device cover and which prefixes are announced,
// and both are sets. The classes are taken by the longest From covering a
// source, which Classes orders them by.
func (e Egress) Normalized() Egress {
	if len(e.Advertise) == 0 {
		e.Advertise = nil
	} else {
		e.Advertise = slices.SortedFunc(slices.Values(e.Advertise), schema.ComparePrefix)
	}
	if e.Sweep == 0 {
		e.Sweep = schema.Duration(DefaultSweep)
	}
	e.Translate = slices.DeleteFunc(slices.Clone(e.Translate), func(class Class) bool {
		return class.From.Bits() == 0 && class.To == Translation{Auto: true}
	})
	if len(e.Translate) == 0 {
		e.Translate = nil
	} else {
		slices.SortFunc(e.Translate, func(a, b Class) int { return schema.ComparePrefix(a.From, b.From) })
	}
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
	froms := make([]schema.Prefix, 0, len(e.Translate))
	for _, class := range e.Translate {
		froms = append(froms, class.From)
	}
	if err := schema.CheckPrefixes("egress: cap.egress translate from", froms, nil); err != nil {
		return err
	}
	for _, class := range e.Translate {
		if err := class.check(); err != nil {
			return err
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

// CheckReturn refuses what New refuses of the In direction's source under the
// families the capability advertises, such a family with no mesh address among
// mesh or several to pick from where no class from every address names one
func (e Egress) CheckReturn(mesh []netip.Addr) error {
	for _, family := range e.families() {
		if _, err := e.ReturnSource(family, mesh); err != nil {
			return err
		}
	}
	return nil
}

// ReturnSource is the address the In direction translates to for one family:
// the address of the family's class covering every source, or this node's own
// mesh address of that family among mesh. A node with several is refused
// rather than picked from, because the choice decides which address every flow
// out of this node's LAN appears as and guessing it would change under an
// unrelated edit to the address list.
func (e Egress) ReturnSource(family uint8, mesh []netip.Addr) (netip.Addr, error) {
	if !e.Return {
		return netip.Addr{}, nil
	}
	every := everySource(family)
	for _, class := range e.Translate {
		if class.From.Prefix == every && class.To.Addr.IsValid() {
			return class.To.Addr, nil
		}
	}
	switch candidates := MeshSources(family, mesh); len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries no %s mesh address to translate to, so name one in cap.egress translate as the to of the class from %s",
			FamilyName(family), every)
	default:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries %d %s mesh addresses (%s), so name the one to translate to in cap.egress translate as the to of the class from %s",
			len(candidates), FamilyName(family), joinAddrs(candidates), every)
	}
}

// MeshSources is the addresses of family among mesh that a reply can be sent
// to, in order and each once: the In direction's source where no class names
// one, and the sources this node's own traffic out of another link leaves
// from, each under its class
func MeshSources(family uint8, mesh []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, address := range mesh {
		if AddressFamily(address) == family && (address.IsGlobalUnicast() || address.IsPrivate()) {
			out = append(out, address)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// everySource is the prefix of family covering every address, 0.0.0.0/0 or ::/0
func everySource(family uint8) netip.Prefix {
	if family == FamilyIPv4 {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
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
