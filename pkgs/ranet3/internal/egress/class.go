// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/schema"
)

// Class is one entry of cap.egress translate: the sources inside From leave
// the mesh under To. It is the source that decides, not the path a packet took
// here, since with one tun the kernel sees the packet's addresses and the links
// it crosses and nothing of whether a route or a segment brought it.
type Class struct {
	From schema.Prefix `yaml:"from" json:"from" toml:"from"`
	To   Translation   `yaml:"to" json:"to" toml:"to"`
}

// Translation names the source a class's sources leave under, written
// "none", "auto" or as an address. A file writes one of the three.
type Translation struct {
	// None leaves the source as the packet carries it, which works only where
	// the exit's upstream accepts that source and the replies to it come back
	// into the mesh.
	None bool
	// Auto is the address this node's own routes would have used for the
	// packet, the only answer a deployment owning no address block has: the
	// address of the link the packet leaves the mesh by. Under a class from
	// 0.0.0.0/0 or ::/0, return translates to this node's own mesh address.
	Auto bool
	// Addr is an address written out, used unchanged, and under a class from
	// 0.0.0.0/0 or ::/0 by return as well. It is how a fleet with an address
	// block of its own has the replies come back to a chosen node rather than
	// to whichever one a reply reaches.
	Addr netip.Addr
}

// ClassOf is the class address leaves the mesh under, auto with no From where
// no class covers it
func (e Egress) ClassOf(address netip.Addr) Class {
	for _, class := range e.Classes(AddressFamily(address)) {
		if class.From.Contains(address) {
			return class
		}
	}
	return Class{To: Translation{Auto: true}}
}

// Classes is family's classes in the order a packet meets them, the longest
// From first, so the first covering an address is the class it takes. Two
// classes of one length cover no address in common, so their order by address
// decides nothing.
func (e Egress) Classes(family uint8) []Class {
	var out []Class
	for _, class := range e.Translate {
		if AddressFamily(class.From.Addr()) == family {
			out = append(out, class)
		}
	}
	slices.SortFunc(out, func(a, b Class) int {
		return cmp.Or(cmp.Compare(b.From.Bits(), a.From.Bits()), a.From.Addr().Compare(b.From.Addr()))
	})
	return out
}

// check refuses a class whose to cannot mean anything, its From checked
// already
func (c Class) check() error {
	name, to := "egress: cap.egress translate class "+c.From.String(), c.To
	var written []string
	if to.None {
		written = append(written, "none")
	}
	if to.Auto {
		written = append(written, "auto")
	}
	if to.Addr.IsValid() {
		written = append(written, to.Addr.String())
	}
	switch {
	case len(written) == 0:
		return fmt.Errorf("%s names no to, which is none, auto or an address", name)
	case to.Addr.Zone() != "":
		// Checked first, as the decoder checks it before unmapping: it refuses
		// a zone, so a capability carrying one renders to a file that does not
		// load.
		return fmt.Errorf("%s to %s carries a zone, which a translated address cannot", name, to.Addr)
	case len(written) > 1:
		// A file writes one of the three, and a to carrying more is written as
		// one of them and read back without the rest.
		return fmt.Errorf("%s has the to %s at once, and a to is one of none, auto and an address", name, strings.Join(written, " and "))
	case !to.None && sourceless(c.From.Prefix):
		return fmt.Errorf("%s to %s holds only sources a router forwards no packet from, so it translates nothing", name, to)
	case !to.Addr.IsValid():
		return nil
	case to.Addr.Is4In6():
		// Refused rather than judged in the family it is written in, as an
		// advertised prefix in this spelling is. The decoder unmaps it, so a
		// capability carrying one renders to a file that reads back as an IPv4
		// address, which an IPv6 class then refuses.
		return fmt.Errorf("%s to %s is an IPv4 address written as IPv6, so write it as %s", name, to.Addr, to.Addr.Unmap())
	case AddressFamily(to.Addr) != AddressFamily(c.From.Addr()):
		return fmt.Errorf("%s to %s is not of its from's family", name, to.Addr)
	case !to.Addr.IsGlobalUnicast() && !to.Addr.IsPrivate():
		// A translated packet has to be answerable, and a loopback, multicast or
		// unspecified source is one nothing replies to. A backend would install
		// it, and the failure would show only as a flow that never completes.
		return fmt.Errorf("%s to %s is not an address a reply can be sent to", name, to.Addr)
	}
	return nil
}

// sourceless reports whether from lies inside a block of sources a router
// forwards no packet from, RFC 1812 section 5.3.7, RFC 3927 section 7 and RFC
// 4291 sections 2.5.2, 2.5.3, 2.5.6 and 2.7, which the mesh drops before it
// hands a packet to an exit, as packet.InvalidSource has it. Each block runs as
// far as such sources do, 224.0.0.0/3 multicast with class E and ::/127 the
// unspecified and loopback addresses, so a from holding only such sources lies
// inside one.
func sourceless(from netip.Prefix) bool {
	return slices.ContainsFunc([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/3"),
		netip.MustParsePrefix("::/127"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}, func(block netip.Prefix) bool {
		return block.Contains(from.Addr()) && from.Bits() >= block.Bits()
	})
}

// checkTranslated refuses family's classes where every source of the family a
// router forwards a packet from takes one of none: an exit that translates
// nothing for anyone is an open relay for the overlay's sources onto its
// upstream
func (e Egress) checkTranslated(family uint8) error {
	classes := e.Classes(family)
	if !untranslated(classes, everySource(family)) {
		return nil
	}
	var nones []string
	for _, class := range classes {
		if class.To.None {
			nones = append(nones, class.From.String())
		}
	}
	name := "class " + nones[0] + " is"
	if len(nones) > 1 {
		name = "classes " + strings.Join(nones, " and ") + " are"
	}
	return fmt.Errorf("egress: cap.egress translate %s none, which leaves every %s source untranslated: an exit that translates nothing for anyone is an open relay for the overlay's sources onto its upstream",
		name, FamilyName(family))
}

// untranslated reports whether every source of prefix a router forwards a
// packet from takes a class of none among classes, which are in the order
// Classes gives. A prefix inside a block sourceless names counts as none
// whatever class it takes. Any other prefix holding a longer From splits in
// two, and one holding none takes its longest covering class.
func untranslated(classes []Class, prefix netip.Prefix) bool {
	if sourceless(prefix) {
		return true
	}
	split := slices.ContainsFunc(classes, func(class Class) bool {
		return class.From.Bits() > prefix.Bits() && prefix.Contains(class.From.Addr())
	})
	if !split {
		i := slices.IndexFunc(classes, func(class Class) bool {
			return class.From.Bits() <= prefix.Bits() && class.From.Contains(prefix.Addr())
		})
		return i >= 0 && classes[i].To.None
	}
	bits := prefix.Bits()
	raw := prefix.Addr().AsSlice()
	raw[bits/8] |= 0x80 >> (bits % 8)
	high, _ := netip.AddrFromSlice(raw)
	return untranslated(classes, netip.PrefixFrom(prefix.Addr(), bits+1)) && untranslated(classes, netip.PrefixFrom(high, bits+1))
}

// IsZero reports a translation nothing was written for, which Validate
// refuses. yaml.v3 and the toml encoder both consult it.
func (t Translation) IsZero() bool { return !t.None && !t.Auto && !t.Addr.IsValid() }

func (t Translation) String() string {
	switch {
	case t.None:
		return "none"
	case t.Addr.IsValid():
		return t.Addr.String()
	case t.Auto:
		return "auto"
	}
	return ""
}

func (t *Translation) UnmarshalText(text []byte) error {
	switch string(text) {
	case "none":
		*t = Translation{None: true}
		return nil
	case "auto":
		*t = Translation{Auto: true}
		return nil
	}
	address, err := netip.ParseAddr(string(text))
	if err != nil {
		return fmt.Errorf("a translation is none, auto or an address: %w", err)
	}
	if address.Zone() != "" {
		// A zone names a link on this host, and the address goes into a
		// translation rule the kernel matches on its own, so there is nothing
		// for one to select.
		return fmt.Errorf("translation %s carries a zone, which a translated address cannot", address)
	}
	*t = Translation{Addr: address.Unmap()}
	return nil
}

func (t Translation) MarshalText() ([]byte, error) {
	if t.IsZero() {
		return nil, fmt.Errorf("egress: a translation naming nothing has no spelling")
	}
	return []byte(t.String()), nil
}

func (t *Translation) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a translation, none, auto or an address", t)
}
