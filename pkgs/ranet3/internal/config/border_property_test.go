// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// overlayTaken is the model of what the loader takes of overlay beside egress
// segments and cap.egress, where a node with an allow entry writes a local
// segment: without it, no local segment, and with it, at least one entry, each
// a masked prefix of its own family no shorter than the family's floor and
// longer than zero, none written twice, holding an IPv6 prefix beside a local
// segment, covering an IPv6 entry of each allow list that holds an entry it
// does not cover, and overlapping no advertised prefix but a default. The
// entries cover together, so a prefix two of them hold half each is covered.
// Without the overlay no translate class is none either, since
// nothing but the overlay tells the mesh's node addresses from the LANs the
// none sets leave out.
func overlayTaken(overlay []schema.Prefix, allows [][]schema.Prefix, advertise []schema.Prefix, none bool) bool {
	if overlay == nil {
		return len(allows) == 0 && !none
	}
	if len(overlay) == 0 {
		return false
	}
	for i, entry := range overlay {
		prefix := entry.Prefix
		floor := schema.MinSourceBits6
		if prefix.Addr().Is4() {
			floor = schema.MinSourceBits4
		}
		if prefix.Masked() != prefix || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Bits() < floor ||
			slices.ContainsFunc(overlay[:i], func(other schema.Prefix) bool { return other.Prefix == prefix }) {
			return false
		}
	}
	if len(allows) > 0 && !slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return entry.Addr().Is6() }) {
		return false
	}
	for _, allow := range allows {
		uncovered := slices.ContainsFunc(allow, func(allowed schema.Prefix) bool { return !covered(overlay, allowed) })
		ipv6 := slices.ContainsFunc(allow, func(allowed schema.Prefix) bool { return allowed.Addr().Is6() && covered(overlay, allowed) })
		if uncovered && !ipv6 {
			return false
		}
	}
	for _, advertised := range advertise {
		for _, entry := range overlay {
			if advertised.Bits() == 0 || advertised.Addr().BitLen() != entry.Addr().BitLen() {
				continue
			}
			shorter := min(advertised.Bits(), entry.Bits())
			if maskedTo(advertised, shorter) == maskedTo(entry, shorter) {
				return false
			}
		}
	}
	return true
}

// antispoofTaken is the model of what the loader takes of cap.antispoof beside
// an overlay it took: no block, or one beside an overlay exempting something,
// each list holding each prefix once and only prefixes the overlay's entries
// cover, and each interface named exactly or by what comes before one
// trailing *, at least one byte and at most 15 of it, with a list of its own
func antispoofTaken(overlay []schema.Prefix, antispoof *egress.Antispoof) bool {
	if antispoof == nil {
		return true
	}
	if overlay == nil || len(antispoof.Exempt) == 0 && len(antispoof.Interface) == 0 {
		return false
	}
	list := func(exempt []schema.Prefix) bool {
		for i, prefix := range exempt {
			if !covered(overlay, prefix) || slices.Contains(exempt[:i], prefix) {
				return false
			}
		}
		return true
	}
	if !list(antispoof.Exempt) {
		return false
	}
	for name, entry := range antispoof.Interface {
		pattern := strings.TrimSuffix(name, "*")
		if pattern == "" || strings.Contains(pattern, "*") || len(pattern) > 15 || len(entry.Exempt) == 0 || !list(entry.Exempt) {
			return false
		}
	}
	return true
}

// covered reports each address of prefix lying in some overlay entry: the
// entries of its family, as ranges of addresses joined where they touch or
// overlap, hold its first and last address in one range
func covered(overlay []schema.Prefix, prefix schema.Prefix) bool {
	type span struct{ first, last netip.Addr }
	var spans []span
	for _, entry := range overlay {
		if entry.Addr().BitLen() == prefix.Addr().BitLen() {
			spans = append(spans, span{entry.Masked().Addr(), lastOf(entry.Prefix)})
		}
	}
	slices.SortFunc(spans, func(a, b span) int { return a.first.Compare(b.first) })
	first, last := prefix.Masked().Addr(), lastOf(prefix.Prefix)
	for i := 0; i < len(spans); i++ {
		joined := spans[i]
		for i+1 < len(spans) && joined.last.Next().IsValid() && spans[i+1].first.Compare(joined.last.Next()) <= 0 {
			i++
			if spans[i].last.Compare(joined.last) > 0 {
				joined.last = spans[i].last
			}
		}
		if joined.first.Compare(first) <= 0 && last.Compare(joined.last) <= 0 {
			return true
		}
	}
	return false
}

// lastOf is the highest address prefix holds
func lastOf(prefix netip.Prefix) netip.Addr {
	raw := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(raw)*8; bit++ {
		raw[bit/8] |= 0x80 >> (bit % 8)
	}
	last, _ := netip.AddrFromSlice(raw)
	return last
}

// maskedTo is prefix's address with every bit past bits cleared
func maskedTo(prefix schema.Prefix, bits int) netip.Addr {
	masked, _ := prefix.Addr().Prefix(bits)
	return masked.Addr()
}

// An exit with one or two egress segments and cap.egress, or with cap.egress
// alone, translating none for a class now and then, loads exactly where the
// models take its overlay, drawn absent, from entries on either side of the
// allow lists' and the advertised prefixes' edges, from two halves covering an
// allow entry and an exemption only together, and with each entry the
// filter refuses on its own, and its cap.antispoof, drawn absent, exempting
// prefixes inside and outside the overlay and from names exact, wildcarded and
// refused. A node without the overlay is refused for that by name, and a
// configuration the models take reads back unchanged from each format.
func TestOverlayLoadsExactlyWhereTheModelTakesIt(t *testing.T) {
	pool := []schema.Prefix{
		// covering the allow list's IPv4 entry, equal to it, shorter, longer, beside it
		schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("203.0.0.0/8"), schema.MustPrefix("203.0.113.0/25"), schema.MustPrefix("198.51.100.0/24"),
		// the same for its IPv6 entry
		schema.MustPrefix("3fff:a::/36"), schema.MustPrefix("3fff:a::/32"), schema.MustPrefix("3fff:a::/37"), schema.MustPrefix("3fff:a:1000::/36"),
		// overlapping no allow entry
		schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff:c::/30"),
		// refused by the filter itself
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0"), schema.MustPrefix("8.0.0.0/7"), schema.MustPrefix("2000::/11"),
		schema.MustPrefix("10.0.0.0/8"), schema.MustPrefix("2000::/12"), schema.MustPrefix("198.18.0.1/15"), schema.MustPrefix("::ffff:198.18.0.0/111"),
	}
	advertised := []schema.Prefix{
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0"), schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8::/32"),
		schema.MustPrefix("198.18.4.0/24"), schema.MustPrefix("203.0.0.0/8"), schema.MustPrefix("3fff:c::/32"), schema.MustPrefix("10.1.0.0/16"),
	}
	// inside the overlay's IPv4 entry, equal to it, inside a shorter one alone,
	// reaching past it, and the same for IPv6
	exempts := []schema.Prefix{
		schema.MustPrefix("203.0.113.128/26"), schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("203.0.112.0/24"), schema.MustPrefix("203.0.112.0/23"),
		schema.MustPrefix("3fff:a:1::/48"), schema.MustPrefix("3fff:a::/36"), schema.MustPrefix("3fff:a:f000::/36"), schema.MustPrefix("3fff:a::/35"),
	}
	names := []string{"eth1", "wl*", "fifteen-bytes-x", "fifteen-bytes-x*", "sixteen-bytes-xy", "*", "", "w*0", "wl**"}
	pbt.Check(t, func(ht *hegel.T) {
		var overlay, advertise []schema.Prefix
		if hegel.Draw(ht, hegel.Booleans()) {
			// half the cases draw an overlay the filter takes, covering the allow
			// list by one entry or by the union of its two halves, or missing one
			// family's entry by a longer prefix, beside an advertise list that
			// overlaps it, is the exit default or is apart
			v4 := hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				{schema.MustPrefix("203.0.113.0/24")},
				{schema.MustPrefix("203.0.113.0/24")},
				{schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("203.0.113.0/25")},
				{schema.MustPrefix("203.0.113.0/25")},
			}))
			v6 := hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				{schema.MustPrefix("3fff:a::/36")},
				{schema.MustPrefix("3fff:a::/36")},
				{schema.MustPrefix("3fff:a::/37"), schema.MustPrefix("3fff:a:800::/37")},
				{schema.MustPrefix("3fff:a::/37")},
			}))
			overlay = append(slices.Clone(v4), v6...)
			// the pool's entries before the ones the filter refuses
			for _, prefix := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool[:10])).MaxSize(2)) {
				if !slices.Contains(overlay, prefix) {
					overlay = append(overlay, prefix)
				}
			}
			advertise = slices.Clone(hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				nil,
				{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")},
				{schema.MustPrefix("203.0.0.0/8")},
				{schema.MustPrefix("3fff:a:1::/48")},
				{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8::/32")},
				{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.18.4.0/24")},
			})))
		} else {
			if hegel.Draw(ht, hegel.WeightedBooleans(7.0/8)) {
				overlay = append([]schema.Prefix{}, hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(4))...)
			}
			for _, prefix := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(advertised)).MaxSize(3)) {
				if !slices.Contains(advertise, prefix) {
					advertise = append(advertise, prefix)
				}
			}
		}
		// an empty list is drawn as none, which is all an encoder writes of it
		exempt := func() []schema.Prefix {
			list := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(exempts)).MaxSize(2))
			if len(list) == 0 {
				return nil
			}
			return list
		}
		var antispoof *egress.Antispoof
		if hegel.Draw(ht, hegel.Booleans()) {
			antispoof = &egress.Antispoof{Exempt: exempt()}
			for _, name := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(names)).MaxSize(2)) {
				if antispoof.Interface == nil {
					antispoof.Interface = map[string]egress.AntispoofInterface{}
				}
				antispoof.Interface[name] = egress.AntispoofInterface{Exempt: exempt()}
			}
		}
		allow := []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff:a::/36")}
		segments := []srv6.Segment{{SID: schema.MustAddr("3fff:b:0:306::3"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow}}
		allows := [][]schema.Prefix{allow}
		if hegel.Draw(ht, hegel.Booleans()) {
			// a second egress segment, whose allow list the overlay covers or
			// misses apart from the first's, a LAN outside it beside an IPv6 entry inside among them
			second := slices.Clone(hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				{schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("3fff:a:1::/48")},
				{schema.MustPrefix("198.18.4.0/24"), schema.MustPrefix("3fff:c::/32")},
				{schema.MustPrefix("3fff:c::/32")},
				{schema.MustPrefix("3fff:a:1::/48"), schema.MustPrefix("2001:db8:f3::/64"), schema.MustPrefix("198.51.100.64/28")},
				{schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("2001:db8:f3::/64")},
				allow,
			})))
			segments = append(segments, srv6.Segment{SID: schema.MustAddr("3fff:b:0:306::4"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: second})
			allows = append(allows, second)
		}
		// a class of the leaves' addresses translating auto or none, beside a longer one translating auto
		translate := slices.Clone(hegel.Draw(ht, hegel.SampledFrom([][]egress.Class{
			nil,
			{{From: schema.MustPrefix("198.18.0.0/16"), To: egress.Translation{Auto: true}}},
			{{From: schema.MustPrefix("198.18.0.0/16"), To: egress.Translation{None: true}}},
			{{From: schema.MustPrefix("3fff:c::/32"), To: egress.Translation{None: true}}, {From: schema.MustPrefix("3fff:c:1::/48"), To: egress.Translation{Auto: true}}},
		})))
		c := Config{
			Node:    identity.MustParse("example/exit"),
			Auth:    Auth{Key: "key.pem", Trust: "trust.json"},
			Link:    Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}},
			Dial:    Dial{All: true},
			Overlay: overlay,
			Cap: Caps{
				Egress:    &egress.Egress{Advertise: advertise, Translate: translate},
				Antispoof: antispoof,
				Table:     &kernel.Table{},
				Segment:   &srv6.Segments{Local: segments},
			},
		}
		switch {
		case hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)):
			c.Cap.Segment, c.Cap.Egress, allows, advertise, translate = nil, nil, nil, nil, nil
		case hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)):
			// cap.egress alone, an exit advertising the defaults with no segment
			advertise = []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
			c.Cap.Segment, c.Cap.Egress.Advertise, allows = nil, advertise, nil
		}
		none := slices.ContainsFunc(translate, func(class egress.Class) bool { return class.To.None })
		err := c.Validate()
		want := overlayTaken(overlay, allows, advertise, none) && antispoofTaken(overlay, antispoof)
		if want != (err == nil) {
			ht.Fatalf("%s beside allow %v, advertise %v and translate %v loaded with %v, want taken %v", describe(overlay, antispoof), allows, advertise, translate, err, want)
		}
		// refused for the absent overlay itself, not later for the local table it leaves unbounded
		if overlay == nil && antispoof == nil && len(allows) > 0 && !strings.Contains(fmt.Sprint(err), "is written and overlay is absent") {
			ht.Fatalf("local segments without overlay were refused with %v, want the absent overlay named", err)
		}
		// and a none class without it for that, by name
		if overlay == nil && antispoof == nil && len(allows) == 0 && none && !strings.Contains(fmt.Sprint(err), "is none and overlay is absent") {
			ht.Fatalf("a none class without overlay was refused with %v, want the class and the absent overlay named", err)
		}
		if err == nil {
			sameAfterEachEncoder(ht, c)
		}
	})
}

func describe(overlay []schema.Prefix, antispoof *egress.Antispoof) string {
	if overlay == nil {
		return fmt.Sprintf("no overlay and cap.antispoof %+v", antispoof)
	}
	return fmt.Sprintf("overlay %v and cap.antispoof %+v", overlay, antispoof)
}
