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

// borderTaken is the model of what the loader takes of cap.border beside
// egress segments and cap.egress, where a node with an allow entry writes a
// local segment: without the block, no local segment, and with it, an overlay
// of at least one entry, each a masked prefix of its own family no shorter
// than the family's floor and longer than zero, none written twice, holding an
// IPv6 prefix beside a local segment, covering every allow entry, and
// overlapping no advertised prefix but a default
func borderTaken(border *egress.Border, allow, advertise []schema.Prefix) bool {
	if border == nil {
		return len(allow) == 0
	}
	if len(border.Overlay) == 0 {
		return false
	}
	for i, entry := range border.Overlay {
		prefix := entry.Prefix
		floor := schema.MinSourceBits6
		if prefix.Addr().Is4() {
			floor = schema.MinSourceBits4
		}
		if prefix.Masked() != prefix || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Bits() < floor ||
			slices.ContainsFunc(border.Overlay[:i], func(other schema.Prefix) bool { return other.Prefix == prefix }) {
			return false
		}
	}
	if len(allow) > 0 && !slices.ContainsFunc(border.Overlay, func(entry schema.Prefix) bool { return entry.Addr().Is6() }) {
		return false
	}
	for _, allowed := range allow {
		covered := false
		for _, entry := range border.Overlay {
			covered = covered || entry.Addr().BitLen() == allowed.Addr().BitLen() && entry.Bits() <= allowed.Bits() && maskedTo(allowed, entry.Bits()) == entry.Addr()
		}
		if !covered {
			return false
		}
	}
	for _, advertised := range advertise {
		for _, entry := range border.Overlay {
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

// maskedTo is prefix's address with every bit past bits cleared
func maskedTo(prefix schema.Prefix, bits int) netip.Addr {
	masked, _ := prefix.Addr().Prefix(bits)
	return masked.Addr()
}

// An exit with one or two egress segments and cap.egress loads exactly where
// the model takes its cap.border, drawn absent, from overlay entries on either
// side of the allow lists' and the advertised prefixes' edges, and with each
// entry the block refuses on its own, a node without the block refused for
// that by name, and a configuration it takes reads back unchanged from each
// format
func TestBorderLoadsExactlyWhereTheModelTakesIt(t *testing.T) {
	pool := []schema.Prefix{
		// covering the allow list's IPv4 entry, equal to it, shorter, longer, beside it
		schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("23.161.0.0/16"), schema.MustPrefix("23.161.104.0/25"), schema.MustPrefix("23.161.105.0/24"),
		// the same for its IPv6 entry
		schema.MustPrefix("2602:f590::/36"), schema.MustPrefix("2602::/16"), schema.MustPrefix("2602:f590::/37"), schema.MustPrefix("2602:f591::/36"),
		// overlapping no allow entry
		schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20"),
		// refused by the block itself
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0"), schema.MustPrefix("8.0.0.0/7"), schema.MustPrefix("2000::/11"),
		schema.MustPrefix("10.0.0.0/8"), schema.MustPrefix("2000::/12"), schema.MustPrefix("198.18.0.1/15"), schema.MustPrefix("::ffff:198.18.0.0/111"),
	}
	advertised := []schema.Prefix{
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0"), schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8::/32"),
		schema.MustPrefix("198.18.4.0/24"), schema.MustPrefix("23.0.0.0/8"), schema.MustPrefix("3fff:a::/32"), schema.MustPrefix("10.1.0.0/16"),
	}
	pbt.Check(t, func(ht *hegel.T) {
		var border *egress.Border
		var advertise []schema.Prefix
		if hegel.Draw(ht, hegel.Booleans()) {
			// half the cases draw an overlay the block takes, covering the allow
			// list or missing one family's entry by a longer prefix, beside an
			// advertise list that overlaps it, is the exit default or is apart
			v4, v6 := schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("2602:f590::/36")
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
				v4 = schema.MustPrefix("23.161.104.0/25")
			}
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
				v6 = schema.MustPrefix("2602:f590::/37")
			}
			overlay := []schema.Prefix{v4, v6}
			// the pool's entries before the ones the block refuses
			for _, prefix := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool[:10])).MaxSize(2)) {
				if !slices.Contains(overlay, prefix) {
					overlay = append(overlay, prefix)
				}
			}
			border = &egress.Border{Overlay: overlay}
			advertise = slices.Clone(hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				nil,
				{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")},
				{schema.MustPrefix("23.0.0.0/8")},
				{schema.MustPrefix("2602:f590:1::/48")},
				{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8::/32")},
				{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.18.4.0/24")},
			})))
		} else {
			if hegel.Draw(ht, hegel.WeightedBooleans(7.0/8)) {
				border = &egress.Border{Overlay: hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(4))}
			}
			for _, prefix := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(advertised)).MaxSize(3)) {
				if !slices.Contains(advertise, prefix) {
					advertise = append(advertise, prefix)
				}
			}
		}
		allow := []schema.Prefix{schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("2602:f590::/36")}
		segments := []srv6.Segment{{SID: schema.MustAddr("2a0c:b641:69c:5d26::3"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow}}
		if hegel.Draw(ht, hegel.Booleans()) {
			// a second egress segment, whose allow list the overlay covers or
			// misses apart from the first's
			second := slices.Clone(hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
				{schema.MustPrefix("23.161.104.128/25"), schema.MustPrefix("2602:f590:1::/48")},
				{schema.MustPrefix("198.18.4.0/24"), schema.MustPrefix("3fff:a::/32")},
				{schema.MustPrefix("3fff:a::/32")},
				allow,
			})))
			segments = append(segments, srv6.Segment{SID: schema.MustAddr("2a0c:b641:69c:5d26::4"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: second})
			allow = slices.Concat(allow, second)
		}
		c := Config{
			Node: identity.MustParse("example/exit"),
			Auth: Auth{Key: "key.pem", Trust: "trust.json"},
			Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}},
			Dial: Dial{All: true},
			Cap: Caps{
				Egress: &egress.Egress{Advertise: advertise},
				Border: border,
				Table: &kernel.Table{Rules: []kernel.Rule{
					{To: schema.MustPrefix("10.66.0.0/16"), Table: kernel.DefaultTable, Priority: 100},
					{IIF: "ranet3e", Table: schema.TableMain, Priority: 120, Family: kernel.FamilyBoth},
					{From: schema.MustPrefix("10.66.0.0/16"), Table: kernel.DefaultTable, Priority: 150},
				}},
				Segment: &srv6.Segments{Local: segments},
			},
		}
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
			c.Cap.Segment, c.Cap.Egress, allow, advertise = nil, nil, nil, nil
		}
		err := c.Validate()
		if want := borderTaken(border, allow, advertise); want != (err == nil) {
			ht.Fatalf("%s beside allow %v and advertise %v loaded with %v, want taken %v", describe(border), allow, advertise, err, want)
		}
		// refused for the absent block itself, not later for the local table it leaves unbounded
		if border == nil && len(allow) > 0 && !strings.Contains(fmt.Sprint(err), "is written and cap.border is absent") {
			ht.Fatalf("local segments without cap.border were refused with %v, want the absent block named", err)
		}
		if err == nil {
			sameAfterEachEncoder(ht, c)
		}
	})
}

func describe(border *egress.Border) string {
	if border == nil {
		return "no cap.border"
	}
	return fmt.Sprintf("cap.border overlay %v", border.Overlay)
}
