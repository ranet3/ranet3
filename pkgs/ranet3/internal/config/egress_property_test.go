// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// ruleShape is one kind of rule a drawn cap.table holds beside an egress segment
type ruleShape int

const (
	toMesh ruleShape = iota
	fromMesh
	toAndFromMesh
	markMesh
	toElsewhere
	iifMain
	iifElsewhere
	iifAddressed
	iifOtherDevice
	shapeCount
)

// egressRules draws up to six rules of every shape, each of a drawn family,
// and half the time one more sending both families from device to the main
// table
// destination rules take the low priorities, source rules the high ones and
// the device's rules the middle, overlapping at the edges, so a drawn table is
// often placed right and a misplaced one is often wrong by one rule
func egressRules(device string) hegel.Generator[[]kernel.Rule] {
	rule := hegel.Composite(func(tc hegel.TestCase) kernel.Rule {
		v6 := hegel.Draw(tc, hegel.Booleans())
		prefix := schema.MustPrefix("10.66.0.0/16")
		if v6 {
			prefix = schema.MustPrefix("3fff:a::/32")
		}
		family := hegel.Draw(tc, hegel.SampledFrom([]kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6, kernel.FamilyBoth}))
		shape := ruleShape(hegel.Draw(tc, pbt.Spanning(0, int(shapeCount)-1)))
		lo, hi := uint32(1), uint32(12)
		switch shape {
		case toMesh:
			hi = 6
		case fromMesh, toAndFromMesh:
			lo = 6
		case iifMain, iifElsewhere, iifAddressed, iifOtherDevice:
			lo, hi = 4, 9
		}
		r := kernel.Rule{Table: kernel.DefaultTable, Priority: hegel.Draw(tc, pbt.Spanning(lo, hi))}
		switch shape {
		case toMesh:
			r.To = prefix
		case fromMesh:
			r.From = prefix
		case toAndFromMesh:
			r.To, r.From = prefix, prefix
		case markMesh:
			r.FWMark, r.Family = 7, family
		case toElsewhere:
			r.To, r.Table = prefix, 300
		case iifMain:
			r.IIF, r.Table, r.Family = device, schema.TableMain, family
		case iifElsewhere:
			r.IIF, r.Table, r.Family = device, 300, family
		case iifAddressed:
			r.IIF, r.Table, r.To = device, schema.TableMain, prefix
		case iifOtherDevice:
			r.IIF, r.Table, r.Family = device+"x", schema.TableMain, family
		}
		return r
	})
	return hegel.Composite(func(tc hegel.TestCase) []kernel.Rule {
		rules := hegel.Draw(tc, hegel.Lists(rule).MaxSize(6))
		if hegel.Draw(tc, hegel.Booleans()) {
			rules = append(rules, kernel.Rule{IIF: device, Table: schema.TableMain, Family: kernel.FamilyBoth, Priority: hegel.Draw(tc, pbt.Spanning[uint32](4, 9))})
		}
		return rules
	})
}

// ruleFamilies is the families one written rule covers
func ruleFamilies(rule kernel.Rule) []kernel.Family {
	switch {
	case rule.To.IsValid() && rule.To.Addr().Is4(), rule.From.IsValid() && rule.From.Addr().Is4():
		return []kernel.Family{kernel.FamilyIPv4}
	case rule.To.IsValid() || rule.From.IsValid():
		return []kernel.Family{kernel.FamilyIPv6}
	case rule.Family == kernel.FamilyBoth:
		return []kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6}
	}
	return []kernel.Family{rule.Family}
}

// placed is the model of the egress device's rule: in each family at least one
// rule sends what arrives on device to the main table and selects on nothing
// else, and each such rule sits after every rule into the mesh table naming a
// destination and no source, and before every one naming a source
func placed(rules []kernel.Rule, device string) bool {
	for _, family := range []kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6} {
		var in []kernel.Rule
		for _, rule := range rules {
			for _, covered := range ruleFamilies(rule) {
				if covered == family {
					in = append(in, rule)
				}
			}
		}
		found := false
		for _, candidate := range in {
			if candidate.IIF != device || candidate.Table != schema.TableMain || candidate.To.IsValid() || candidate.From.IsValid() || candidate.FWMark != 0 {
				continue
			}
			found = true
			for _, other := range in {
				if other.Table != kernel.DefaultTable {
					continue
				}
				if other.From.IsValid() && candidate.Priority >= other.Priority {
					return false
				}
				if other.To.IsValid() && !other.From.IsValid() && candidate.Priority <= other.Priority {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// egressSIDs are the SIDs the properties below give their egress segments, in order
var egressSIDs = []string{"2a0c:b641:69c:5d26::3", "2a0c:b641:69c:5d26::4", "2a0c:b641:69c:5d26::5"}

// egressExit is an exit whose mesh tun is tun, with cap.table table and an egress segment at each of the first count egressSIDs
func egressExit(tun string, table *kernel.Table, count int) Config {
	var segments []srv6.Segment
	for _, sid := range egressSIDs[:count] {
		segments = append(segments, srv6.Segment{
			SID:      schema.MustAddr(sid),
			Behavior: srv6.BehaviorEndDT46,
			Deliver:  srv6.DeliverEgress,
			Allow:    []schema.Prefix{schema.MustPrefix("3fff:a::/32")},
		})
	}
	return Config{
		Node: identity.MustParse("example/exit"),
		Auth: Auth{Key: "key.pem", Trust: "trust.json"},
		Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}, TUN: tun},
		Dial: Dial{All: true},
		Cap:  Caps{Egress: &egress.Egress{}, Table: table, Segment: &srv6.Segments{Local: segments}},
	}
}

// A node with one or two egress segments loads exactly when its drawn
// cap.table rules place the egress device's rule as the model says, whatever
// the mesh tun is named
func TestEgressRuleIsTakenExactlyWhereItSits(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		tun := hegel.Draw(ht, hegel.SampledFrom([]string{"", "ranet0", "wg"}))
		device := map[string]string{"": "ranet3e", "ranet0": "ranet0e", "wg": "wge"}[tun]
		table := &kernel.Table{Rules: hegel.Draw(ht, egressRules(device))}
		ht.Assume(table.Validate() == nil)
		count := hegel.Draw(ht, pbt.Spanning(1, 2))
		c := egressExit(tun, table, count)
		err := c.Validate()
		if want := placed(table.Rules, device); want != (err == nil) {
			ht.Fatalf("%d egress segments and the rules %v beside %s loaded with %v, want taken %v", count, table.Rules, device, err, want)
		}
	})
}

// A node with up to three egress segments and the egress device's rule in
// place loads exactly when cap.route announces none of their /128s, whatever
// else it announces, a covering prefix included
func TestEgressSIDsRoutesAreLeftToReadiness(t *testing.T) {
	table := &kernel.Table{Rules: []kernel.Rule{{IIF: "ranet3e", Table: schema.TableMain, Family: kernel.FamilyBoth, Priority: 120}}}
	pool := []string{"2a0c:b641:69c:5d20::/60", "2001:db8::/32", "2a0c:b641:69c:5d26::6/128"}
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(1, len(egressSIDs)))
		c := egressExit("", table, count)
		var announce []schema.Announce
		sid := false
		for i, address := range egressSIDs {
			if hegel.Draw(ht, hegel.Booleans()) {
				announce = append(announce, schema.Announce{Prefix: schema.MustPrefix(address + "/128")})
				sid = sid || i < count
			}
		}
		for _, prefix := range pool {
			if hegel.Draw(ht, hegel.Booleans()) {
				announce = append(announce, schema.Announce{Prefix: schema.MustPrefix(prefix)})
			}
		}
		if len(announce) != 0 {
			c.Cap.Route = &babel.Routes{Announce: announce}
		}
		if err := c.Validate(); (err == nil) == sid {
			ht.Fatalf("%d egress segments beside cap.route announcing %v loaded with %v, want taken %v", count, announce, err, !sid)
		}
	})
}
