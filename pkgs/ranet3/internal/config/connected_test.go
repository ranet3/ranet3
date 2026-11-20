// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

var connectedOverlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}

func untranslatedFrom(from string) egress.Class {
	return egress.Class{From: schema.MustPrefix(from), To: egress.Translation{None: true}}
}

func translatedFrom(from string) egress.Class {
	return egress.Class{From: schema.MustPrefix(from), To: egress.Translation{Auto: true}}
}

// assigningExit is an exit advertising both defaults
func assigningExit(classes []egress.Class, addresses ...string) Config {
	c := Config{
		Node:    identity.MustParse("example/exit"),
		Auth:    Auth{Key: "key.pem", Trust: "trust.json"},
		Link:    Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}},
		Dial:    Dial{All: true},
		Overlay: connectedOverlay,
		Cap: Caps{
			Egress: &egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Translate: classes},
			Table:  &kernel.Table{},
		},
	}
	for _, address := range addresses {
		c.Cap.Table.Addresses = append(c.Cap.Table.Addresses, schema.MustPrefix(address))
	}
	return c
}

// assigningLeaf is assigningExit advertising the LANs behind it,
// 198.51.100.0/24 and 2001:db8:5::/48, in place of the defaults, in cap.exit's
// mode under fallback none with those LANs as its lan
func assigningLeaf(classes []egress.Class, addresses ...string) Config {
	c := assigningExit(classes, addresses...)
	lans := []schema.Prefix{schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("2001:db8:5::/48")}
	c.Cap.Egress.Advertise = lans
	c.Cap.Exit = &kernel.ExitMode{Fallback: kernel.FallbackNone, LAN: lans}
	return c
}

func withAnnounced(c Config, assign bool, prefix string) Config {
	c.Cap.Route = &babel.Routes{Announce: []schema.Announce{{Prefix: schema.MustPrefix(prefix)}}}
	c.Cap.Table.AssignAnnounced = assign
	return c
}

// The loader refuses an address cap.table assigns under a length shorter than
// its own where an address of its network outside the overlay takes a none
// class as the longest class covering it, naming the assigned prefix and the
// class of the first such address, on an exit and in cap.exit's mode alike, in
// each family. A full length, a network inside the overlay, one under no class
// or under a class that translates, a longer class that translates, and a LAN
// the node announces, advertises or keeps as cap.exit's lan outside the overlay
// all load. A file holding such an address and an exemption outside the overlay
// is refused for the exemption.
func TestAssignedNetworkOutsideTheOverlayUnderANoneClassIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		node Config
		// the refusal names assigned and class, both empty for a node that loads
		assigned, class string
		// refused by another check, which names this
		other string
	}{
		{"refused: network inside a none class", assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}, "198.51.100.1/25"), "198.51.100.1/25", "198.51.100.0/25", ""},
		{"refused: ipv6 network inside a none class", assigningExit([]egress.Class{untranslatedFrom("2001:db8:5::/64")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5::/64", ""},
		{"refused: network inside a none class in cap.exit's mode", assigningLeaf([]egress.Class{untranslatedFrom("198.51.100.0/24")}, "198.51.100.1/25"), "198.51.100.1/25", "198.51.100.0/24", ""},
		{"refused: ipv6 network inside a none class in cap.exit's mode", assigningLeaf([]egress.Class{untranslatedFrom("2001:db8:5::/48")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5::/48", ""},
		{"refused: announced prefix assigned", withAnnounced(assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}), true, "198.51.100.0/25"), "198.51.100.0/25", "198.51.100.0/25", ""},
		{"refused: ipv6 announced prefix assigned", withAnnounced(assigningExit([]egress.Class{untranslatedFrom("2001:db8:5::/64")}), true, "2001:db8:5::/64"), "2001:db8:5::/64", "2001:db8:5::/64", ""},
		{"refused: network half inside the overlay", assigningExit([]egress.Class{untranslatedFrom("192.0.2.0/23")}, "192.0.2.1/23"), "192.0.2.1/23", "192.0.2.0/23", ""},
		{"refused: ipv6 network half inside the overlay", assigningExit([]egress.Class{untranslatedFrom("3fff::/19")}, "3fff::1/19"), "3fff::1/19", "3fff::/19", ""},
		{"refused: network half under no class", assigningExit([]egress.Class{untranslatedFrom("198.51.100.128/25")}, "198.51.100.1/24"), "198.51.100.1/24", "198.51.100.128/25", ""},
		{"refused: ipv6 network half under no class", assigningExit([]egress.Class{untranslatedFrom("2001:db8:5:0:8000::/65")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5:0:8000::/65", ""},
		{"refused: network half a longer class translates", assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/24"), translatedFrom("198.51.100.0/25")}, "198.51.100.1/24"), "198.51.100.1/24", "198.51.100.0/24", ""},
		{"refused: ipv6 network half a longer class translates", assigningExit([]egress.Class{untranslatedFrom("2001:db8:5::/64"), translatedFrom("2001:db8:5::/65")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5::/64", ""},
		{"refused: none class inside a translating one inside a none one", assigningExit([]egress.Class{untranslatedFrom("198.51.0.0/16"), translatedFrom("198.51.100.0/24"), untranslatedFrom("198.51.100.64/26")}, "198.51.100.1/25"), "198.51.100.1/25", "198.51.100.64/26", ""},
		{"refused: ipv6 none class inside a translating one inside a none one", assigningExit([]egress.Class{untranslatedFrom("2001:db8::/32"), translatedFrom("2001:db8:5::/48"), untranslatedFrom("2001:db8:5:0:4000::/66")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5:0:4000::/66", ""},
		{"refused: network meeting two none classes names the first", assigningExit([]egress.Class{untranslatedFrom("198.51.100.128/26"), untranslatedFrom("198.51.100.0/26")}, "198.51.100.1/24"), "198.51.100.1/24", "198.51.100.0/26", ""},
		{"refused: ipv6 network meeting two none classes names the first", assigningExit([]egress.Class{untranslatedFrom("2001:db8:5:0:8000::/66"), untranslatedFrom("2001:db8:5::/66")}, "2001:db8:5::1/64"), "2001:db8:5::1/64", "2001:db8:5::/66", ""},
		{"refused: second address after one that loads", assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}, "198.51.100.1/32", "198.51.100.2/26"), "198.51.100.2/26", "198.51.100.0/25", ""},
		{"refused for the exemption: exemption outside the overlay beside a network inside a none class", func() Config {
			c := assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}, "198.51.100.1/25")
			c.Cap.Antispoof = &egress.Antispoof{Exempt: []schema.Prefix{schema.MustPrefix("198.51.100.0/25")}}
			return c
		}(), "", "", "lies outside overlay, and the filter drops only an overlay source, so it would exempt nothing"},

		{"loads: address at its full length", assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}, "198.51.100.1/32"), "", "", ""},
		{"loads: ipv6 address at its full length", assigningExit([]egress.Class{untranslatedFrom("2001:db8:5::/64")}, "2001:db8:5::1/128"), "", "", ""},
		{"loads: network inside the overlay", assigningExit([]egress.Class{untranslatedFrom("192.0.2.0/24")}, "192.0.2.1/25"), "", "", ""},
		{"loads: ipv6 network inside the overlay", assigningExit([]egress.Class{untranslatedFrom("3fff::/20")}, "3fff::1/64"), "", "", ""},
		{"loads: network under no class", assigningExit([]egress.Class{untranslatedFrom("203.0.113.0/24")}, "198.51.100.1/25"), "", "", ""},
		{"loads: ipv6 network under no class", assigningExit([]egress.Class{untranslatedFrom("2001:db8:7::/48")}, "2001:db8:5::1/64"), "", "", ""},
		{"loads: network under a class of auto", assigningExit([]egress.Class{translatedFrom("198.51.100.0/24")}, "198.51.100.1/25"), "", "", ""},
		{"loads: ipv6 network under a class of an address", assigningExit([]egress.Class{{From: schema.MustPrefix("2001:db8:5::/48"), To: egress.Translation{Addr: netip.MustParseAddr("2001:db8:7::1")}}}, "2001:db8:5::1/64"), "", "", ""},
		{"loads: network a longer class translates whole", assigningExit([]egress.Class{untranslatedFrom("198.51.0.0/16"), translatedFrom("198.51.100.0/24")}, "198.51.100.1/25"), "", "", ""},
		{"loads: ipv6 network a longer class translates whole", assigningExit([]egress.Class{untranslatedFrom("2001:db8::/32"), translatedFrom("2001:db8:5::/48")}, "2001:db8:5::1/64"), "", "", ""},
		{"loads: announced prefix not assigned", withAnnounced(assigningExit([]egress.Class{untranslatedFrom("198.51.100.0/25")}, "192.0.2.1/32"), false, "198.51.100.0/25"), "", "", ""},
		{"loads: ipv6 announced prefix not assigned", withAnnounced(assigningExit([]egress.Class{untranslatedFrom("2001:db8:5::/64")}, "3fff::1/128"), false, "2001:db8:5::/64"), "", "", ""},
		{"loads: advertised lan and cap.exit lan", assigningLeaf([]egress.Class{untranslatedFrom("198.51.100.0/24"), untranslatedFrom("2001:db8:5::/48")}, "192.0.2.1/24", "3fff::1/64"), "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.node.Validate()
			switch {
			case c.other != "":
				if err == nil || !strings.Contains(err.Error(), c.other) || strings.Contains(err.Error(), "cap.table assigns") {
					t.Errorf("loaded with %v, want refused for %q alone", err, c.other)
				}
			case c.assigned == "":
				if err != nil {
					t.Errorf("refused: %v", err)
				}
			case err == nil:
				t.Errorf("loaded, want %s refused under class %s", c.assigned, c.class)
			case !strings.Contains(err.Error(), fmt.Sprintf("cap.table assigns %s,", c.assigned)) || !strings.Contains(err.Error(), fmt.Sprintf("class %s,", c.class)):
				t.Errorf("refused with %v, want %s and class %s named", err, c.assigned, c.class)
			}
		})
	}
}
