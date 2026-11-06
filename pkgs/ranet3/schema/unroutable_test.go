// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

import (
	"net/netip"
	"testing"
)

// each class's reason, a clause written after the prefix
const (
	thisNetwork = "holds addresses of this network, 0.0.0.0/8, which name the sender's own network"
	loopback4   = "holds loopback addresses, 127.0.0.0/8, which belong to the host"
	linkLocal4  = "holds link-local addresses, 169.254.0.0/16, which name the link they arrive on"
	multicast4  = "holds multicast addresses, 224.0.0.0/4, which name a group rather than a host"
	broadcast   = "holds the limited broadcast address 255.255.255.255, which names every host of the link"
	classE      = "holds class E addresses, 240.0.0.0/4, which are reserved and name no host"
	unspecified = "holds the unspecified address ::, which names no host"
	loopback6   = "holds the loopback address ::1, which belongs to the host"
	mapped      = "holds IPv4-mapped addresses, ::ffff:0:0/96, which stand for IPv4 addresses inside a host"
	linkLocal6  = "holds link-local addresses, fe80::/10, which name the link they arrive on"
	multicast6  = "holds multicast addresses, ff00::/8, which name a group rather than a host"
)

// Each class is named at its first and last address, a prefix inside it and
// itself, and held in part by a prefix holding it. The address before its
// first and the one after its last are named by their own class or by none. A
// prefix in class E holding the limited broadcast is held whole by class E.
func TestUnroutableNamesEachClassAtItsEdges(t *testing.T) {
	for _, c := range []struct {
		prefix, class string
		whole         bool
	}{
		{"0.0.0.0/32", thisNetwork, true}, {"0.255.255.255/32", thisNetwork, true}, {"1.0.0.0/32", "", false},
		{"0.0.0.0/8", thisNetwork, true}, {"0.1.0.0/16", thisNetwork, true}, {"0.0.0.0/7", thisNetwork, false},
		{"0.0.0.0/1", thisNetwork, false},

		{"126.255.255.255/32", "", false}, {"127.0.0.0/32", loopback4, true}, {"127.255.255.255/32", loopback4, true},
		{"128.0.0.0/32", "", false}, {"127.0.0.0/8", loopback4, true}, {"127.1.0.0/16", loopback4, true},
		{"126.0.0.0/7", loopback4, false},

		{"169.253.255.255/32", "", false}, {"169.254.0.0/32", linkLocal4, true}, {"169.254.255.255/32", linkLocal4, true},
		{"169.255.0.0/32", "", false}, {"169.254.0.0/16", linkLocal4, true}, {"169.254.169.0/24", linkLocal4, true},
		{"169.254.1.1/16", linkLocal4, true}, {"169.254.0.0/15", linkLocal4, false}, {"169.0.0.0/8", linkLocal4, false},
		{"128.0.0.0/1", linkLocal4, false},

		{"223.255.255.255/32", "", false}, {"224.0.0.0/32", multicast4, true}, {"239.255.255.255/32", multicast4, true},
		{"224.0.0.0/4", multicast4, true}, {"224.0.0.0/24", multicast4, true}, {"224.0.0.0/3", multicast4, false},
		{"192.0.0.0/2", multicast4, false},

		{"240.0.0.0/32", classE, true}, {"255.255.255.254/32", classE, true}, {"240.0.0.0/4", classE, true},
		{"240.0.0.0/8", classE, true}, {"255.0.0.0/8", classE, true}, {"255.255.255.0/24", classE, true},
		{"255.255.255.255/32", broadcast, true},

		{"::/128", unspecified, true}, {"::/127", unspecified, false}, {"::/96", unspecified, false},
		{"::/0", unspecified, false}, {"::/1", unspecified, false},

		{"::1/128", loopback6, true}, {"::2/128", "", false},

		{"::fffe:ffff:ffff/128", "", false}, {"::ffff:0.0.0.0/128", mapped, true}, {"::ffff:255.255.255.255/128", mapped, true},
		{"::1:0:0:0/128", "", false}, {"::ffff:0:0/96", mapped, true}, {"::ffff:198.51.100.0/120", mapped, true},
		{"::fffe:0:0/95", mapped, false},

		{"fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "", false}, {"fe80::/128", linkLocal6, true},
		{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", linkLocal6, true}, {"fec0::/128", "", false},
		{"fe80::/10", linkLocal6, true}, {"fe80::/64", linkLocal6, true}, {"fe80::/9", linkLocal6, false},
		{"fe00::/7", linkLocal6, false}, {"8000::/1", linkLocal6, false},

		{"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "", false}, {"ff00::/128", multicast6, true},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", multicast6, true}, {"ff00::/8", multicast6, true},
		{"ff02::/16", multicast6, true},

		{"192.0.2.0/24", "", false}, {"198.51.100.7/32", "", false}, {"3fff::/20", "", false}, {"2001:db8::/32", "", false},
	} {
		reason, whole := Unroutable(netip.MustParsePrefix(c.prefix))
		if reason != c.class || whole != c.whole {
			t.Errorf("%s: %q whole %v, want %q whole %v", c.prefix, reason, whole, c.class, c.whole)
		}
	}
}
