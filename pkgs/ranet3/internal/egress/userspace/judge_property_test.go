// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// judgeCase is a packet a session may hand the exit, described rather than
// written, so the model below reads the description and never the bytes
type judgeCase struct {
	ipv4     bool
	ttl      byte
	protocol byte
	// destination is one of judgeDestinations
	destination int
	// fragment is 0 for a whole packet, 1 for a first fragment and 2 for a
	// later one
	fragment int
	// extensions is the IPv6 headers ahead of the upper layer or the fragment
	// header, each 0, 60 or 43 with segments left of segmentsLeft
	extensions   []byte
	segmentsLeft byte
	// afterFragment is an IPv6 extension header the fragmentable part opens
	// with, 0 for none
	afterFragment byte
	// damage is 0 for none, 1 for a bad IPv4 header checksum and 2 for a
	// packet cut short of what its header claims
	damage int
}

// judgeDestinations are the destinations a case draws from, by family: a
// server, an address the host holds, the host's loopback, a group and a
// link-local address
var judgeDestinations = [2][5]netip.Addr{
	{server4, netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("224.0.0.9"), netip.MustParseAddr("169.254.1.1")},
	{server6, netip.MustParseAddr("2001:db8:2::1"), netip.IPv6Loopback(), netip.MustParseAddr("ff02::9"), netip.MustParseAddr("fe80::1")},
}

// heldByHost is the address of each family the cases' host holds
func heldByHost(address netip.Addr) bool {
	return address == judgeDestinations[0][1] || address == judgeDestinations[1][1]
}

// bytes writes the case as a packet from a leaf
func (c judgeCase) bytes() []byte {
	family := 1
	if c.ipv4 {
		family = 0
	}
	destination := judgeDestinations[family][c.destination]
	upper := make([]byte, 24)
	var raw []byte
	if c.ipv4 {
		fragment := uint16(0)
		switch c.fragment {
		case 1:
			fragment = 1 << 13
		case 2:
			fragment = 3
		}
		raw = ip4(leaf4, destination, c.protocol, 7, fragment, c.ttl, upper)
		if c.damage == 1 {
			raw[10] ^= 0xff
		}
	} else {
		var chain []byte
		next := c.protocol
		if c.fragment != 0 {
			body := upper
			if c.afterFragment != 0 {
				body = append(extension(c.afterFragment, c.protocol, 0), upper...)
				next = c.afterFragment
			}
			offset := uint16(0)
			if c.fragment == 2 {
				offset = 24
			}
			header := make([]byte, 8)
			header[0] = next
			binary.BigEndian.PutUint16(header[2:4], offset|1)
			upper, next = append(header, body...), ipv6Fragment
		}
		for i := len(c.extensions) - 1; i >= 0; i-- {
			chain = append(extension(c.extensions[i], next, c.segmentsLeft), chain...)
			next = c.extensions[i]
		}
		raw = ip6(leaf6, destination, next, c.ttl, append(chain, upper...))
	}
	if c.damage == 2 {
		raw = raw[:len(raw)-3]
	}
	return raw
}

// extension is an 8 byte IPv6 extension header of kind naming next, a routing
// header carrying segmentsLeft
func extension(kind, next, segmentsLeft byte) []byte {
	header := make([]byte, 8)
	header[0] = next
	if kind == 43 {
		header[3] = segmentsLeft
	}
	return header
}

// want is the judgment the case asks for, from its description: a damaged
// packet dropped, then a TTL of 1 or less answered expired, then a protocol
// other than TCP, UDP and the family's ICMP answered prohibited, where an
// IPv6 routing header with segments left and an extension header opening a
// fragment's fragmentable part count as such a protocol, then a destination
// the host holds or no server may hold answered prohibited
func (c judgeCase) want() judgment {
	if c.damage != 0 {
		return judgment{act: drop, reason: reasonMalformed}
	}
	if c.ttl <= 1 {
		return judgment{act: answer, kind: netstack.ExitExpired, reason: reasonExpired}
	}
	protocol := c.protocol
	if !c.ipv4 {
		for _, kind := range c.extensions {
			if kind == 43 && c.segmentsLeft != 0 {
				protocol = 43
			}
		}
		if protocol != 43 && c.fragment != 0 && c.afterFragment != 0 {
			protocol = c.afterFragment
		}
	}
	icmp := byte(58)
	if c.ipv4 {
		icmp = 1
	}
	if protocol != 6 && protocol != 17 && protocol != icmp {
		return judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonProtocol}
	}
	if c.destination != 0 {
		return judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonDestination}
	}
	return judgment{act: deliver}
}

func (c judgeCase) String() string {
	return fmt.Sprintf("ipv4 %t ttl %d protocol %d destination %d fragment %d extensions %v segments left %d after fragment %d damage %d",
		c.ipv4, c.ttl, c.protocol, c.destination, c.fragment, c.extensions, c.segmentsLeft, c.afterFragment, c.damage)
}

// for any packet a session hands the exit, of either family, whole or any
// fragment, behind any chain of IPv6 extension headers, damaged or not, the
// lane's judgment is the model's: so a protocol the exit does not carry never
// reaches the stack on any fragment, nor a packet toward an address the host
// holds, which is the exit's refusal of the host's own services
func TestJudgmentIsTheModels(t *testing.T) {
	check := func(tb testing.TB, c judgeCase) {
		tb.Helper()
		if got, want := judge(c.bytes(), heldByHost), c.want(); got != want {
			tb.Fatalf("%s: judged %+v, want %+v", c, got, want)
		}
	}
	for _, ipv4 := range []bool{true, false} {
		for _, protocol := range []byte{1, 6, 17, 58, 132, protoUncarried} {
			for destination := range len(judgeDestinations[0]) {
				for fragment := range 3 {
					for _, ttl := range []byte{0, 1, 2, 64} {
						check(t, judgeCase{ipv4: ipv4, ttl: ttl, protocol: protocol, destination: destination, fragment: fragment})
					}
				}
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		c := judgeCase{
			ipv4:        hegel.Draw(ht, hegel.Booleans()),
			ttl:         hegel.Draw(ht, pbt.Spanning[byte](0, 255)),
			protocol:    hegel.Draw(ht, pbt.Spanning[byte](0, 255)),
			destination: hegel.Draw(ht, hegel.Integers(0, len(judgeDestinations[0])-1)),
			fragment:    hegel.Draw(ht, hegel.Integers(0, 2)),
			damage:      hegel.Draw(ht, hegel.Integers(0, 2)),
		}
		if !c.ipv4 {
			if c.damage == 1 {
				c.damage = 0
			}
			if c.protocol == 0 || c.protocol == 43 || c.protocol == 44 || c.protocol == 60 {
				c.protocol = 17
			}
			for range hegel.Draw(ht, hegel.Integers(0, 3)) {
				c.extensions = append(c.extensions, []byte{0, 43, 60}[hegel.Draw(ht, hegel.Integers(0, 2))])
			}
			c.segmentsLeft = hegel.Draw(ht, pbt.Spanning[byte](0, 3))
			if c.fragment != 0 {
				c.afterFragment = []byte{0, 0, 60}[hegel.Draw(ht, hegel.Integers(0, 2))]
			}
		}
		check(ht, c)
	})
}
