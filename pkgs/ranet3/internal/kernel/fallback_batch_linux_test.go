// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Every request the table's transaction sends, written whole, with nothing
// forwarded, no LAN, no own prefix and no service, and withdrawn, keeps the
// kind, flags and body testdata/fallback.golden holds, and a remade table is
// the whole one behind the withdrawal's request. The root test holds the same
// table beside nft's own listing of it.
func TestFallbackBatchKeepsItsBytes(t *testing.T) {
	var out bytes.Buffer
	write := func(name string, requests []nftables.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fmt.Fprintf(&out, "%s\n", name)
		for _, request := range requests {
			fmt.Fprintf(&out, "  kind %#06x flags %#06x body %x\n", request.Kind, request.Flags, request.Body)
		}
	}
	whole, err := fallbackBatch(fallbackSample, false)
	write("the table of every line", whole, err)
	requests, err := fallbackBatch(fallbackSets{tun: "ranetsw0"}, false)
	write("the table with nothing forwarded, no LAN, no own prefix and no service", requests, err)
	withdrawal := nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)
	write("the withdrawal", []nftables.Request{withdrawal}, nil)
	goldentest.Check(t, "./internal/kernel", "testdata/fallback.golden", out.Bytes())
	remade, err := fallbackBatch(fallbackSample, true)
	if err != nil || !reflect.DeepEqual(remade, append([]nftables.Request{withdrawal}, whole...)) {
		t.Errorf("the table remade sends %+v (err %v), want the withdrawal's request and the whole table's", remade, err)
	}
}

// A table listing a hundred services of each protocol is written in one
// transaction, each line's text within the 128 bytes of the comment the
// readback knows it by
func TestFallbackBatchTakesAnyNumberOfServices(t *testing.T) {
	many := fallbackSample
	many.tcp, many.udp = nil, nil
	for port := uint16(1000); port < 1200; port += 2 {
		many.tcp = append(many.tcp, Service{Protocol: "tcp", First: port, Last: port})
		many.udp = append(many.udp, Service{Protocol: "udp", First: port, Last: port})
	}
	if _, err := fallbackBatch(many, false); err != nil {
		t.Fatalf("the table of a hundred services of each protocol: %v", err)
	}
}

// The debug read spells each element as nft lists it: a link's name, a port,
// a range of ports, an address, a prefix, and a range that is no prefix as its
// two ends
func TestIntervalTextSpellsEachElementAsNftDoes(t *testing.T) {
	named := func(name string) nftables.Set {
		return fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == name })]
	}
	address := func(text string) []byte { return netip.MustParseAddr(text).AsSlice() }
	for _, c := range []struct {
		set      string
		interval nftables.Interval
		want     string
	}{
		{"forwarded", nftables.Key(nftables.InterfaceName("docker0")), "docker0"},
		{"lan4", nftables.Interval{First: address("198.51.100.7"), Last: address("198.51.100.7")}, "198.51.100.7"},
		{"lan4", nftables.Interval{First: address("198.51.100.0"), Last: address("198.51.100.127")}, "198.51.100.0/25"},
		{"lan4", nftables.Interval{First: address("0.0.0.0"), Last: address("255.255.255.255")}, "0.0.0.0/0"},
		{"lan4", nftables.Interval{First: address("198.51.100.0"), Last: address("198.51.100.128")}, "198.51.100.0-198.51.100.128"},
		{"lan4", nftables.Interval{First: address("198.51.100.1"), Last: address("198.51.100.2")}, "198.51.100.1-198.51.100.2"},
		{"lan6", nftables.Interval{First: address("2001:db8:a::"), Last: address("2001:db8:a::ffff:ffff:ffff:ffff")}, "2001:db8:a::/64"},
		{"tcp_ports", nftables.Interval{First: []byte{0, 22}, Last: []byte{0, 22}}, "22"},
		{"udp_ports", nftables.Interval{First: []byte{0xea, 0x60}, Last: []byte{0xee, 0x48}}, "60000-61000"},
	} {
		if got := named(c.set).Text(c.interval); got != c.want {
			t.Errorf("%s's element %x-%x reads %q, want %q", c.set, c.interval.First, c.interval.Last, got, c.want)
		}
	}
}
