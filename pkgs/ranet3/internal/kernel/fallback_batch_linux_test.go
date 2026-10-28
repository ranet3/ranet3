// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Every request the table's transaction sends, written whole, remade, with
// nothing forwarded, no LAN, no own prefix and no service, and withdrawn,
// keeps the kind, flags and body testdata/fallback.golden holds. The root
// test holds the same table beside nft's own listing of it.
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
	requests, err := fallbackBatch(fallbackSample, false)
	write("the table of every line", requests, err)
	requests, err = fallbackBatch(fallbackSample, true)
	write("the table remade", requests, err)
	requests, err = fallbackBatch(fallbackSets{tun: "ranetsw0"}, false)
	write("the table with nothing forwarded, no LAN, no own prefix and no service", requests, err)
	write("the withdrawal", []nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)}, nil)
	goldentest.Check(t, "./internal/kernel", "testdata/fallback.golden", out.Bytes())
}

// The debug read spells each element as nft lists it: a link's name, an
// address, a prefix, and a range that is no prefix as its two ends
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
	} {
		if got := intervalText(named(c.set), c.interval); got != c.want {
			t.Errorf("%s's element %x-%x reads %q, want %q", c.set, c.interval.First, c.interval.Last, got, c.want)
		}
	}
}
