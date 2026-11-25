// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Every request of the new switch is checked byte for byte against its fixed
// digest. The unchanged requests of the original two chains retain their
// readable byte golden. The root test checks the nft listing independently.
func TestFallbackBatchKeepsItsBytes(t *testing.T) {
	var old, all bytes.Buffer
	write := func(name string, requests []nftables.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fmt.Fprintln(&old, name)
		fmt.Fprintln(&all, name)
		pastOutput := false
		for _, request := range requests {
			fmt.Fprintf(&all, "  kind %#06x flags %#06x body %x\n", request.Kind, request.Flags, request.Body)
			// The original golden holds the first two chains and seven sets.
			// Routed's first anonymous set precedes its first rule, so the
			// boundary is the counted drop ending output, not routed's rule.
			if pastOutput || bytes.Contains(request.Body, []byte("routed\x00")) ||
				bytes.Contains(request.Body, []byte("from4\x00")) || bytes.Contains(request.Body, []byte("from6\x00")) {
				continue
			}
			fmt.Fprintf(&old, "  kind %#06x flags %#06x body %x\n", request.Kind, request.Flags, request.Body)
			if request.Kind == nftables.Command(unix.NFT_MSG_NEWRULE) &&
				bytes.Contains(request.Body, []byte("output\x00")) && bytes.Contains(request.Body, []byte("counter drop\x00")) {
				pastOutput = true
			}
		}
	}
	whole, err := fallbackBatch(fallbackSample, nftables.Contents{}, nil)
	write("the switch of every line", whole, err)
	requests, err := fallbackBatch(fallbackSets{tun: "ranetsw0"}, nftables.Contents{}, nil)
	write("the switch with nothing forwarded, no LAN, no own prefix and no service", requests, err)
	stale := nftables.Contents{Chains: fallbackChains[:1], Sets: fallbackNamed[:1]}
	remade, err := fallbackBatch(fallbackSample, stale, nil)
	write("the switch remaking its first chain and its first set", remade, err)
	goldentest.Check(t, "./internal/kernel", "testdata/fallback.golden", old.Bytes())
	if got := fmt.Sprintf("%x", sha256.Sum256(all.Bytes())); got != "41649a8b27d7da2f4687de01a1e5e62c86420a6af3cf57a52b42ea9d223b9452" {
		t.Errorf("the complete switch's netlink requests have SHA-256 %s, want the byte golden", got)
	}
	deletions := slices.DeleteFunc(slices.Clone(remade), func(r nftables.Request) bool {
		return r.Kind != nftables.Command(unix.NFT_MSG_DELCHAIN) && r.Kind != nftables.Command(unix.NFT_MSG_DELSET) && r.Kind != nftables.Command(unix.NFT_MSG_DELTABLE)
	})
	want := []nftables.Request{stale.Chains[0].Delete(unix.NFPROTO_INET), stale.Sets[0].Delete(unix.NFPROTO_INET)}
	if len(remade) != len(whole)+2 || !reflect.DeepEqual(deletions, want) {
		t.Errorf("the switch remade sends %d requests deleting %+v, want the %d of the whole switch and the deletions %+v", len(remade), deletions, len(whole), want)
	}
}

// A switch listing a hundred services of each protocol is written in one
// transaction, each line's text within the 128 bytes of the comment the
// readback knows it by
func TestFallbackBatchTakesAnyNumberOfServices(t *testing.T) {
	many := fallbackSample
	many.tcp, many.udp = nil, nil
	for port := uint16(1000); port < 1200; port += 2 {
		many.tcp = append(many.tcp, Service{Protocol: "tcp", First: port, Last: port})
		many.udp = append(many.udp, Service{Protocol: "udp", First: port, Last: port})
	}
	if _, err := fallbackBatch(many, nftables.Contents{}, nil); err != nil {
		t.Fatalf("the table of a hundred services of each protocol: %v", err)
	}
}

// A pass over a table holding own4, own6, tcp_ports and udp_ports, the sets an
// earlier switch wrote, sends the transaction it sends over a table without
// them with their deletions last, after the flush of the chains whose lines
// read them, so the commit that writes the switch's sets deletes them, and one
// another writer's rule reads stays
func TestFallbackBatchDeletesTheEarlierSetsInItsTransaction(t *testing.T) {
	without, err := fallbackBatch(fallbackSample, nftables.Contents{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leftovers := []nftables.Retired{{Kind: "set", Name: "own4"}, {Kind: "set", Name: "own6"}, {Kind: "set", Name: "tcp_ports", HeldBy: "chain other"}, {Kind: "set", Name: "udp_ports"}}
	with, err := fallbackBatch(fallbackSample, nftables.Contents{}, leftovers)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(without)
	for _, name := range []string{"own4", "own6", "udp_ports"} {
		want = append(want, nftables.Set{Table: nftables.Table, Name: name}.Delete(unix.NFPROTO_INET))
	}
	if !reflect.DeepEqual(with, want) {
		t.Errorf("the batch over the earlier sets sends %d requests, want the %d of the batch without them and the three free sets' deletions last", len(with), len(without))
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
		{"tcpports", nftables.Interval{First: []byte{0, 22}, Last: []byte{0, 22}}, "22"},
		{"udpports", nftables.Interval{First: []byte{0xea, 0x60}, Last: []byte{0xee, 0x48}}, "60000-61000"},
	} {
		if got := named(c.set).Text(c.interval); got != c.want {
			t.Errorf("%s's element %x-%x reads %q, want %q", c.set, c.interval.First, c.interval.Last, got, c.want)
		}
	}
}
