// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
)

func indexKey(t *testing.T) string {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestIndexSkipsKeylessAndUnidentifiedEndpoints(t *testing.T) {
	key := indexKey(t)
	unidentified, identified, dns := "198.51.100.1", "192.0.2.4", "a.example"
	a, b, c := "a", "b", "c"
	document := Document{Nodes: []Node{
		{Name: "example/idle", Endpoints: []Endpoint{{ID: &a, Family: "ip4", Address: &unidentified, Port: 443}}},
		{Name: "example/live", Key: &key, Endpoints: []Endpoint{
			{Family: "ip4", Address: &unidentified, Port: 443},
			{ID: &a, Family: "ip4", Address: &identified, Port: 443},
			{ID: &b, Family: "ip4", Address: &dns, Port: 443},
			{ID: &c, Family: "ip6", Port: 443},
		}},
	}}
	index, err := NewIndex(document)
	if err != nil {
		t.Fatal(err)
	}
	idle := identity.MustParse("example/idle")
	live := identity.MustParse("example/live")
	if _, err := index.Key(idle); err == nil || index.Targets(idle) != nil || index.Targets(idle.At(a)) != nil {
		t.Fatal("keyless record admitted or dialed")
	}
	if _, err := index.Key(live.At("missing")); err == nil || index.Targets(live.At("missing")) != nil {
		t.Fatal("unknown endpoint admitted or dialed")
	}
	expectedKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, who := range []identity.Identity{live, live.At(a), live.At(b), live.At(c)} {
		actual, err := index.Key(who)
		if err != nil || !bytes.Equal(actual, expectedKey) {
			t.Fatalf("key for %s: %x, %v", who, actual, err)
		}
	}
	if got := index.Targets(live); len(got) != 3 || got[0].ID != live.At(a) || got[1].ID != live.At(b) || got[2].ID != live.At(c) {
		t.Fatalf("wrong file-order targets %+v", got)
	}
	if targets := index.Targets(live.At(a)); len(targets) != 1 || targets[0].Address == nil || *targets[0].Address != identified {
		t.Fatalf("wrong endpoint target %+v", targets)
	}
	if got := index.Underlay(); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr(identified)}) {
		t.Fatalf("wrong literal underlay %v", got)
	}
	if got := index.Nodes(); !reflect.DeepEqual(got, []identity.Identity{idle, live}) {
		t.Fatalf("wrong node order %v", got)
	}
}

func TestIndexRejectsInvalidDocument(t *testing.T) {
	bad := Document{Nodes: []Node{{Name: "example/live", Endpoints: nil}}}
	if index, err := NewIndex(bad); err == nil || index != nil {
		t.Fatalf("indexed missing endpoints: %+v, %v", index, err)
	}
}
