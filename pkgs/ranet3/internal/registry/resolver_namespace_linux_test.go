// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package registry

import (
	"context"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/dnstest"
	"ranet3.com/pkgs/ranet3/schema"
)

// handoverNameservers are a nameserver of each family on lo, the IPv6 one also
// with a zone, as resolv.conf may write it
var handoverNameservers = []string{"127.0.0.53", "::1", "::1%lo"}

// handoverLookup bounds one lookup, past the 3 nameservers' timeouts of
// dnstest.QueryTimeout each
const handoverLookup = 5 * time.Second

// The query ResolveRemote sends to each nameserver resolv.conf lists carries no
// mark where the overlay it is handed holds that nameserver, and the underlay's
// mark where it does not or there is none. Go's resolver reads the resolv.conf
// this test binds in its own mount namespace, so the query goes where the
// daemon's would. It runs as root under unshare -rmn.
func TestResolverQueryFollowsTheOverlayResolveRemoteIsHanded(t *testing.T) {
	nameserver := dnstest.Start(t, handoverNameservers...)
	name := "gateway.example."
	endpoint := Endpoint{SerialNumber: "1", AddressFamily: "ip4", Address: &name, Port: 13000}
	for _, test := range []struct {
		name    string
		overlay []schema.Prefix
		want    uint32
	}{
		{"inside the overlay", overlayOf("127.0.0.0/8", "::1/128"), 0},
		{"with no overlay", nil, schema.UnderlayMark},
		{"outside the overlay", overlayOf("192.0.2.0/24", "3fff::/20"), schema.UnderlayMark},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), handoverLookup)
		_, err := endpoint.ResolveRemote(ctx, test.overlay)
		cancel()
		queries := nameserver.Take()
		if len(queries) != len(handoverNameservers) {
			t.Errorf("%s: %d queries reached the %d nameservers, want 1 each: %v, lookup %v", test.name, len(queries), len(handoverNameservers), queries, err)
		}
		for _, query := range queries {
			if query.Mark != test.want {
				t.Errorf("%s: the query to %s carried mark %#x, want %#x", test.name, query.To, query.Mark, test.want)
			}
		}
	}
}
