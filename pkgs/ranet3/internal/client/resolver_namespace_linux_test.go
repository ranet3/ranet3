// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/dnstest"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// handoverDials bounds the test's six dials, each a lookup past the 3
// nameservers' timeouts of dnstest.QueryTimeout
const handoverDials = 30 * time.Second

// A dial resolving its peer's endpoint name, whether it names the endpoint or
// the node, hands the query the overlay of the config in force at that dial: a
// query to a nameserver inside it carries no mark, and once the config in force
// has no cap.border, as a restart without it leaves it, the next dial's query
// carries the underlay's. Go's resolver reads the resolv.conf this test binds
// in its own mount namespace, a nameserver of each family on lo, the IPv6 one
// also with a zone. It runs as root under unshare -rmn.
func TestEndpointQueryFollowsTheOverlayInForceAcrossReloads(t *testing.T) {
	nameservers := []string{"127.0.0.53", "::1", "::1%lo"}
	nameserver := dnstest.Start(t, nameservers...)
	cfg, privateKey, reg := runtimeFixture(t)
	name := "gateway.example."
	reg[0].Nodes[1].Endpoints[0].Address = &name
	inside := *cfg
	inside.Cap.Border = &egress.Border{Overlay: []schema.Prefix{
		schema.PrefixFrom(netip.MustParsePrefix("127.0.0.0/8")),
		schema.PrefixFrom(netip.MustParsePrefix("::1/128")),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), handoverDials)
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, sessions: newSessionSet(), events: events.New()}
	c.cfg.Store(&inside)
	c.storeIndex(trust(t, reg))
	// the endpoint and its node, which resolveEndpoint resolves on two paths
	for _, peer := range []identity.Identity{inside.Dial.To[0], inside.Dial.To[0].Node()} {
		d := dialTo(t, &inside, peer)
		// each step stores its config as the one in force, the one without cap.border as a restart leaves it, since a reload refuses dropping the block
		for _, step := range []struct {
			name string
			cfg  *config.Config
			want uint32
		}{
			{"with the overlay in force", &inside, 0},
			{"after a reload dropping cap.border", cfg, schema.UnderlayMark},
			{"after a reload naming the overlay again", &inside, 0},
		} {
			c.cfg.Store(step.cfg)
			err := c.connectPeer(ctx, d)
			queries := nameserver.Take()
			if len(queries) != len(nameservers) {
				t.Errorf("dialing %s %s: %d queries reached the %d nameservers, want 1 each: %v, dial %v", peer, step.name, len(queries), len(nameservers), queries, err)
			}
			for _, query := range queries {
				if query.Mark != step.want {
					t.Errorf("dialing %s %s: the query to %s carried mark %#x, want %#x", peer, step.name, query.To, query.Mark, step.want)
				}
			}
		}
	}
}
