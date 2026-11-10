// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// a gateway announcing its site's range and exempting it under the site's
// interface, whose speaker holds another router's offer for exactly that range,
// names the conflict with the offer's router-id beside the carved one of the
// peer's more specific prefix, and carves, owns and passes the same sources as
// before the offer came
func TestBorderSetsNameAnExactCopyOfTheGatewaysRangeAndCarveNothingMore(t *testing.T) {
	site := netip.MustParsePrefix("203.0.113.0/25")
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Overlay = overlayOf("203.0.113.0/24")
		cfg.Cap.Route = &babel.Routes{Announce: announce(site.String())}
		cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf(site.String())}}}
	})
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange)}
	peer := sinkPeer(t, "example/gateway:1@0")
	defer c.speaker.AddPeer(peer, identity.MustParse("example/gateway:1")).Close()
	update := func(prefix netip.Prefix) babel.RawTLV {
		return babel.EncodeUpdate(babel.Update{AE: babel.AEIPv4ViaIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(), Seqno: 1, Metric: 20, Interval: 1000})
	}
	c.speaker.Receive(peer, babelPacket(
		babel.EncodeHello(babel.Hello{Seqno: 1, Interval: 1000}),
		babel.EncodeIHU(babel.IHU{RxCost: 96, Interval: 1000}),
		babel.EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		update(netip.MustParsePrefix("203.0.113.96/28")),
	))
	before := c.BorderRuntime().Sets(c.config().Border())
	if len(before.Conflicts) != 1 {
		t.Fatalf("before the copy the filter reports the conflicts %+v, want the more specific prefix's alone, so this proves nothing", before.Conflicts)
	}
	c.speaker.Receive(peer, babelPacket(babel.EncodeRouterID([8]byte{8, 7, 6, 5, 4, 3, 2, 1}), update(site)))
	after := c.BorderRuntime().Sets(c.config().Border())
	if !slices.Equal(after.Carved, before.Carved) || !slices.Equal(after.Owned, before.Owned) || !slices.Equal(after.None, before.None) || !slices.Equal(after.CarveOuts, before.CarveOuts) {
		t.Errorf("with the copy the filter carves %v, owns %v, passes %v and carves out %v, want %v, %v, %v and %v as before", after.Carved, after.Owned, after.None, after.CarveOuts, before.Carved, before.Owned, before.None, before.CarveOuts)
	}
	want := append(slices.Clone(before.Conflicts), egress.ExemptConflict{
		Exemption: egress.Exemption{Interface: "eth1", Prefix: site}, Prefix: site, RouterID: "0807060504030201", Own: true,
	})
	if !slices.Equal(after.Conflicts, want) {
		t.Errorf("with the copy the filter reports the conflicts %+v, want %+v", after.Conflicts, want)
	}
}
