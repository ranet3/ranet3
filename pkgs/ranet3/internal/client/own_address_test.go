// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// a node started on a table hands its mesh the addresses cap.table assigns as those its tun holds, so a read to one goes back into the tun
// and a reload that moves an address hands the mesh the new one, a read to the old one then dropped as looped, a prefix cap.route announces still holding it
func TestNodeHandsTheMeshTheAddressesItsTunHolds(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	dir := t.TempDir()
	cfg.Link.Port = freeUDPPort(t)
	cfg.Auth.Key = filepath.Join(dir, "key.pem")
	cfg.Auth.Trust = filepath.Join(dir, "registry.json")
	writeKey(t, cfg.Auth.Key, privateKey)
	writeRegistry(t, cfg.Auth.Trust, reg)
	cfg.Cap.Table = tableOf("192.0.2.5/32", "3fff:1::5/128")
	cfg.Cap.Route = &babel.Routes{Announce: announce("192.0.2.0/24", "3fff:1::/48")}
	c, err := newClient(cfg, privateKey, trust(t, reg), netstack.NewRoutesOnly(), nil, events.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetReconciler(Reconciler{Table: (&reconcilerStandIn{}).setTable})
	c.Republish()
	// the decision and its reason for a read from address to itself
	decides := func(address string) string {
		own := netip.MustParseAddr(address)
		e := c.Mesh.ExplainRead(routePacket(own, own))
		return strings.TrimSpace(e.Decision.String() + " " + e.Reason)
	}
	for _, address := range []string{"192.0.2.5", "3fff:1::5"} {
		if got := decides(address); got != "deliver" {
			t.Errorf("a node started assigning %s decides %q for a read to it, want deliver", address, got)
		}
	}

	path := filepath.Join(dir, "config.yaml")
	next := *c.config()
	next.Cap.Table = tableOf("192.0.2.6/32", "3fff:1::6/128")
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload was refused: %v", err)
	}
	c.Republish()
	for address, want := range map[string]string{
		"192.0.2.6": "deliver", "3fff:1::6": "deliver",
		"192.0.2.5": "drop looped", "3fff:1::5": "drop looped",
	} {
		if got := decides(address); got != want {
			t.Errorf("after a reload moving the table from 192.0.2.5 and 3fff:1::5 to 192.0.2.6 and 3fff:1::6, a read to %s decides %q, want %q", address, got, want)
		}
	}
}
