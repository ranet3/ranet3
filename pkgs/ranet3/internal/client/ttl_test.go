// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// hostTTL has the host's default TTL read as ttl, or fail with err, until the test ends
func hostTTL(t *testing.T, ttl uint8, err error) {
	previous := defaultTTL
	t.Cleanup(func() { defaultTTL = previous })
	defaultTTL = func() (uint8, error) { return ttl, err }
}

// a node started on a host whose default TTL is not 64 hands the mesh the host's, which its ICMPv4 errors carry
func TestStartHandsTheMeshTheHostsDefaultTTL(t *testing.T) {
	hostTTL(t, 128, nil)
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Link.Port = freeUDPPort(t)
	mesh := netstack.NewRoutesOnly()
	c, err := newClient(cfg, privateKey, trust(t, reg), mesh, nil, events.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if ttl := mesh.AnswerTTL(); ttl != 128 {
		t.Errorf("a node started on a host whose default TTL is 128 answers with %d", ttl)
	}
}

// a start whose read of the host's default TTL fails ends with that read's error
func TestStartEndsWhereTheHostsDefaultTTLCannotBeRead(t *testing.T) {
	refused := errors.New("net.ipv4.ip_default_ttl: refused")
	hostTTL(t, 0, refused)
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Link.Port = freeUDPPort(t)
	if c, err := newClient(cfg, privateKey, trust(t, reg), netstack.NewRoutesOnly(), nil, events.New()); !errors.Is(err, refused) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("a start whose default TTL read failed ended with %v", err)
	}
}

// a reload reads the host's default TTL again and hands it to the mesh
// a read that fails keeps the TTL in use and is recorded, and the rest of the reload applies
func TestReloadTakesTheHostsDefaultTTL(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(old *config.Config) {
		old.Cap.Table = tableOf("192.0.2.5/32")
		old.Cap.Route = &babel.Routes{Announce: announce("192.0.2.0/24")}
	})
	next := *c.config()
	writeConfig(t, path, &next)
	hostTTL(t, 255, nil)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload was refused: %v", err)
	}
	if ttl := c.Mesh.AnswerTTL(); ttl != 255 {
		t.Fatalf("a reload on a host whose default TTL is 255 left the mesh answering with %d", ttl)
	}

	hostTTL(t, 0, errors.New("net.ipv4.ip_default_ttl: refused"))
	next.Cap.Table = tableOf("192.0.2.6/32")
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload whose default TTL read failed was refused: %v", err)
	}
	if ttl := c.Mesh.AnswerTTL(); ttl != 255 {
		t.Errorf("a reload whose default TTL read failed left the mesh answering with %d, want the 255 it had", ttl)
	}
	if sources := c.Mesh.AnswerSources(); sources.Router4 != netip.MustParseAddr("192.0.2.6") {
		t.Errorf("a reload whose default TTL read failed left the router-id at %v", sources.Router4)
	}
	if failed := recorded(bus, "daemon.ttl"); len(failed) != 1 || failed[0].Attrs["ttl"] != "255" || failed[0].Attrs["err"] != "net.ipv4.ip_default_ttl: refused" {
		t.Errorf("the failed read was recorded as %+v", failed)
	}
}
