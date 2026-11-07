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

// hostHopLimit has the host's default hop limit read as hopLimit, or fail with err, until the test ends
func hostHopLimit(t *testing.T, hopLimit uint8, err error) {
	previous := defaultHopLimit
	t.Cleanup(func() { defaultHopLimit = previous })
	defaultHopLimit = func() (uint8, error) { return hopLimit, err }
}

// limitedExit is an exit that builds packets of its own, holding the TTL and hop limit it was last handed
type limitedExit struct {
	fakeExit
	ttl, hopLimit uint8
}

func (e *limitedExit) SetHopLimits(ttl, hopLimit uint8) { e.ttl, e.hopLimit = ttl, hopLimit }

func (e *limitedExit) HopLimits() (uint8, uint8) { return e.ttl, e.hopLimit }

// an exit that builds packets of its own takes the host's default TTL and hop limit when the node is handed it
// a hop limit that cannot be read leaves the exit its own, and is recorded
func TestHandedExitTakesTheHostsTTLAndHopLimit(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	for _, c := range []struct {
		name          string
		read          error
		ttl, hopLimit uint8
		records       int
	}{
		{"read", nil, 128, 200, 0},
		{"refused", errors.New("net.ipv6.conf.all.hop_limit: refused"), 128, 64, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			hostTTL(t, 128, nil)
			hostHopLimit(t, 200, c.read)
			cfg.Link.Port = freeUDPPort(t)
			bus := events.New()
			node, err := newClient(cfg, privateKey, trust(t, reg), netstack.NewRoutesOnly(), nil, bus)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { node.Close() })
			exit := &limitedExit{ttl: 64, hopLimit: 64}
			node.SetExit(exit)
			if exit.ttl != c.ttl || exit.hopLimit != c.hopLimit {
				t.Errorf("the exit holds the TTL %d and the hop limit %d, want %d and %d", exit.ttl, exit.hopLimit, c.ttl, c.hopLimit)
			}
			if failed := recorded(bus, "daemon.ttl"); len(failed) != c.records || c.records == 1 && (failed[0].Attrs["hop_limit"] != "64" || failed[0].Attrs["err"] != c.read.Error()) {
				t.Errorf("the reads were recorded as %+v", failed)
			}
		})
	}
}

// a reload hands an exit that builds packets of its own the host's default TTL and hop limit again
// a hop limit that cannot be read keeps the one the exit holds and is recorded, and a TTL that cannot be read keeps the mesh's
func TestReloadHandsTheExitTheHostsTTLAndHopLimit(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(old *config.Config) {
		old.Cap.Table = tableOf("192.0.2.5/32")
		old.Cap.Route = &babel.Routes{Announce: announce("192.0.2.0/24")}
	})
	exit := &limitedExit{ttl: 64, hopLimit: 64}
	c.SetExit(exit)
	next := *c.config()
	for _, step := range []struct {
		name          string
		table         string
		ttl           uint8
		ttlErr        error
		hopLimit      uint8
		hopErr        error
		want          [2]uint8
		hopLimitsKept int
	}{
		{"both read", "192.0.2.6/32", 255, nil, 100, nil, [2]uint8{255, 100}, 0},
		{"hop limit refused", "192.0.2.7/32", 255, nil, 1, errors.New("net.ipv6.conf.all.hop_limit: refused"), [2]uint8{255, 100}, 1},
		{"ttl refused", "192.0.2.8/32", 1, errors.New("net.ipv4.ip_default_ttl: refused"), 30, nil, [2]uint8{255, 30}, 1},
	} {
		hostTTL(t, step.ttl, step.ttlErr)
		hostHopLimit(t, step.hopLimit, step.hopErr)
		next.Cap.Table = tableOf(step.table)
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err != nil {
			t.Fatalf("%s: the reload was refused: %v", step.name, err)
		}
		if got := [2]uint8{exit.ttl, exit.hopLimit}; got != step.want {
			t.Errorf("%s: the exit holds the TTL and hop limit %v, want %v", step.name, got, step.want)
		}
		var kept []string
		for _, record := range recorded(bus, "daemon.ttl") {
			if hopLimit, ok := record.Attrs["hop_limit"]; ok {
				kept = append(kept, hopLimit+" "+record.Attrs["err"])
			}
		}
		if len(kept) != step.hopLimitsKept || step.hopErr != nil && kept[len(kept)-1] != "100 "+step.hopErr.Error() {
			t.Errorf("%s: the failed hop limit reads were recorded as %v", step.name, kept)
		}
	}
}
