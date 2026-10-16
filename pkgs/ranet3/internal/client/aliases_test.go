// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// a reload names each auth.aliases table it changes, an entry naming another endpoint under the same key included
// an empty table and none are one table, which a file writing a table header and no entry reads as
func TestReloadNamesEachAliasTableItChanges(t *testing.T) {
	gateway, relay := identity.MustParse("example/gateway:1"), identity.MustParse("example/relay:1")
	remote := func(endpoint identity.Identity) ike.RemoteAliases {
		return ike.RemoteAliases{FQDN: map[string]identity.Identity{"gw.example.net": endpoint}}
	}
	local := map[string]ike.LocalAlias{"example/gateway": {FQDN: "laptop.example.net"}}
	empty := ike.Aliases{
		Remote: ike.RemoteAliases{IP: map[string]identity.Identity{}, FQDN: map[string]identity.Identity{}, Email: map[string]identity.Identity{}, KeyID: map[string]identity.Identity{}},
		Local:  map[string]ike.LocalAlias{},
	}
	for name, test := range map[string]struct {
		old, next ike.Aliases
		want      []string
	}{
		"a remote entry added":             {ike.Aliases{}, ike.Aliases{Remote: remote(gateway)}, []string{"auth.aliases.remote"}},
		"a local entry added":              {ike.Aliases{}, ike.Aliases{Local: local}, []string{"auth.aliases.local"}},
		"both tables removed":              {ike.Aliases{Remote: remote(gateway), Local: local}, ike.Aliases{}, []string{"auth.aliases.local", "auth.aliases.remote"}},
		"a key naming another endpoint":    {ike.Aliases{Remote: remote(gateway)}, ike.Aliases{Remote: remote(relay)}, []string{"auth.aliases.remote"}},
		"a local entry writing another ID": {ike.Aliases{Local: local}, ike.Aliases{Local: map[string]ike.LocalAlias{"example/gateway": {Email: "laptop@example.net"}}}, []string{"auth.aliases.local"}},
		"empty tables in place of none":    {ike.Aliases{}, empty, nil},
		"the same tables":                  {ike.Aliases{Remote: remote(gateway), Local: local}, ike.Aliases{Remote: remote(gateway), Local: maps.Clone(local)}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			old, next := &config.Config{Auth: config.Auth{Aliases: test.old}}, &config.Config{Auth: config.Auth{Aliases: test.next}}
			if got := changedCapabilities(old, next); !slices.Equal(got, test.want) {
				t.Errorf("the reload names %v, want %v", got, test.want)
			}
		})
	}
}

// a reload applies auth.aliases to the handshakes after it and keeps every session up
// a presents an FQDN to h, which h refuses until a reload of h names a by it, and a reload of a presenting another FQDN keeps the session and reaches a's next handshake
func TestReloadAppliesAuthAliasesToTheNextHandshake(t *testing.T) {
	a, h := &listenNode{name: "a", presents: "a.example.net"}, &listenNode{name: "h", listen: true}
	a.dials = []*listenNode{h}
	listenMesh(t, a, h)
	runListen(t, a, h)
	waitFor(t, convergeBudget, "h to refuse the FQDN a presents", func() bool {
		return slices.ContainsFunc(recorded(h.events, "ike.handshake.failed"), func(failed control.Event) bool {
			return strings.Contains(failed.Attrs["err"], fmt.Sprintf("fqdn ID %q names no endpoint auth.aliases.remote lists", a.presents))
		})
	})

	h.resolves = map[string]*listenNode{"a.example.net": a, "laptop.example.net": a}
	if err := h.client.ReloadFrom(writeListenPath(t, h, true)); err != nil {
		t.Fatalf("naming a by its FQDN was refused: %v", err)
	}
	if got := lastReload(t, h.events)["applied"]; got != "auth.aliases.remote" {
		t.Errorf("the reload was recorded as applying %q, want auth.aliases.remote", got)
	}
	if _, err := a.client.Redial(t.Context(), h.name, false); err != nil {
		t.Fatal(err)
	}
	heldAtBothEnds(t, a, h)
	for _, end := range []struct {
		node, peer *listenNode
		want       map[string]string
	}{
		{h, a, map[string]string{"type": "fqdn", "id": a.presents, "sent": "dn"}},
		{a, h, map[string]string{"type": "dn", "sent": "fqdn"}},
	} {
		resolved := sessionEvents(end.node, end.peer, "ike.id.resolved")
		if len(resolved) == 0 || !maps.Equal(resolved[len(resolved)-1].Attrs, end.want) {
			t.Errorf("%s recorded the IDs of its session with %s as %v, want %v last", end.node.name, end.peer.name, resolved, end.want)
		}
	}

	dialed, answered := held(a, h), held(h, a)
	a.presents = "laptop.example.net"
	if err := a.client.ReloadFrom(writeListenPath(t, a, false)); err != nil {
		t.Fatalf("presenting another FQDN was refused: %v", err)
	}
	if got := lastReload(t, a.events)["applied"]; got != "auth.aliases.local" {
		t.Errorf("the reload was recorded as applying %q, want auth.aliases.local", got)
	}
	if held(a, h) != dialed || held(h, a) != answered {
		t.Error("a reload of auth.aliases closed the session it was made with")
	}
	if got := slices.Concat(recorded(a.events, "ike.session.revoked"), recorded(h.events, "ike.session.revoked")); len(got) != 0 {
		t.Errorf("a reload of auth.aliases revoked %v", got)
	}
	if _, err := a.client.Redial(t.Context(), h.name, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "h to resolve the FQDN a presents after its reload", func() bool {
		resolved := sessionEvents(h, a, "ike.id.resolved")
		return len(resolved) > 0 && resolved[len(resolved)-1].Attrs["id"] == a.presents && held(h, a) != nil
	})
}

// an auth.aliases entry naming a node the trust document does not name, or an endpoint it does not list, refuses the start as a dial.to peer does
// the same tables naming what the document holds start
func TestStartupRefusesAnAliasTheTrustDocumentCannotBack(t *testing.T) {
	for name, test := range map[string]struct {
		aliases ike.Aliases
		want    string
	}{
		"a remote endpoint it does not list": {
			ike.Aliases{Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{"gw.example.net": identity.MustParse("example/gateway:9")}}},
			`config: auth.aliases.remote.fqdn "gw.example.net" names example/gateway:9, an endpoint the trust document does not list`},
		"a remote endpoint of a node it does not name": {
			ike.Aliases{Remote: ike.RemoteAliases{KeyID: map[string]identity.Identity{"0a1b": identity.MustParse("example/absent:1")}}},
			`config: auth.aliases.remote.keyid "0a1b" names example/absent:1, a node the trust document does not name`},
		"a local node it does not name": {
			ike.Aliases{Local: map[string]ike.LocalAlias{"example/absent": {FQDN: "laptop.example.net"}}},
			`config: auth.aliases.local "example/absent" names example/absent, a node the trust document does not name`},
		"a local endpoint it does not list": {
			ike.Aliases{Local: map[string]ike.LocalAlias{"example/gateway:9": {FQDN: "laptop.example.net"}}},
			`config: auth.aliases.local "example/gateway:9" names example/gateway:9, an endpoint the trust document does not list`},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, privateKey, reg := runtimeFixture(t)
			cfg.Auth.Aliases = test.aliases
			if err := validateRuntimeConfig(cfg, privateKey, trust(t, reg)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the start was answered %v, want a refusal naming %q", err, test.want)
			}
		})
	}
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Auth.Aliases = ike.Aliases{
		Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{
			"gw.example.net": identity.MustParse("example/gateway:1"), "laptop.example.net": identity.MustParse("example/local:0"),
		}},
		Local: map[string]ike.LocalAlias{"example/gateway": {FQDN: "laptop.example.net"}, "example/gateway:1": {Email: "ops@example.net"}},
	}
	if err := validateRuntimeConfig(cfg, privateKey, trust(t, reg)); err != nil {
		t.Errorf("aliases naming what the trust document holds stopped the start: %v", err)
	}
}

// a reload takes an auth.aliases entry naming whom the trust document does not hold and logs it, as it does a dial.to peer, or one stale entry would block every later reload
func TestReloadLogsAnAliasTheTrustDocumentCannotBack(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	written := &syncBuffer{}
	previous := log.Writer()
	log.SetOutput(written)
	t.Cleanup(func() { log.SetOutput(previous) })
	next := *c.config()
	next.Auth.Aliases = ike.Aliases{
		Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{"gw.example.net": identity.MustParse("example/gateway:9")}},
		Local:  map[string]ike.LocalAlias{"example/absent": {FQDN: "laptop.example.net"}},
	}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload naming whom the trust document does not hold was refused: %v", err)
	}
	if got := c.config().Auth.Aliases; !got.Remote.Equal(next.Auth.Aliases.Remote) || !maps.Equal(got.Local, next.Auth.Aliases.Local) {
		t.Errorf("the reload holds the aliases %+v, want %+v", got, next.Auth.Aliases)
	}
	if got := lastReload(t, bus)["applied"]; got != "auth.aliases.local,auth.aliases.remote" {
		t.Errorf("the reload was recorded as applying %q, want both alias tables", got)
	}
	for _, want := range []string{
		`reload: config: auth.aliases.remote.fqdn "gw.example.net" names example/gateway:9, an endpoint the trust document does not list, so no handshake can use it`,
		`reload: config: auth.aliases.local "example/absent" names example/absent, a node the trust document does not name, so no handshake can use it`,
	} {
		if got := written.count(want); got != 1 {
			t.Errorf("the reload logged %q %d times, want once", want, got)
		}
	}
}

// a reload refuses auth.aliases.local on a node with two endpoints in one family as it refuses any file it cannot load, and keeps the configuration in force
// a startup reads the file through the same config.Load, whose refusal internal/config's tests hold
func TestReloadRefusesALocalAliasOnTwoEndpointsInAFamily(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	before := c.config()
	next := *before
	next.Link.Endpoints = []config.Endpoint{{Serial: "0", Family: "ip4"}, {Serial: "1", Family: "ip4"}}
	next.Auth.Aliases = ike.Aliases{Local: map[string]ike.LocalAlias{"example/gateway": {FQDN: "laptop.example.net"}}}
	writeConfig(t, path, &next)
	want := "auth.aliases.local is refused on a node whose link.endpoints holds 2 endpoints of the ip4 family"
	if err := c.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("the reload was answered %v, want a refusal naming %q", err, want)
	}
	if c.config() != before {
		t.Error("the refused reload stored its configuration")
	}
}

// a node with an endpoint in each family answers a peer that asks in IDr for the alias it presents as its endpoint of the family the peer reached it in, and the session is held under that endpoint at both ends
// a names h's ip4 endpoint by the FQDN h presents it, which a asks for in IDr, and h answers with that FQDN
func TestDualStackNodeAnswersAnAliasAsItsEndpointOfTheFamilyReached(t *testing.T) {
	a, h := &listenNode{name: "a", presents: "a.example.net"}, &listenNode{name: "h", listen: true, dualStack: true, presents: "h.example.net"}
	a.dials, h.presentsTo = []*listenNode{h}, []*listenNode{a}
	a.resolves, h.resolves = map[string]*listenNode{"h.example.net": h}, map[string]*listenNode{"a.example.net": a}
	listenMesh(t, a, h)
	runListen(t, a, h)
	heldAtBothEnds(t, a, h)
	resolved := sessionEvents(h, a, "ike.id.resolved")
	if want := map[string]string{"type": "fqdn", "id": a.presents, "sent": "fqdn"}; len(resolved) == 0 || !maps.Equal(resolved[len(resolved)-1].Attrs, want) {
		t.Errorf("h recorded the IDs of its session with a as %v, want %v last", resolved, want)
	}
}
