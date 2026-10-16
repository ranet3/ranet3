// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"maps"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// a startup refuses an organization or node the trust document does not name, by that name, and takes the ones it does
func TestStartupRefusesExtraCostNamingWhatTheTrustDocumentLacks(t *testing.T) {
	for name, test := range map[string]struct {
		extra babel.ExtraCost
		names string
	}{
		"an unknown organization":        {babel.ExtraCost{Org: map[string]uint16{"nobody": 1}}, `org "nobody"`},
		"an unknown node":                {babel.ExtraCost{Node: map[string]uint16{"example/nobody": 1}}, "node example/nobody"},
		"a node of another organization": {babel.ExtraCost{Node: map[string]uint16{"other/gateway": 1}}, "node other/gateway"},
		"known names":                    {babel.ExtraCost{Foreign: 9, Org: map[string]uint16{"example": 1}, Node: map[string]uint16{"example/gateway": 2}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, privateKey, reg := runtimeFixture(t)
			cfg.Cap.Babel = &babel.Config{Cost: babel.CostOptions{Extra: test.extra}}
			err := validateRuntimeConfig(cfg, privateKey, trust(t, reg))
			switch {
			case test.names == "" && err != nil:
				t.Errorf("names the trust document holds were refused: %v", err)
			case test.names != "" && (err == nil || !strings.Contains(err.Error(), test.names)):
				t.Errorf("the startup was answered with %v, want a refusal naming %s", err, test.names)
			}
		})
	}
}

// a reload naming a node the trust document does not hold is refused and changes nothing
// one changing an amount is applied: the running neighbor is charged the new amount and the reload reports cap.babel
// one changing only foreign, the key a deployment sets most, charges every neighbor again and reports cap.babel as well
func TestReloadAppliesExtraCostAndRefusesAnUnknownName(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	defer c.speaker.AddPeer(sinkPeer(t, "example/gateway:1@0"), identity.MustParse("example/gateway:1")).Close()

	old := c.config()
	unknown := *old
	unknown.Cap.Babel = &babel.Config{Cost: babel.CostOptions{Extra: babel.ExtraCost{Node: map[string]uint16{"example/nobody": 300}}}}
	joinedAndAnnounced(t, c, &unknown)
	writeConfig(t, path, &unknown)
	if err := c.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), "example/nobody") {
		t.Fatalf("the reload was answered with %v, want a refusal naming example/nobody", err)
	}
	changedNothing(t, c, old, bus)

	charged := *old
	charged.Cap.Babel = &babel.Config{Cost: babel.CostOptions{Extra: babel.ExtraCost{Node: map[string]uint16{"example/gateway": 300}}}}
	writeConfig(t, path, &charged)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload charging a known node was refused: %v", err)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.babel" {
		t.Errorf("the reload was recorded as applying %q, want cap.babel", got)
	}
	if got := c.Neighbors(); len(got) != 1 || got[0].Extra != 300 {
		t.Errorf("the neighbor reads as %+v after the reload, want an extra of 300", got)
	}

	defer c.speaker.AddPeer(sinkPeer(t, "other/router:1@0"), identity.MustParse("other/router:1")).Close()
	foreign := charged
	foreign.Cap.Babel = &babel.Config{Cost: babel.CostOptions{Extra: babel.ExtraCost{Foreign: 40, Node: map[string]uint16{"example/gateway": 300}}}}
	writeConfig(t, path, &foreign)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload changing only foreign was refused: %v", err)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.babel" {
		t.Errorf("the reload changing only foreign was recorded as applying %q, want cap.babel", got)
	}
	want := map[string]uint16{"example/gateway:1@0": 300, "other/router:1@0": 40}
	got := map[string]uint16{}
	for _, neighbor := range c.Neighbors() {
		got[neighbor.Peer] = neighbor.Extra
	}
	if !maps.Equal(got, want) {
		t.Errorf("the neighbors are charged %v after a reload changing only foreign, want %v", got, want)
	}
}

// the speaker charges the identity each session's IKE_AUTH proved, against this node's own organization
// a node charging every other organization sees the amount on its neighbor of another one and none on its neighbor of its own, and the charged neighbor reads it in the IHU
func TestSessionHandsTheSpeakerThePeerIdentity(t *testing.T) {
	foreign := &listenNode{org: "bravo", name: "b", listen: true}
	own := &listenNode{org: "alpha", name: "c", listen: true}
	dialing := &listenNode{org: "alpha", name: "a", dials: []*listenNode{foreign, own}, foreign: 700}
	listenMesh(t, foreign, own, dialing)
	defer runListen(t, foreign, own, dialing)()
	neighbor := func(node, peer *listenNode) (control.Neighbor, bool) {
		for _, got := range node.client.Neighbors() {
			if strings.HasPrefix(got.Peer, peer.org+"/"+peer.name+":") && got.ReportedCost != nil {
				return got, true
			}
		}
		return control.Neighbor{}, false
	}
	waitFor(t, convergeBudget, "each pair to read the other's IHU", func() bool {
		_, toForeign := neighbor(dialing, foreign)
		_, toOwn := neighbor(dialing, own)
		_, back := neighbor(foreign, dialing)
		return toForeign && toOwn && back
	})
	waitFor(t, convergeBudget, "the dialer to charge its foreign neighbor and that neighbor to read it", func() bool {
		charged, _ := neighbor(dialing, foreign)
		back, _ := neighbor(foreign, dialing)
		return charged.Extra == 700 && *back.ReportedCost >= 700
	})
	if got, _ := neighbor(dialing, own); got.Extra != 0 {
		t.Errorf("the dialer charges its neighbor of its own organization %d, want nothing", got.Extra)
	}
	if got, _ := neighbor(foreign, dialing); got.Extra != 0 {
		t.Errorf("the answering node charges %d, where it writes no cost.extra", got.Extra)
	}
}
