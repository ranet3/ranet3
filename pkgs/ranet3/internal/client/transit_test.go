// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// relaySilence is how long a node that does not relay is watched for relaying, several of the update intervals writeListenConfig writes
const relaySilence = 2 * time.Second

// holds reports whether node's speaker holds a route to prefix through the peer named via
func holds(node *listenNode, prefix netip.Prefix, via *listenNode) bool {
	return slices.ContainsFunc(node.client.speaker.RouteDump(), func(route babel.RouteStat) bool {
		return route.Destination == prefix && strings.Contains(route.Via, via.name)
	})
}

// a hub leaving cap.transit out advertises only what it originates, so one spoke never learns the other's prefix through it, and its status says no transit
// a hub writing enable = true relays that prefix, and its status says transit
func TestStartupTransitDecidesWhetherTheHubRelays(t *testing.T) {
	far, own := netip.MustParsePrefix("fd00:c::/64"), netip.MustParsePrefix("fd00:b::/64")
	for name, relays := range map[string]bool{"left out": false, "enable = true": true} {
		t.Run(name, func(t *testing.T) {
			hub := &listenNode{name: "b", listen: true, transit: relays, announce: own}
			near, spoke := &listenNode{name: "a", dials: []*listenNode{hub}}, &listenNode{name: "c", dials: []*listenNode{hub}, announce: far}
			listenMesh(t, hub, near, spoke)
			if status := hub.client.Status(); status.NoTransit == relays {
				t.Errorf("the hub's status says no transit %t, where cap.transit is %s", status.NoTransit, name)
			}
			defer runListen(t, hub, near, spoke)()
			waitFor(t, convergeBudget, "the hub to learn the spoke's prefix and the near node the hub's", func() bool {
				return holds(hub, far, spoke) && holds(near, own, hub)
			})
			if relays {
				waitFor(t, convergeBudget, "the near node to learn the spoke's prefix through the hub", func() bool { return holds(near, far, hub) })
				return
			}
			time.Sleep(relaySilence)
			if holds(near, far, hub) {
				t.Error("a hub leaving cap.transit out relayed the spoke's prefix")
			}
		})
	}
}

// a reload that turns transit on or off is refused by name and changes nothing
// left out and enable = false are both off, so a reload between them applies, and reports no capability since nothing moved
func TestReloadRefusesTurningTransitOnOrOffAndChangesNothing(t *testing.T) {
	on, off := true, false
	for name, move := range map[string]struct{ old, next *babel.Transit }{
		"left out to enable = true":       {nil, &babel.Transit{Enable: &on}},
		"enable = true to enable = false": {&babel.Transit{Enable: &on}, &babel.Transit{Enable: &off}},
		"enable = true to left out":       {&babel.Transit{Enable: &on}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			c, path, _, bus := reloadOf(t, func(old *config.Config) { old.Cap.Transit = move.old })
			old := c.config()
			next := *old
			next.Cap.Transit = move.next
			joinedAndAnnounced(t, c, &next)
			writeConfig(t, path, &next)
			const naming = "config: cap.transit enable changed, restart to apply"
			if err := c.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), naming) {
				t.Fatalf("the reload was answered with %v, want it to say %q", err, naming)
			}
			changedNothing(t, c, old, bus)
		})
	}

	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	stated := *c.config()
	stated.Cap.Transit = &babel.Transit{Enable: &off}
	writeConfig(t, path, &stated)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload writing enable = false where the file left cap.transit out was refused: %v", err)
	}
	if got, ok := lastReload(t, bus)["applied"]; ok {
		t.Errorf("writing enable = false where the file left cap.transit out was recorded as applying %q", got)
	}
}

// changedCapabilities names cap.route for a change to what it announces, and a written cap.transit is no change to it
func TestReloadReportsCapRouteOnlyForItsAnnouncements(t *testing.T) {
	on := true
	old := &config.Config{}
	transit := &config.Config{Cap: config.Caps{Transit: &babel.Transit{Enable: &on}}}
	if got := changedCapabilities(old, transit); len(got) != 0 {
		t.Errorf("writing cap.transit out was reported as applying %v", got)
	}
	announced := &config.Config{Cap: config.Caps{Route: &babel.Routes{Announce: announce("fd00:9::/64")}}}
	if got := changedCapabilities(old, announced); !slices.Equal(got, []string{"cap.route"}) {
		t.Errorf("a new announcement was reported as applying %v, want cap.route", got)
	}
}
