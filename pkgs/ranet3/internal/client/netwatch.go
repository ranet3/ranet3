// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// networkSource is the host's network as this node follows it, kernel.NetworkWatch in production
type networkSource interface {
	Changes() <-chan kernel.NetworkChange
	State() (kernel.NetworkState, kernel.NetworkChange)
	Close() error
}

// openNetwork opens the one network watch of this node, nil on a platform the kernel package reads no routes on
func openNetwork(host kernel.Host, mesh string) (networkSource, error) {
	watch, err := kernel.WatchNetwork(host, mesh)
	if errors.Is(err, kernel.ErrUnsupported) {
		slog.Info("this platform has no network watch, a moved host waits for each session's own liveness check")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return watch, nil
}

// followNetwork acts on each change of the host's network until ctx ends
// the route reconciler is handed every change, since the rules of cap.exit follow the links
// where a default or an address moved, every socket connected to one peer closes, since it keeps a source the host may have lost or the route no longer picks
// every session is then asked to prove its path now, and every dialer comes round at once
// a dialer that finds its session healthy stands down as it does after any wake
// a link that comes or goes alone moves no session's path, so a container starting costs no probe
func (c *Client) followNetwork(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case change := <-c.network.Changes():
			if wake := c.reconcilerNetwork.Load(); wake != nil {
				(*wake)(change)
			}
			probed, woken := 0, 0
			if slices.ContainsFunc(change.Families(), kernel.FamilyChange.PathMoved) {
				c.hub.NetworkChanged()
				probed = len(c.sessions.matching("", true, c.sessions.startProbe))
				dialers := c.matchingDialers("", true)
				c.wakeDialers(dialers)
				woken = len(dialers)
				slog.Info("the host's network changed, every session probed and every dialer woken", "probed", probed, "woken", woken)
			}
			c.events.Emit("network.changed", "", append(changeAttrs(change), slog.Int("probed", probed), slog.Int("woken", woken))...)
		}
	}
}

// SetReconcilerNetwork hands followNetwork the route reconciler's wake for a change of the host's network, as SetReconcilerTable hands the reload path its SetTable
func (c *Client) SetReconcilerNetwork(wake func(kernel.NetworkChange)) {
	c.reconcilerNetwork.Store(&wake)
}

// networkState is the host's network as the watch last read it, the zero state where no watch runs
func (c *Client) networkState() kernel.NetworkState {
	if c.network == nil {
		return kernel.NetworkState{}
	}
	state, _ := c.network.State()
	return state
}

// changeAttrs names what moved in each family that moved, the default with what it was, the addresses added and removed, and the links added, removed and whose prefixes or far ends moved
func changeAttrs(change kernel.NetworkChange) []slog.Attr {
	var attrs []slog.Attr
	for _, family := range change.Families() {
		name := string(family.Family)
		if family.DefaultMoved() {
			attrs = append(attrs, slog.String(name+"_default", netmonDefault(family.DefaultAfter).String()),
				slog.String(name+"_default_was", netmonDefault(family.DefaultBefore).String()))
		}
		if len(family.Added) > 0 {
			attrs = append(attrs, slog.String(name+"_added", joinAddrs(family.Added)))
		}
		if len(family.Removed) > 0 {
			attrs = append(attrs, slog.String(name+"_removed", joinAddrs(family.Removed)))
		}
		added, removed, changed := linkMoves(family.LinksBefore, family.LinksAfter)
		for _, moved := range []struct {
			key   string
			names []string
		}{{"_links_added", added}, {"_links_removed", removed}, {"_links_changed", changed}} {
			if len(moved.names) > 0 {
				attrs = append(attrs, slog.String(name+moved.key, strings.Join(moved.names, " ")))
			}
		}
	}
	return attrs
}

// linkMoves names the links that came, those that went and those whose prefixes or far ends moved, each sorted
func linkMoves(before, after []kernel.Link) (added, removed, changed []string) {
	was := make(map[string]kernel.Link, len(before))
	for _, link := range before {
		was[link.Name] = link
	}
	for _, link := range after {
		old, ok := was[link.Name]
		switch {
		case !ok:
			added = append(added, link.Name)
		case !slices.Equal(old.Prefixes, link.Prefixes) || !slices.Equal(old.Peers, link.Peers):
			changed = append(changed, link.Name)
		}
		delete(was, link.Name)
	}
	return added, slices.Sorted(maps.Keys(was)), changed
}

func joinAddrs(addresses []netip.Addr) string {
	words := make([]string, len(addresses))
	for i, address := range addresses {
		words[i] = address.String()
	}
	return strings.Join(words, " ")
}
