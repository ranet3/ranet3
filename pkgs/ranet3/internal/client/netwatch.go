// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
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
// every session proves its path now and every dialer comes round at once
// a dialer that finds its session healthy stands down as it does after any wake
func (c *Client) followNetwork(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case change := <-c.network.Changes():
			probed := c.sessions.matching("", true, c.sessions.startProbe)
			dialers := c.matchingDialers("", true)
			c.wakeDialers(dialers)
			attrs := append(changeAttrs(change), slog.Int("probed", len(probed)), slog.Int("woken", len(dialers)))
			c.events.Emit("network.changed", "", attrs...)
			slog.Info("the host's network changed, every session probed and every dialer woken", "probed", len(probed), "woken", len(dialers))
		}
	}
}

// changeAttrs names what moved in each family that moved, the default with what it was and the addresses added and removed
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
	}
	return attrs
}

func joinAddrs(addresses []netip.Addr) string {
	words := make([]string, len(addresses))
	for i, address := range addresses {
		words[i] = address.String()
	}
	return strings.Join(words, " ")
}
