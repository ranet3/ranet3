// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
)

// WatchNetwork opens the network watch over a PF_ROUTE watcher of every interface
// mesh names this node's tun, whose addresses and routes never signal, and is empty on a node without one
// host is the machine it reads, nil for the one this process is running on
func WatchNetwork(host Host, mesh string) (*NetworkWatch, error) {
	host = hostOr(host)
	index := 0
	if mesh != "" {
		var err error
		if index, err = host.InterfaceIndex(mesh); err != nil {
			return nil, err
		}
	}
	watcher, err := host.Watch(0, index)
	if err != nil {
		return nil, err
	}
	reader := hostReader{host: host, mesh: index}
	return newNetworkWatch(watcher.Changed(), reader.read, watcher.Close)
}

// hostReader reads the host's network through a Host
type hostReader struct {
	host Host
	mesh int
}

func (h hostReader) read() (NetworkState, error) {
	interfaces, err := h.host.Links()
	if err != nil {
		return NetworkState{}, err
	}
	var state NetworkState
	state.IPv4, state.IPv6 = hostLinks(interfaces, h.mesh)
	if state.IPv4.Default, err = h.defaultRoute(netip.IPv4Unspecified()); err != nil {
		return NetworkState{}, err
	}
	if state.IPv6.Default, err = h.defaultRoute(netip.IPv6Unspecified()); err != nil {
		return NetworkState{}, err
	}
	return state, nil
}

// defaultRoute names the interface of the family's default, the zero value where the host has none of its own
func (h hostReader) defaultRoute(family netip.Addr) (DefaultRoute, error) {
	index, gateway, err := lookupDefault(h.host, h.mesh, family)
	if errors.Is(err, ErrNoDefaultRoute) {
		return DefaultRoute{}, nil
	}
	if err != nil {
		return DefaultRoute{}, err
	}
	name, err := h.host.InterfaceName(index)
	if err != nil {
		return DefaultRoute{}, err
	}
	return DefaultRoute{Interface: name, Gateway: gateway}, nil
}
