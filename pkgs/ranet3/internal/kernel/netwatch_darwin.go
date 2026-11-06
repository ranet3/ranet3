// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
)

// ShareWatcher opens the host's watcher of every interface but mesh, which reads the routing socket and the kernel's network events, for the
// underlay's selection and the network watch to follow through a Reader each
// mesh names this node's tun, whose addresses, routes and events never wake it, and is empty on a node without one
// host is the machine it watches, nil for the one this process is running on
func ShareWatcher(host Host, mesh string) (*SharedWatcher, error) {
	host = hostOr(host)
	index, err := meshIndex(host, mesh)
	if err != nil {
		return nil, err
	}
	watcher, err := host.Watch(0, index)
	if err != nil {
		return nil, err
	}
	return shareWatcher(watcher), nil
}

// meshIndex is the index of the mesh's tun, zero where mesh is empty
func meshIndex(host Host, mesh string) (int, error) {
	if mesh == "" {
		return 0, nil
	}
	return host.InterfaceIndex(mesh)
}

// WatchNetwork opens the network watch over watcher, a Reader of the SharedWatcher of every interface but mesh, which it takes over and
// closes when the watch closes or fails to open
// mesh names this node's tun, which the reads leave out, and is empty on a node without one
// host is the machine it reads, nil for the one this process is running on
func WatchNetwork(host Host, mesh string, watcher Watcher) (*NetworkWatch, error) {
	host = hostOr(host)
	index, err := meshIndex(host, mesh)
	if err != nil {
		_ = watcher.Close()
		return nil, err
	}
	reader := hostReader{host: host, mesh: index}
	return newNetworkWatch(watcher.Changed(), reader.read, watcher.Close, watchSweep)
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
