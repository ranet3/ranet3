// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net"
	"net/netip"
)

// WatchNetwork opens the network watch over the PF_ROUTE watcher WatchLinks takes
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
	// this process's own writes are dropped as WatchLinks drops them, the underlay's scoped defaults among them
	watcher, err := host.Watch(0, index, true)
	if err != nil {
		return nil, err
	}
	reader := hostReader{host: host, mesh: index, interfaces: net.Interfaces}
	return newNetworkWatch(watcher.Changed(), reader.read, watcher.Close)
}

// hostReader reads the host's network through a Host, with the interface list apart so a test chooses it
type hostReader struct {
	host       Host
	mesh       int
	interfaces func() ([]net.Interface, error)
}

func (h hostReader) read() (NetworkState, error) {
	interfaces, err := h.interfaces()
	if err != nil {
		return NetworkState{}, err
	}
	var v4, v6 []netip.Addr
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Index == h.mesh {
			continue
		}
		prefixes, err := h.host.Addresses(device.Index)
		if err != nil {
			return NetworkState{}, err
		}
		for _, prefix := range prefixes {
			switch address := prefix.Addr().Unmap(); {
			case !address.IsGlobalUnicast():
			case address.Is4():
				v4 = append(v4, address)
			default:
				v6 = append(v6, address)
			}
		}
	}
	state := NetworkState{IPv4: NetworkFamily{Addresses: addressSet(v4)}, IPv6: NetworkFamily{Addresses: addressSet(v6)}}
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
