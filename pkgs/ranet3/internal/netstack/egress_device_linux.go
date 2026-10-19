// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/wireguard/tun"
)

// NewEgressDevice creates the egress device, a tun of one queue taking frames
// as the mesh tun does, at mtu, and brings it up with no address in either
// family and multicast off
// on a host forwarding IPv6 the tun joins ff02::2 when it registers, before multicast goes off, so the kernel still sends its MLD reports for that group each time the device's IPv6 comes up
// it is always created and never attached to, so a device of the name already there refuses the start
// rp_filter is 0 because the kernel's reverse path check fails every source on a device with no address, loose mode included
// disable_ipv6 is 0 whatever conf.default holds, since the kernel discards every IPv6 packet arriving on a device with it set
func NewEgressDevice(name string, mtu int) (tun.Device, error) {
	fds, actualName, err := openTUNQueues(name, 1, 0, unix.IFF_TUN_EXCL)
	if errors.Is(err, unix.EBUSY) {
		return nil, fmt.Errorf("a device named %q already exists, and the egress device is always created and never attached to", name)
	}
	if err != nil {
		return nil, err
	}
	device, _, err := tun.CreateUnmonitoredTUNFromFDs(fds)
	if err != nil {
		return nil, fmt.Errorf("initialize the egress device %q: %w", actualName, err)
	}
	if err := prepareEgressDevice(actualName, mtu); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("initialize the egress device %q: %w", actualName, err)
	}
	return device, nil
}

// prepareEgressDevice sets what the link has to carry before it goes up, since
// a link-local address is generated and router advertisements are taken at up
func prepareEgressDevice(name string, mtu int) error {
	if err := setTUNMTU(name, mtu); err != nil {
		return fmt.Errorf("set its mtu to %d: %w", mtu, err)
	}
	for _, sysctl := range []struct{ path, value string }{
		{"/proc/sys/net/ipv6/conf/" + name + "/addr_gen_mode", "1"},
		{"/proc/sys/net/ipv6/conf/" + name + "/accept_ra", "0"},
		{"/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", "0"},
		{"/proc/sys/net/ipv4/conf/" + name + "/rp_filter", "0"},
	} {
		if err := os.WriteFile(sysctl.path, []byte(sysctl.value), 0); err != nil {
			return err
		}
	}
	if err := bringTUNUp(name, unix.IFF_MULTICAST); err != nil {
		return fmt.Errorf("bring it up with multicast off: %w", err)
	}
	return nil
}
