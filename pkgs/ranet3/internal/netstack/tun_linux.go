// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/wireguard/tun"
)

// tunMTUSettable is true, the kernel taking a new MTU on a tun whose queues are open
const tunMTUSettable = true

// setTUNMTU sets the MTU of the link name with SIOCSIFMTU
// wireguard-go sets the MTU only when it opens the device and exports no setter
func setTUNMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	return unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr)
}

func bringTUNUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// tunQueues is how many queues a mesh asking for wanted lanes opens, up to the most one tun takes
func tunQueues(wanted int) int { return min(wanted, maxTUNQueues) }

// createTUNQueues opens the lanes of name as the queues of one device, whose MTU it sets to mtu
// and sets the device's gso_max_segs to the read batch
// nothing reads the device's events, so it watches nothing
func createTUNQueues(name string, mtu, queueCount int) (tun.Device, string, error) {
	queueCount = tunQueues(queueCount)
	// a device made multiqueue at one lane still takes the lanes of a second instance under its name
	options := []tun.Option{tun.WithQueues(queueCount), tun.MultiQueue(), tun.Unmonitored()}
	// a queue opened under the default name would join a device of that name that exists, another instance's or not
	exclusive := name == defaultTUNName
	if exclusive {
		options = append(options, tun.Exclusive())
	}
	device, err := tun.CreateTUN(name, mtu, options...)
	if exclusive && errors.Is(err, unix.EBUSY) {
		return nil, "", fmt.Errorf("a device named %q already exists, and the default name is never attached to: a second instance on this host needs a link.tun of its own, as does a device made for this one", name)
	}
	if err != nil {
		return nil, "", fmt.Errorf("open tun %q with %d queues: %w", name, queueCount, err)
	}
	actualName, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	batch := device.BatchSize()
	if err := device.(*tun.NativeTun).SetGSOMaxSegs(batch); err != nil {
		slog.Warn("netstack could not set gso_max_segs on the tun", "interface", actualName, "segments", batch, "err", err)
	}
	return device, actualName, nil
}
