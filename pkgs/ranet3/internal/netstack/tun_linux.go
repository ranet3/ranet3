// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/wireguard/tun"
)

const cloneDevicePath = "/dev/net/tun"

// tunMTUSettable is true, the kernel taking a new MTU on a tun whose queues are open
const tunMTUSettable = true

// setTUNMTU sets the MTU of the link name with SIOCSIFMTU
// wireguard-go sets no MTU on a device made from descriptors and exports no setter
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
// the device is made from the descriptors alone, so nothing reads its events
func createTUNQueues(name string, mtu, queueCount int) (tun.Device, string, error) {
	queueCount = tunQueues(queueCount)
	// IFF_TUN_EXCL has the kernel refuse a device of the default name that exists
	// where a queue opened under that name would join it, another instance's or not
	var exclusive uint16
	if name == defaultTUNName {
		exclusive = unix.IFF_TUN_EXCL
	}
	fds, actualName, err := openTUNQueues(name, queueCount, unix.IFF_MULTI_QUEUE, exclusive)
	if err != nil && queueCount == 1 {
		// a tun made without IFF_MULTI_QUEUE refuses a multiqueue attach
		fds, actualName, err = openTUNQueues(name, 1, 0, exclusive)
	}
	if exclusive != 0 && errors.Is(err, unix.EBUSY) {
		return nil, "", fmt.Errorf("a device named %q already exists, and the default name is never attached to: a second instance on this host needs a link.tun of its own, as does a device made for this one", name)
	}
	if err != nil {
		return nil, "", err
	}
	// the device owns the descriptors from here, whether it is made or not
	device, _, err := tun.CreateUnmonitoredTUNFromFDs(fds)
	if err != nil {
		return nil, "", fmt.Errorf("initialize tun %q: %w", actualName, err)
	}
	// the MTU is set on a device attached to as on one created, since the first keeps the MTU it had and the second takes the kernel's default
	if err := setTUNMTU(actualName, mtu); err != nil {
		_ = device.Close()
		return nil, "", fmt.Errorf("initialize tun %q: set its mtu to %d: %w", actualName, mtu, err)
	}
	batch := device.BatchSize()
	if err := setGSOMaxSegs(actualName, batch); err != nil {
		slog.Warn("netstack could not set gso_max_segs on the tun", "interface", actualName, "segments", batch, "err", err)
	}
	return device, actualName, nil
}

// setGSOMaxSegs sets how many segments the kernel puts in one GSO frame for the link name
// the request is written here because internal/kernel, which holds the netlink client, imports this package
func setGSOMaxSegs(name string, segments int) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	request := make([]byte, unix.SizeofNlMsghdr+unix.SizeofIfInfomsg+unix.SizeofRtAttr+4)
	binary.NativeEndian.PutUint32(request[0:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	body := request[unix.SizeofNlMsghdr:]
	binary.NativeEndian.PutUint32(body[4:], uint32(link.Index))
	attr := body[unix.SizeofIfInfomsg:]
	binary.NativeEndian.PutUint16(attr[0:], unix.SizeofRtAttr+4)
	binary.NativeEndian.PutUint16(attr[2:], unix.IFLA_GSO_MAX_SEGS)
	binary.NativeEndian.PutUint32(attr[4:], uint32(segments))
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	// NLM_F_ACK makes the one reply an NLMSG_ERROR
	// whose errno is zero when the kernel took the value
	reply := make([]byte, unix.SizeofNlMsghdr+unix.SizeofNlMsgerr)
	if _, _, err := unix.Recvfrom(fd, reply, 0); err != nil {
		return err
	}
	if errno := int32(binary.NativeEndian.Uint32(reply[unix.SizeofNlMsghdr:])); errno != 0 {
		return unix.Errno(-errno)
	}
	return nil
}

// openTUNQueues opens one file descriptor per lane of name
// multiqueue is IFF_MULTI_QUEUE, or 0 for a tun made without that flag
// exclusive is IFF_TUN_EXCL when the first lane has to create the device, or 0
func openTUNQueues(name string, queueCount int, multiqueue, exclusive uint16) ([]int, string, error) {
	fds := make([]int, 0, queueCount)
	closeFDs := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	// a tun made without IFF_MULTI_QUEUE refuses a multiqueue attach
	// and naming the mode in the error points at that device
	attach := "attach tun"
	if multiqueue != 0 {
		attach = "attach multiqueue tun"
	}

	actualName := name
	for i := range queueCount {
		fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			closeFDs()
			return nil, "", fmt.Errorf("open %s for queue %d: %w", cloneDevicePath, i, err)
		}

		flags := unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | multiqueue
		if i == 0 {
			// the later lanes join the device this one makes, under the name it got
			flags |= exclusive
		}
		ifr, err := unix.NewIfreq(actualName)
		if err == nil {
			ifr.SetUint16(flags)
			err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
		}
		if err != nil {
			_ = unix.Close(fd)
			closeFDs()
			return nil, "", fmt.Errorf("%s %q queue %d: %w", attach, actualName, i, err)
		}
		if i == 0 {
			actualName = ifr.Name()
		}
		fds = append(fds, fd)
	}
	return fds, actualName, nil
}
