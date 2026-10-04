// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const cloneDevicePath = "/dev/net/tun"

// defaultTUNName lets the kernel number the interface.
const defaultTUNName = "ranet%d"

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

// createTUNQueues opens the lanes of name
// and sets the device's gso_max_segs to the read batch
func createTUNQueues(name string, mtu, queueCount int) ([]tun.Device, string, error) {
	devices, actualName, err := openTUNQueues(name, mtu, queueCount, unix.IFF_MULTI_QUEUE)
	if err != nil && queueCount == 1 {
		// a tun made without IFF_MULTI_QUEUE refuses a multiqueue attach
		devices, actualName, err = openTUNQueues(name, mtu, 1, 0)
	}
	if err != nil {
		return nil, "", err
	}
	// every queue of one device reads in batches of the same size
	batch := devices[0].BatchSize()
	if err := setGSOMaxSegs(actualName, batch); err != nil {
		slog.Warn("netstack could not set gso_max_segs on the tun", "interface", actualName, "segments", batch, "err", err)
	}
	return devices, actualName, nil
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

// openTUNQueues opens one file descriptor per Linux multiqueue TUN lane.
// Each descriptor is wrapped in its own wireguard-go Device, which gives every
// data-plane worker independent read buffers, GRO tables, and I/O locks.
func openTUNQueues(name string, mtu, queueCount int, multiqueue uint16) ([]tun.Device, string, error) {
	devices := make([]tun.Device, 0, queueCount)
	closeDevices := func() {
		for _, device := range devices {
			_ = device.Close()
		}
	}

	actualName := name
	for i := range queueCount {
		fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			closeDevices()
			return nil, "", fmt.Errorf("open %s for queue %d: %w", cloneDevicePath, i, err)
		}

		requestName := actualName
		if i == 0 {
			requestName = name
		}
		ifr, err := unix.NewIfreq(requestName)
		if err == nil {
			ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | multiqueue)
			err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
		}
		if err != nil {
			_ = unix.Close(fd)
			closeDevices()
			return nil, "", fmt.Errorf("attach tun %q queue %d: %w", requestName, i, err)
		}
		if i == 0 {
			actualName = ifr.Name()
		}

		var device tun.Device
		if i == 0 {
			if err := unix.SetNonblock(fd, true); err != nil {
				_ = unix.Close(fd)
				closeDevices()
				return nil, "", fmt.Errorf("make tun %q nonblocking: %w", actualName, err)
			}
			file := os.NewFile(uintptr(fd), cloneDevicePath)
			device, err = tun.CreateTUNFromFile(file, mtu)
			if err != nil {
				_ = file.Close()
			}
		} else {
			device, _, err = tun.CreateUnmonitoredTUNFromFD(fd)
		}
		if err != nil {
			closeDevices()
			return nil, "", fmt.Errorf("initialize tun %q queue %d: %w", actualName, i, err)
		}
		devices = append(devices, device)
	}
	return devices, actualName, nil
}
