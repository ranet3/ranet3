// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// a GSO frame of more segments than one read holds comes back cut short
// the kernel splits it before the tun once gso_max_segs is the read batch
// and every way the mesh comes by its device has to set that value
func TestTUNSetsGSOMaxSegsToTheReadBatch(t *testing.T) {
	for _, path := range []struct {
		name  string
		setup func(t *testing.T, device string)
	}{
		{"created", func(*testing.T, string) {}},
		{"multiqueue attach", func(t *testing.T, device string) {
			persistTUN(t, device, unix.IFF_MULTI_QUEUE)
		}},
		{"single-queue attach at one core", func(t *testing.T, device string) {
			persistTUN(t, device, 0)
			previous := runtime.GOMAXPROCS(1)
			t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			const device = "gsocap0"
			path.setup(t, device)
			if _, err := net.InterfaceByName(device); err == nil {
				t.Logf("gso_max_segs %d before the mesh attached", gsoMaxSegs(t, device))
			}

			m, err := NewNamed(0, device)
			if err != nil {
				t.Fatalf("open the mesh on %s: %v", device, err)
			}
			t.Cleanup(m.Close)
			batch := m.devs[0].BatchSize()
			if batch < 2 {
				t.Fatalf("the device reads %d packet at a time, so it takes no GSO frame and this proves nothing", batch)
			}
			got := gsoMaxSegs(t, m.Name)
			t.Logf("gso_max_segs %d with the mesh on it, reading %d packets at a time", got, batch)
			if got != uint32(batch) {
				t.Errorf("the kernel holds gso_max_segs %d for %s, want the read batch of %d", got, m.Name, batch)
			}
		})
	}
}

// enterEmptyNamespace moves the test's thread into a network namespace of its own
// and refuses to go on unless that namespace is new and holds no route
// a loaded tunnel module puts a fallback device in every new namespace
// the thread stays locked
// and the runtime retires it with the test rather than run another goroutine in the namespace
func enterEmptyNamespace(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	runtime.LockOSThread()
	before := namespaceOf(t)
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare a network namespace: %v", err)
	}
	if namespaceOf(t) == before {
		t.Fatal("refusing to continue: the network namespace did not change")
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		t.Fatalf("dump the routes of the new namespace: %v", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		t.Fatalf("parse the route dump: %v", err)
	}
	for _, message := range messages {
		if message.Header.Type == syscall.RTM_NEWROUTE {
			t.Fatal("refusing to continue: this network namespace already holds routes")
		}
	}
}

// namespaceOf is the inode of the calling thread's network namespace
func namespaceOf(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatalf("stat this thread's network namespace: %v", err)
	}
	return st.Ino
}

// persistTUN leaves a tun the way systemd-networkd does
// it outlives its descriptor with no queue attached
func persistTUN(t *testing.T, name string, flags uint16) {
	t.Helper()
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", cloneDevicePath, err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tun %s: %v", name, err)
	}
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
		t.Fatalf("keep tun %s past its descriptor: %v", name, err)
	}
}

// gsoMaxSegs is the GSO segment limit the kernel holds for the link name
// read through the standard library rather than through the code under test
func gsoMaxSegs(t *testing.T, name string) uint32 {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		t.Fatalf("dump the links: %v", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		t.Fatalf("parse the link dump: %v", err)
	}
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWLINK || binary.NativeEndian.Uint32(message.Data[4:]) != uint32(link.Index) {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			t.Fatalf("parse the attributes of %s: %v", name, err)
		}
		for _, attr := range attrs {
			if attr.Attr.Type == unix.IFLA_GSO_MAX_SEGS {
				return binary.NativeEndian.Uint32(attr.Value)
			}
		}
	}
	t.Fatalf("the kernel reported no gso_max_segs for %s", name)
	return 0
}
