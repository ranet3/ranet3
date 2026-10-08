// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// a GSO frame of more segments than one read holds comes back cut short
// the kernel splits it before the tun once gso_max_segs is the read batch
// and every way the mesh comes by its device has to set that value
func TestTUNSetsGSOMaxSegsToTheReadBatch(t *testing.T) {
	for _, path := range []struct {
		name string
		// asked is the name the mesh is opened with and device the one the kernel gives it
		asked, device string
		setup         func(t *testing.T, device string)
	}{
		{"created", "gsocap0", "gsocap0", func(*testing.T, string) {}},
		{"created under the default name", "", "ranet3", func(*testing.T, string) {}},
		{"created from a name the kernel numbers", "gsocap%d", "gsocap0", func(*testing.T, string) {}},
		{"multiqueue attach", "gsocap0", "gsocap0", func(t *testing.T, device string) {
			persistTUN(t, device, unix.IFF_MULTI_QUEUE)
		}},
		{"single-queue attach at one core", "gsocap0", "gsocap0", func(t *testing.T, device string) {
			persistTUN(t, device, 0)
			previous := runtime.GOMAXPROCS(1)
			t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			path.setup(t, path.device)
			if _, err := net.InterfaceByName(path.device); err == nil {
				t.Logf("gso_max_segs %d before the mesh attached", gsoMaxSegs(t, path.device))
			}

			m, err := NewNamed(0, 0, path.asked)
			if err != nil {
				t.Fatalf("open the mesh on %q: %v", path.asked, err)
			}
			t.Cleanup(m.Close)
			if m.Name != path.device {
				t.Fatalf("the mesh opened %q as %s, want %s", path.asked, m.Name, path.device)
			}
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

// a node whose kernel refused the cap can cut a burst of reads just after it opens the tun and then no more
// so the first cut read of a mesh NewNamed opened warns at once rather than an interval later
func TestTUNMeshWarnsAtItsFirstCutRead(t *testing.T) {
	enterEmptyNamespace(t)
	m, err := NewNamed(0, 0, "gsocap0")
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	warned := warnedReads(t)
	m.noteTruncatedRead()
	if got := warned(); !slices.Equal(got, []uint64{1}) {
		t.Errorf("the first cut read of a new mesh warned with counts %v, want one line at once", got)
	}
}

// a queue opened under the name of a multiqueue tun joins that device
// and a mesh under the default name has to be refused instead when a device of that name is there
// whether its link.tun is empty or names ranet3
// at one core a multiqueue open that a single-queue device refuses is tried again single-queue
// and that open has to refuse the device too
func TestTUNUnderTheDefaultNameIsNeverShared(t *testing.T) {
	heldByAMesh := func(t *testing.T) {
		first, err := NewNamed(0, 0, "")
		if err != nil {
			t.Fatalf("open the first mesh: %v", err)
		}
		t.Cleanup(first.Close)
	}
	singleQueueAtOneCore := func(t *testing.T) {
		persistTUN(t, "ranet3", 0)
		previous := runtime.GOMAXPROCS(1)
		t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	}
	for _, arm := range []struct {
		name  string
		asked string
		setup func(t *testing.T)
	}{
		{"held by a mesh, empty link.tun", "", heldByAMesh},
		{"held by a mesh, link.tun naming it", "ranet3", heldByAMesh},
		{"single-queue at one core, empty link.tun", "", singleQueueAtOneCore},
		{"single-queue at one core, link.tun naming it", "ranet3", singleQueueAtOneCore},
	} {
		t.Run(arm.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			arm.setup(t)

			m, err := NewNamed(0, 0, arm.asked)
			if err == nil {
				m.Close()
				t.Fatalf("a mesh asking for %q joined %s, which was there before it", arm.asked, m.Name)
			}
			t.Logf("the refusal reads: %v", err)
			for _, want := range []string{`"ranet3"`, "link.tun"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal reads %q, which does not name %s", err, want)
				}
			}
		})
	}
}

// every lane after the first joins the device the first one made, under the name the kernel gave it
// only the first lane may refuse a device that exists, or the default name would never get a second lane
// a template asked of every lane would make one device per lane
// the lane count is given outright, so a runner of any core count opens several
func TestTUNLanesJoinTheDeviceTheFirstLaneMade(t *testing.T) {
	const lanes = 4
	for _, name := range []string{"ranet3", "gsocap%d"} {
		t.Run(name, func(t *testing.T) {
			enterEmptyNamespace(t)
			devices, actualName, err := createTUNQueues(name, DefaultMTU, lanes)
			if err != nil {
				t.Fatalf("open %d lanes of %q: %v", lanes, name, err)
			}
			t.Cleanup(func() {
				for _, device := range devices {
					_ = device.Close()
				}
			})
			if len(devices) != lanes {
				t.Fatalf("%q opened %d lanes, want %d", name, len(devices), lanes)
			}
			links, err := net.Interfaces()
			if err != nil {
				t.Fatalf("list the links: %v", err)
			}
			var made []string
			for _, link := range links {
				if strings.HasPrefix(link.Name, strings.TrimSuffix(name, "%d")) {
					made = append(made, link.Name)
				}
			}
			if len(made) != 1 || made[0] != actualName {
				t.Errorf("%d lanes of %q made %v, want the one device %s", lanes, name, made, actualName)
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
