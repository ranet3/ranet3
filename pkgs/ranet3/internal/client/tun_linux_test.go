// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// captureWait is how long a read of the capture waits for a packet before the SYN is sent again
const captureWait = time.Second

// synPort is the port each SYN below goes to
// and tells it apart from anything else the capture reads
const synPort = 443

// a SYN a peer sends through its session reaches the tun with its MSS lowered to what this node's session carries back
// bravo's link.mtu of 1300 bytes leaves an MSS of 1260 under IPv4 and 1240 under IPv6
// alpha hands each SYN straight to its session
// which leaves bravo's inbound path the only one that can have lowered it
// a capture on bravo's tun reads the SYN as the kernel receives it
// with every byte but the MSS and the checksum as alpha sent it
func TestTUNClampsTheMSSOfASYNArrivingThroughASession(t *testing.T) {
	const session = 1300
	enterEmptyNamespace(t)
	mesh, err := netstack.NewNamed(0, 0, "synclamp0")
	if err != nil {
		t.Fatalf("open bravo's mesh: %v", err)
	}
	t.Cleanup(mesh.Close)
	capture := captureInbound(t, mesh.Name)
	alpha, bravo := newLoopbackMeshOn(t, mesh)
	cfg := *bravo.client.config()
	cfg.Link.MTU = session
	bravo.client.cfg.Store(&cfg)
	run(t, alpha, bravo)
	var peer *netstack.Peer
	waitFor(t, convergeBudget, "alpha forwarding to bravo's prefix", func() bool {
		found, ok := alpha.client.Mesh.Routes.Lookup(netip.Addr{}, bravo.prefix.Addr().Next())
		peer = found
		return ok && found != nil
	})
	for _, family := range []struct {
		source, destination netip.Addr
		nextHeader          byte
		mss                 uint16
	}{
		{netip.MustParseAddr("10.66.0.2"), netip.MustParseAddr("10.66.0.1"), esp.NextHeaderIPv4, session - 40},
		{alpha.prefix.Addr().Next(), bravo.prefix.Addr().Next(), esp.NextHeaderIPv6, session - 60},
	} {
		syn := synTo(family.source, family.destination, 1460)
		got := sendUntilCaptured(t, peer, syn, family.nextHeader, capture)
		if want := withMSS(syn, family.mss); !bytes.Equal(got, want) {
			t.Errorf("a SYN from %s with an MSS of 1460 reached bravo's tun with an MSS of %d, want %d, as %x where %x was wanted",
				family.source, binary.BigEndian.Uint16(got[tcpOffset(got)+22:]), family.mss, got, want)
		}
	}
}

// a reload moves the tun New opened to link.mtu less the longest steering list, read back from the kernel
// whether link.mtu moves or the list grows by a segment
func TestTUNFollowsAReloadOfLinkMTUOrTheSteering(t *testing.T) {
	header := func(segments int) int { return 40 + 8 + 16*segments }
	a, b := "3fff:1:69c:98d6::1", "3fff:1:69c:6c46::1"
	for name, move := range map[string]struct {
		old, next func(*config.Config)
		from, to  int
	}{
		"link.mtu raised": {func(*config.Config) {}, func(c *config.Config) { c.Link.MTU = 2000 }, 1400, 2000},
		"a list one segment longer": {
			func(c *config.Config) { c.Cap.Segment = steering(a) },
			func(c *config.Config) { c.Cap.Segment = steering(a, b) },
			1400 - header(1), 1400 - header(2),
		},
	} {
		t.Run(name, func(t *testing.T) {
			enterEmptyNamespace(t)
			c, path := startOnTUN(t, move.old)
			if got := linkMTU(t, c.Mesh.Name); got != move.from {
				t.Fatalf("New opened the tun at %d bytes, want %d", got, move.from)
			}
			next := *c.config()
			move.next(&next)
			writeConfig(t, path, &next)
			if err := c.ReloadFrom(path); err != nil {
				t.Fatalf("the reload was refused: %v", err)
			}
			if got := linkMTU(t, c.Mesh.Name); got != move.to {
				t.Errorf("the tun holds %d bytes after the reload, want %d", got, move.to)
			}
		})
	}
}

// New opens every read buffer for link.mtu rather than for the device
// the device runs at link.mtu less the longest steering list
// 8936 bytes at link.mtu 9000 under one segment
// and the mesh holds the 9000 bytes a steered read of 8936 grows to in its own buffer
func TestTUNOpenedByNewHoldsASteeredReadOfLinkMTU(t *testing.T) {
	const largest = 9000
	enterEmptyNamespace(t)
	c, _ := startOnTUN(t, func(cfg *config.Config) {
		cfg.Link.MTU = largest
		cfg.Cap.Segment = steering("3fff:1:69c:98d6::1")
	})
	if got, want := linkMTU(t, c.Mesh.Name), largest-(40+8+16); got != want {
		t.Errorf("New opened the tun at %d bytes, want %d", got, want)
	}
	if err := c.Mesh.CheckMTU(largest); err != nil {
		t.Errorf("the mesh New opened cannot hold a steered read of link.mtu: %v", err)
	}
}

// startOnTUN starts a node through New on a tun of its own, from the reload fixture's configuration with change made to it
// it returns the node and the path a reload reads its next configuration from
func startOnTUN(t *testing.T, change func(*config.Config)) (*Client, string) {
	t.Helper()
	fixture, path := reloadFixture(t)
	cfg := *fixture.config()
	cfg.Link.TUN = "reload0"
	change(&cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the configuration the node starts on is refused: %v", err)
	}
	c, err := New(&cfg, events.New())
	if err != nil {
		t.Fatalf("start the node: %v", err)
	}
	t.Cleanup(c.Close)
	return c, path
}

// sendUntilCaptured hands syn to peer until the capture reads a SYN to synPort, and returns that SYN
// it sends again after each captureWait the capture reads nothing in
func sendUntilCaptured(t *testing.T, peer *netstack.Peer, syn []byte, nextHeader byte, capture int) []byte {
	t.Helper()
	buf := make([]byte, 1<<16)
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		place, err := peer.ReserveRawOrDrop(bytes.Clone(syn), nextHeader)
		if err != nil {
			t.Fatalf("hand the SYN to the session: %v", err)
		}
		if err := place.Send(); err != nil {
			t.Fatalf("send the SYN: %v", err)
		}
		for {
			n, _, err := unix.Recvfrom(capture, buf, 0)
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				t.Fatalf("read the capture: %v", err)
			}
			if raw := buf[:n]; isSYNTo(raw, synPort) {
				return bytes.Clone(raw)
			}
		}
	}
	t.Fatalf("no SYN reached the tun within %s", convergeBudget)
	return nil
}

// isSYNTo reports whether raw is an IP packet carrying a TCP SYN to port
func isSYNTo(raw []byte, port uint16) bool {
	offset := tcpOffset(raw)
	return offset != 0 && len(raw) >= offset+20 && binary.BigEndian.Uint16(raw[offset+2:]) == port && raw[offset+13]&0x02 != 0
}

// tcpOffset is where TCP starts in the IPv4 or IPv6 packet raw, zero for a packet that carries no TCP right after its header
func tcpOffset(raw []byte) int {
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4 && raw[9] == 6:
		return int(raw[0]&0x0f) * 4
	case len(raw) >= 40 && raw[0]>>4 == 6 && raw[6] == 6:
		return 40
	}
	return 0
}

// synTo is an IP packet from source to destination carrying a TCP SYN to synPort with one option, an MSS of mss
func synTo(source, destination netip.Addr, mss uint16) []byte {
	segment := make([]byte, 24)
	binary.BigEndian.PutUint16(segment[0:], 40000)
	binary.BigEndian.PutUint16(segment[2:], synPort)
	binary.BigEndian.PutUint32(segment[4:], 1)
	segment[12], segment[13] = 6<<4, 0x02
	binary.BigEndian.PutUint16(segment[14:], 64240)
	copy(segment[20:], []byte{2, 4, byte(mss >> 8), byte(mss)})
	var raw []byte
	if source.Is4() {
		raw = make([]byte, 20, 20+len(segment))
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:], uint16(20+len(segment)))
		raw[8], raw[9] = 64, 6
		copy(raw[12:], source.AsSlice())
		copy(raw[16:], destination.AsSlice())
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw)))
	} else {
		raw = make([]byte, 40, 40+len(segment))
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:], uint16(len(segment)))
		raw[6], raw[7] = 6, 64
		copy(raw[8:], source.AsSlice())
		copy(raw[24:], destination.AsSlice())
	}
	raw = append(raw, segment...)
	sumTCP(raw)
	return raw
}

// withMSS is the SYN synTo built, its MSS set to mss and its checksum written again
func withMSS(syn []byte, mss uint16) []byte {
	out := bytes.Clone(syn)
	binary.BigEndian.PutUint16(out[tcpOffset(out)+22:], mss)
	sumTCP(out)
	return out
}

// sumTCP writes the checksum of the TCP segment in the IP packet raw
// over the pseudo-header of RFC 9293 section 3.1 under IPv4 and of RFC 8200 section 8.1 under IPv6
func sumTCP(raw []byte) {
	offset := tcpOffset(raw)
	segment := raw[offset:]
	length := binary.BigEndian.AppendUint16(nil, uint16(len(segment)))
	pseudo := slices.Concat(raw[12:20], []byte{0, 6}, length)
	if offset == 40 {
		pseudo = slices.Concat(raw[8:40], []byte{0, 0}, length, []byte{0, 0, 0, 6})
	}
	binary.BigEndian.PutUint16(segment[16:], 0)
	binary.BigEndian.PutUint16(segment[16:], ^uint16(packet.Sum(packet.Sum(0, pseudo), segment)))
}

// captureInbound opens a packet socket that reads each packet crossing the link name
// the ones the mesh writes into it among them
// a read waits captureWait for one
func captureInbound(t *testing.T, name string) int {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	// every protocol, in the network byte order packet(7) takes it in
	all := binary.NativeEndian.Uint16(binary.BigEndian.AppendUint16(nil, unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(all))
	if err != nil {
		t.Fatalf("open a packet socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: all, Ifindex: link.Index}); err != nil {
		t.Fatalf("bind the packet socket to %s: %v", name, err)
	}
	wait := unix.NsecToTimeval(captureWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &wait); err != nil {
		t.Fatalf("bound how long a read of the capture waits: %v", err)
	}
	return fd
}

// linkMTU is the MTU the kernel holds for the link name
// read through the standard library rather than through the code under test
func linkMTU(t *testing.T, name string) int {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	return link.MTU
}

// enterEmptyNamespace moves the test's thread into a network namespace of its own and brings its loopback up
// and refuses to go on unless that namespace is new and held no route before
// the tun, the sockets and the capture a test opens on its own goroutine live there
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
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open a socket to bring the loopback up with: %v", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatalf("build an ifreq for the loopback: %v", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatalf("read the flags of the loopback: %v", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatalf("bring the loopback up: %v", err)
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
