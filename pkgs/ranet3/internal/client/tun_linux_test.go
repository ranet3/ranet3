// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// captureWait is how long a read of the capture waits for a packet before the SYN is sent again
const captureWait = time.Second

// synPort is the port each SYN below goes to
// and tells it apart from anything else the capture reads
const synPort = 443

// a SYN a peer sends through its session reaches the tun with its MSS lowered to what this node's session carries back
// the MSS bravo's link.mtu leaves is that link.mtu less the IP and TCP headers of the SYN's family
// alpha hands each SYN straight to its session
// which leaves bravo's inbound path the only one that can have lowered it
// a steered SYN reaches bravo inside an outer IPv6 header to an End.DT46 SID of bravo's, which the session's own clamp passes over
// and its MSS is lowered to the same once bravo takes it out of that header
// a capture on bravo's tun reads the SYN as the kernel receives it
// with every byte but the MSS and the checksum as alpha sent it
// and bravo counts the clamp, at the session for a SYN it carries bare and at the End.DT46 for a steered one
func TestTUNClampsTheMSSOfASYNArrivingThroughASession(t *testing.T) {
	const session = 1300
	enterEmptyNamespace(t)
	mesh, err := netstack.NewNamed(0, "synclamp0", nil)
	if err != nil {
		t.Fatalf("open bravo's mesh: %v", err)
	}
	t.Cleanup(mesh.Close)
	capture := captureInbound(t, mesh.Name)
	alpha, bravo := newLoopbackMeshOn(t, mesh)
	exit := netip.MustParseAddr("fd00:b::d7")
	cfg := *bravo.client.config()
	cfg.Link.MTU = session
	cfg.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}}}
	// holding the headend's outer source below
	cfg.Cap.Border = borderOf(alpha.prefix.Masked().String())
	segments, _, err := cfg.SegmentTables()
	if err != nil {
		t.Fatalf("build bravo's segment table: %v", err)
	}
	// as New installs the table of cap.segment
	mesh.SetSegments(segments)
	bravo.client.cfg.Store(&cfg)
	run(t, alpha, bravo)
	var peer *netstack.Peer
	waitFor(t, convergeBudget, "alpha forwarding to bravo's prefix", func() bool {
		found, verdict, _ := alpha.client.Mesh.Routes.Resolve(netip.Addr{}, bravo.prefix.Addr().Next())
		peer = found
		return verdict == netstack.RoutePeer && found != nil
	})
	headend := alpha.prefix.Addr().Next()
	for _, arm := range []struct {
		name                string
		source, destination netip.Addr
		nextHeader          byte
		mss                 uint16
		steered             bool
	}{
		{"IPv4", netip.MustParseAddr("10.66.0.2"), netip.MustParseAddr("10.66.0.1"), esp.NextHeaderIPv4, session - 40, false},
		{"IPv6", headend, bravo.prefix.Addr().Next(), esp.NextHeaderIPv6, session - 60, false},
		{"IPv4 steered to an End.DT46 SID", netip.MustParseAddr("10.66.0.2"), netip.MustParseAddr("10.66.0.11"), esp.NextHeaderIPv4, session - 40, true},
		{"IPv6 steered to an End.DT46 SID", headend, netip.MustParseAddr("fd00:b::11"), esp.NextHeaderIPv6, session - 60, true},
	} {
		t.Run(arm.name, func(t *testing.T) {
			syn := synTo(arm.source, arm.destination, 1460)
			send, nextHeader := syn, arm.nextHeader
			if arm.steered {
				outer, err := srv6.Encapsulate(syn, headend, []netip.Addr{exit})
				if err != nil {
					t.Fatalf("encapsulate the SYN toward %s: %v", exit, err)
				}
				send, nextHeader = outer, esp.NextHeaderIPv6
			}
			clamped := mesh.MSSClamped()
			got := sendUntilCaptured(t, peer, send, nextHeader, capture, arm.destination)
			if want := withMSS(syn, arm.mss); !bytes.Equal(got, want) {
				t.Errorf("a SYN from %s with an MSS of 1460 reached bravo's tun with an MSS of %d, want %d, as %x where %x was wanted",
					arm.source, binary.BigEndian.Uint16(got[tcpOffset(got)+22:]), arm.mss, got, want)
			}
			if mesh.MSSClamped() == clamped {
				t.Errorf("bravo lowered the MSS of a SYN from %s and counted no clamp", arm.source)
			}
		})
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

// sendUntilCaptured hands raw to peer until the capture reads a SYN to synPort of destination, and returns that SYN
// it sends again after each captureWait the capture reads nothing in
// the destination tells this caller's SYN from a copy an earlier one sent again
func sendUntilCaptured(t *testing.T, peer *netstack.Peer, raw []byte, nextHeader byte, capture int, destination netip.Addr) []byte {
	t.Helper()
	buf := make([]byte, 1<<16)
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		place, err := peer.ReserveRawOrDrop(bytes.Clone(raw), nextHeader)
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
			if got := buf[:n]; isSYNTo(got, destination, synPort) {
				return bytes.Clone(got)
			}
		}
	}
	t.Fatalf("no SYN to %s reached the tun within %s", destination, convergeBudget)
	return nil
}

// isSYNTo reports whether raw is an IP packet to destination carrying a TCP SYN to port
func isSYNTo(raw []byte, destination netip.Addr, port uint16) bool {
	offset := tcpOffset(raw)
	if offset == 0 || len(raw) < offset+20 || binary.BigEndian.Uint16(raw[offset+2:]) != port || raw[offset+13]&0x02 == 0 {
		return false
	}
	if raw[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(raw[16:20])) == destination
	}
	return netip.AddrFrom16([16]byte(raw[24:40])) == destination
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
	fd, err := openCapture(name, captureWait)
	if err != nil {
		t.Fatalf("capture %s: %v", name, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// openCapture opens a packet socket reading each packet crossing the link name in the calling thread's namespace, each read waiting wait
func openCapture(name string, wait time.Duration) (int, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return -1, err
	}
	// every protocol, in the network byte order packet(7) takes it in
	all := binary.NativeEndian.Uint16(binary.BigEndian.AppendUint16(nil, unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(all))
	if err != nil {
		return -1, err
	}
	timeout := unix.NsecToTimeval(wait.Nanoseconds())
	if err := errors.Join(unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: all, Ifindex: link.Index}),
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
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
	if err := enterEmptyNetwork(); err != nil {
		t.Fatal(err)
	}
}

// enterEmptyNetwork moves the calling thread, which its caller locked, into a new network namespace and brings its loopback up
// and refuses to go on unless the namespace changed and holds no route
func enterEmptyNetwork() error {
	var before, after unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &before); err != nil {
		return fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare a network namespace: %w", err)
	}
	if err := unix.Stat("/proc/thread-self/ns/net", &after); err != nil {
		return fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	if after.Ino == before.Ino {
		return errors.New("refusing to continue: the network namespace did not change")
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("dump the routes of the new namespace: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return fmt.Errorf("parse the route dump: %w", err)
	}
	for _, message := range messages {
		if message.Header.Type == syscall.RTM_NEWROUTE {
			return errors.New("refusing to continue: this network namespace already holds routes")
		}
	}
	return bringUp("lo")
}

// bringUp sets the up flag of the link name, as netstack does for a tun it opens
func bringUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open a socket to bring %s up: %w", name, err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("read the flags of %s: %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bring %s up: %w", name, err)
	}
	return nil
}
