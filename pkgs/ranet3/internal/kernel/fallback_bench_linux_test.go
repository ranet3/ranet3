// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// benchMesh is the mesh's tun, benchUplink the uplink's stand-in, and benchForwarded a link whose hosts the namespace forwards
	benchMesh      = "ranetbm0"
	benchUplink    = "ranetbu0"
	benchForwarded = "ranetbf0"
	// benchService is the listed service's port on the uplink's address, and benchClient the far side's port
	benchService = 7100
	benchClient  = 5000
)

var (
	benchUplink4, benchUplink6 = prefix("198.51.100.10/25"), prefix("2001:db8:a::10/64")
	benchForwarded4            = prefix("203.0.113.1/26")
	// benchInternet is a host beyond the LAN, and benchPeer an overlay address the mesh's tun carries
	benchInternet = netip.MustParseAddr("203.0.113.200")
	benchPeer     = netip.MustParseAddr("192.0.2.9")
	benchOwn      = prefix("203.0.113.128/26")
)

// benchSwitch is a throwaway namespace holding the mesh's tun, the uplink's tun with main's defaults through it, and a forwarded link's
// tun, each held open by the benchmark, with the platform that writes the table
type benchSwitch struct {
	plat *netlinkPlatform
	fds  map[string]int
}

func newBenchSwitch(b *testing.B) *benchSwitch {
	b.Helper()
	if os.Getuid() != 0 {
		b.Skip("the table's arms need root on linux")
	}
	enterThrowawayNamespace(b)
	conn, err := dialNetlink()
	if err != nil {
		b.Fatalf("dial rtnetlink: %v", err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(b, conn)
	s := &benchSwitch{fds: map[string]int{}}
	index := map[string]uint32{}
	for _, name := range []string{benchMesh, benchUplink, benchForwarded} {
		s.fds[name] = benchTUN(b, name)
		link, err := conn.link(0, name)
		if err != nil {
			b.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(b, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	writeBatchSysctl(b, "ipv4/ip_forward", "1")
	for _, name := range []string{"all", "default", benchUplink, benchForwarded} {
		writeBatchSysctl(b, "ipv4/conf/"+name+"/rp_filter", "0")
	}
	writeBatchAddress(b, conn, index[benchUplink], benchUplink4)
	writeBatchAddress(b, conn, index[benchUplink], benchUplink6)
	writeBatchAddress(b, conn, index[benchForwarded], benchForwarded4)
	writeBatchRoute(b, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: index[benchUplink]})
	writeBatchRoute(b, conn, unix.RT_TABLE_MAIN, prefix("::/0"), batchHop{index: index[benchUplink]})
	writeBatchRoute(b, conn, unix.RT_TABLE_MAIN, prefix("192.0.2.0/24"), batchHop{index: index[benchMesh]})
	tbl, rt := platformFor(benchMesh)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		b.Fatalf("open the netlink platform: %v", err)
	}
	b.Cleanup(func() { _ = opened.Close() })
	s.plat = opened.(*netlinkPlatform)
	return s
}

// benchTUN opens the tun name and answers its descriptor, which the device lives as long as
func benchTUN(b *testing.B, name string) int {
	b.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		b.Skipf("no /dev/net/tun: %v", err)
	}
	b.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		b.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		b.Fatalf("create tun %s: %v", name, err)
	}
	return fd
}

// write writes the table for sets, its tun the mesh's
func (s *benchSwitch) write(b *testing.B, sets fallbackSets) {
	b.Helper()
	sets.tun = benchMesh
	if err := s.plat.writeFallback(sets, false); err != nil {
		b.Fatalf("write the table: %v", err)
	}
}

// benchSocket is a UDP socket of to's family bound to from and port, unbound where from is invalid, connected to to and port 9
func benchSocket(b *testing.B, from netip.Addr, port int, to netip.Addr) int {
	b.Helper()
	family := unix.AF_INET6
	if to.Is4() {
		family = unix.AF_INET
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = unix.Close(fd) })
	if from.IsValid() {
		if err := unix.Bind(fd, benchSockaddr(from, port)); err != nil {
			b.Fatalf("bind %s: %v", from, err)
		}
	}
	if err := unix.Connect(fd, benchSockaddr(to, 9)); err != nil && !errors.Is(err, unix.ENETUNREACH) {
		b.Fatalf("connect %s: %v", to, err)
	}
	return fd
}

func benchSockaddr(address netip.Addr, port int) unix.Sockaddr {
	if address.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: address.As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: address.As16()}
}

// benchSend sends b.N datagrams on fd, each meeting want: nil, EPERM for the table's drop, or ENETUNREACH for 5450.
// A tun nobody reads drops what its queue cannot hold, which ENOBUFS reports.
func benchSend(b *testing.B, fd int, to netip.Addr, want error) {
	b.Helper()
	payload := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		err := unix.Sendto(fd, payload, 0, benchSockaddr(to, 9))
		if errors.Is(err, unix.ENOBUFS) {
			continue
		}
		if !errors.Is(err, want) && (want != nil || err != nil) {
			b.Fatalf("a datagram to %s met %v, want %v", to, err, want)
		}
	}
}

// The host's own UDP into the tun with the exit live, against the same send with no table: the first line's accept on the common path
func BenchmarkFallbackSendIntoTheTun(b *testing.B) {
	for _, table := range []bool{false, true} {
		b.Run(fmt.Sprintf("table %v", table), func(b *testing.B) {
			s := newBenchSwitch(b)
			if table {
				s.write(b, fallbackSets{})
			}
			benchSend(b, benchSocket(b, netip.Addr{}, 0, benchPeer), benchPeer, nil)
		})
	}
}

// The host's own UDP from the uplink's address to a LAN host, with 2, 50 and 500 networks in the LAN's set, against no table: the
// forwarded line's input device and the interval lookup. The networks are IPv6, as 500 apart from one another fit no IPv4 documentation range.
func BenchmarkFallbackSendToTheLAN(b *testing.B) {
	for _, networks := range []int{0, 2, 50, 500} {
		b.Run(fmt.Sprintf("%d networks", networks), func(b *testing.B) {
			s := newBenchSwitch(b)
			lan := []netip.Prefix{benchUplink6.Masked()}
			for i := 1; i < networks; i++ {
				lan = append(lan, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i), 0x10}), 64))
			}
			if networks > 0 {
				s.write(b, fallbackSets{lan6: lan})
			}
			to := netip.MustParseAddr("2001:db8:a::20")
			benchSend(b, benchSocket(b, benchUplink6.Addr(), 0, to), to, nil)
		})
	}
}

// The host's own UDP beyond the LAN with the mesh's defaults retracted: through main and out of the uplink with no table, against
// 5450's ENETUNREACH (layout A) and the table's drop (layout B)
func BenchmarkFallbackSendRetracted(b *testing.B) {
	for _, layout := range []string{"no table", "A, 5450", "B, the drop"} {
		b.Run(layout, func(b *testing.B) {
			s := newBenchSwitch(b)
			var want error
			switch layout {
			case "A, 5450":
				if err := s.plat.AddRule(Rule{Family: FamilyIPv4, Priority: priorityRefused, IIF: loopback, action: actionUnreachable}); err != nil {
					b.Fatal(err)
				}
				s.write(b, fallbackSets{})
				want = unix.ENETUNREACH
			case "B, the drop":
				s.write(b, fallbackSets{})
				want = unix.EPERM
			}
			benchSend(b, benchSocket(b, netip.Addr{}, 0, benchInternet), benchInternet, want)
		})
	}
}

// benchDatagram is an IPv4 UDP datagram of size bytes from source to destination, its checksum zero, which IPv4 takes as none
func benchDatagram(size int, source netip.Addr, sourcePort int, destination netip.Addr, port int) []byte {
	datagram := make([]byte, size)
	datagram[0], datagram[8], datagram[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(datagram[2:], uint16(size))
	copy(datagram[12:16], source.AsSlice())
	copy(datagram[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(datagram[10:], ^uint16(packet.Sum(0, datagram[:20])))
	binary.BigEndian.PutUint16(datagram[20:], uint16(sourcePort))
	binary.BigEndian.PutUint16(datagram[22:], uint16(port))
	binary.BigEndian.PutUint16(datagram[24:], uint16(size-20))
	return datagram
}

// A host's datagram the namespace forwards from a link forward leaves out and from one it names, of 64 and 1400 bytes, against no
// table: the forwarded line's cost per packet on a subnet router. One forward names meets every line and the drop.
func BenchmarkFallbackForward(b *testing.B) {
	for _, size := range []int{64, 1400} {
		for _, arm := range []string{"no table", "left out", "named"} {
			b.Run(fmt.Sprintf("%d bytes, %s", size, arm), func(b *testing.B) {
				s := newBenchSwitch(b)
				switch arm {
				case "left out":
					s.write(b, fallbackSets{})
				case "named":
					s.write(b, fallbackSets{forwarded: []string{benchForwarded}})
				}
				datagram := benchDatagram(size, netip.MustParseAddr("203.0.113.10"), benchClient, benchInternet, 9)
				fd := s.fds[benchForwarded]
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if _, err := unix.Write(fd, datagram); err != nil {
						b.Fatalf("write into %s: %v", benchForwarded, err)
					}
				}
			})
		}
	}
}

// A listed service's replies to a flow the far side opened, with 1 and 20 ports listed and the service's last, against no table:
// the connection lines
func BenchmarkFallbackInboundReplies(b *testing.B) {
	for _, listed := range []int{0, 1, 20} {
		b.Run(fmt.Sprintf("%d ports listed", listed), func(b *testing.B) {
			s := newBenchSwitch(b)
			var services []Service
			for i := 1; i < listed; i++ {
				services = append(services, Service{Protocol: "udp", First: uint16(6000 + 2*i), Last: uint16(6000 + 2*i)})
			}
			if listed > 0 {
				s.write(b, fallbackSets{udp: append(services, Service{Protocol: "udp", First: benchService, Last: benchService})})
			}
			far := netip.MustParseAddr("203.0.113.9")
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = unix.Close(fd) })
			if err := unix.Bind(fd, benchSockaddr(benchUplink4.Addr(), benchService)); err != nil {
				b.Fatal(err)
			}
			// the flow is the far side's: its first datagram arrives by the uplink before the service answers
			if _, err := unix.Write(s.fds[benchUplink], benchDatagram(64, far, benchClient, benchUplink4.Addr(), benchService)); err != nil {
				b.Fatal(err)
			}
			read := make([]byte, 64)
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
				b.Fatal(err)
			}
			if _, _, err := unix.Recvfrom(fd, read, 0); err != nil {
				b.Fatalf("read the far side's datagram: %v", err)
			}
			to := benchSockaddr(far, benchClient)
			payload := make([]byte, 64)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := unix.Sendto(fd, payload, 0, to); err != nil && !errors.Is(err, unix.ENOBUFS) {
					b.Fatalf("a reply met %v", err)
				}
			}
		})
	}
}

// A route lookup of this node's own prefix beyond the gateway with and without 5445 and 5450: the rule walk's added length
func BenchmarkFallbackRouteGet(b *testing.B) {
	for _, rules := range []bool{false, true} {
		b.Run(fmt.Sprintf("5445 and 5450 %v", rules), func(b *testing.B) {
			s := newBenchSwitch(b)
			if rules {
				for _, rule := range []Rule{
					{Family: FamilyIPv4, Priority: priorityOwnPastMesh, To: schema.PrefixFrom(benchOwn), Table: schema.TableMain},
					{Family: FamilyIPv4, Priority: priorityRefused, IIF: loopback, action: actionUnreachable},
				} {
					if err := s.plat.AddRule(rule); err != nil {
						b.Fatal(err)
					}
				}
			}
			to := benchOwn.Addr().Next()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := RouteGet(netip.Addr{}, to, ""); err != nil {
					b.Fatalf("look up %s: %v", to, err)
				}
			}
		})
	}
}
