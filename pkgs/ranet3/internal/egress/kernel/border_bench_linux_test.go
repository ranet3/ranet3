// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// The benchmarks are arms A to E. A to C time a packet's path through the
// table as root, D a pass moving a set by one LAN as root, and E a pass that
// moves nothing, which needs no kernel.

// the benchmarks' devices and addresses: the mesh's tun, an uplink's tun with
// an address of each family, a host beyond the uplink in each family, and a
// prefix of the mesh's in each family routed into its tun
const (
	benchTun    = "ranet3"
	benchUplink = "eth9"
)

var (
	benchUplink4 = netip.MustParsePrefix("192.0.2.1/24")
	benchUplink6 = netip.MustParsePrefix("2001:db8::1/64")
	benchFar4    = netip.MustParseAddr("203.0.113.9")
	benchFar6    = netip.MustParseAddr("2001:db8:ff::9")
	benchMesh4   = netip.MustParsePrefix("198.18.0.0/15")
	benchMesh6   = netip.MustParsePrefix("3fff::/20")
)

// benchFamilies is each family an arm runs in
var benchFamilies = []string{"ipv4", "ipv6"}

// benchHost is a throwaway namespace holding the mesh's tun and the uplink's,
// each held open by the benchmark
type benchHost struct {
	tun, uplink int
}

func newBenchHost(b *testing.B) *benchHost {
	b.Helper()
	if os.Getuid() != 0 {
		b.Skip("the antispoof filter's benchmarks need root on linux")
	}
	enterThrowawayNamespace(b)
	if err := netnstest.BringUp("lo"); err != nil {
		b.Fatal(err)
	}
	// an address the uplink takes is usable at once, with no duplicate detection to wait out
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0o644); err != nil {
		b.Fatal(err)
	}
	h := &benchHost{tun: benchOpenTun(b, benchTun), uplink: benchOpenTun(b, benchUplink)}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		b.Fatal(err)
	}
	defer netlink.Close()
	if err := netlink.AddAddresses(benchUplink, benchUplink4, benchUplink6); err != nil {
		b.Fatal(err)
	}
	tun, err := netInterfaceIndex(benchTun)
	if err != nil {
		b.Fatal(err)
	}
	uplink, err := netInterfaceIndex(benchUplink)
	if err != nil {
		b.Fatal(err)
	}
	for _, route := range []struct {
		index int
		to    netip.Prefix
	}{
		{tun, benchMesh4}, {tun, benchMesh6},
		{uplink, netip.PrefixFrom(benchFar4, 24).Masked()}, {uplink, netip.PrefixFrom(benchFar6, 48).Masked()},
	} {
		if err := netlink.RouteVia(route.index, route.to, netip.Addr{}); err != nil {
			b.Fatalf("route %s: %v", route.to, err)
		}
	}
	return h
}

// benchOpenTun opens the tun name, brings it up and answers its descriptor,
// which the device lives as long as
func benchOpenTun(b *testing.B, name string) int {
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
	if err := netnstest.BringUp(name); err != nil {
		b.Fatal(err)
	}
	return fd
}

// drain reads every packet queued on the tun fd, as the daemon's reader would
func drain(fd int, buf []byte) {
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
	}
}

func netInterfaceIndex(name string) (int, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, err
	}
	return int(ifr.Uint32()), nil
}

// write starts an antispoof filter over cfg and sets, withdrawn when the benchmark ends
func (h *benchHost) write(b *testing.B, cfg *egress.Border, sets egress.BorderSets) *BorderFilter {
	b.Helper()
	be, err := newBorderBackend()
	if err != nil {
		b.Fatal(err)
	}
	rt := egress.BorderRuntime{Tun: benchTun, Inside: []string{benchTun, "lo"}, Sets: func(*egress.Border) egress.BorderSets { return sets }}
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		b.Fatalf("write the table: %v", err)
	}
	b.Cleanup(func() { _ = f.finish() })
	return f
}

// conntrackAlone turns conntrack on in the namespace by a table of its own
// holding one ct rule at forward, a hook no benchmark's packet meets, so an
// arm holding it pays conntrack's hooks and no chain of the filter's
func conntrackAlone(b *testing.B) {
	b.Helper()
	conn, err := nftables.Dial()
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	chain := nftables.Chain{Table: "conntrack", Name: "forward", Type: "filter", Hook: unix.NF_INET_FORWARD}
	rule, err := chain.Rule(unix.NFPROTO_INET, "accept a reply", append(nftables.CTReplyMatch(), nftables.Verdict(nftables.Accept)))
	if err != nil {
		b.Fatal(err)
	}
	if err := conn.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, chain.Table), chain.Create(unix.NFPROTO_INET), rule}); err != nil {
		b.Fatalf("turn conntrack on: %v", err)
	}
}

// checksum folds the ones' complement sum of data into sum
func checksum(sum uint32, data []byte) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// benchUDP is a UDP datagram of eight bytes of payload from source to
// destination's port 9, of either family, with its checksums
func benchUDP(source, destination netip.Addr) []byte {
	udp := make([]byte, 8+8)
	binary.BigEndian.PutUint16(udp[0:], 4000)
	binary.BigEndian.PutUint16(udp[2:], 9)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	pseudo := slices.Concat(source.AsSlice(), destination.AsSlice())
	if source.Is4() {
		pseudo = append(pseudo, 0, unix.IPPROTO_UDP, 0, byte(len(udp)))
		binary.BigEndian.PutUint16(udp[6:], fold(checksum(checksum(0, pseudo), udp)))
		packet := make([]byte, 20, 20+len(udp))
		packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(packet[2:], uint16(20+len(udp)))
		copy(packet[12:], source.AsSlice())
		copy(packet[16:], destination.AsSlice())
		binary.BigEndian.PutUint16(packet[10:], fold(checksum(0, packet)))
		return append(packet, udp...)
	}
	pseudo = append(pseudo, 0, 0, 0, byte(len(udp)), 0, 0, 0, unix.IPPROTO_UDP)
	binary.BigEndian.PutUint16(udp[6:], fold(checksum(checksum(0, pseudo), udp)))
	packet := make([]byte, 40, 40+len(udp))
	packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_UDP, 64
	binary.BigEndian.PutUint16(packet[4:], uint16(len(udp)))
	copy(packet[8:], source.AsSlice())
	copy(packet[24:], destination.AsSlice())
	return append(packet, udp...)
}

// benchOverlay is an overlay of a prefix of each family, each
// holding the uplink's network of its family and neither the far host
func benchOverlay() *egress.Border {
	return &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8::/48")}}
}

// benchFamily is the uplink's address and the far host of family
func benchFamily(family string) (uplink netip.Prefix, far netip.Addr) {
	if family == "ipv6" {
		return benchUplink6, benchFar6
	}
	return benchUplink4, benchFar4
}

// Arm A: a datagram from a host beyond the uplink to the uplink's own
// address, written into the uplink's tun b.N times, meeting prerouting, in
// each family: with no table, with conntrack alone, with mesh_entry alone
// (conntrack on), with the antispoof chain over the overlay and no carve-out,
// so no carved drop, and with the uplink's network carved out in each family
// and two of the mesh's prefixes inside each. A source outside the overlay
// meets every line of the antispoof chain.
func BenchmarkBorderChainOnAnUnderlayPacket(b *testing.B) {
	carved := egress.BorderSets{
		CarveOuts: []egress.CarveOut{{Link: benchUplink, Prefix: benchUplink4.Masked()}, {Link: benchUplink, Prefix: benchUplink6.Masked()}},
		Carved:    ranges("192.0.2.128/32", "192.0.2.130/32", "2001:db8::80/128", "2001:db8::82/128"),
	}
	for _, family := range benchFamilies {
		for _, arm := range []struct {
			name             string
			conntrack, table bool
			cfg              *egress.Border
			sets             egress.BorderSets
		}{
			{"no table", false, false, nil, egress.BorderSets{}},
			{"conntrack alone", true, false, nil, egress.BorderSets{}},
			{"mesh_entry alone", false, true, nil, egress.BorderSets{}},
			{"overlay with no carve-out", false, true, benchOverlay(), egress.BorderSets{}},
			{"two carve-outs", false, true, benchOverlay(), carved},
		} {
			b.Run(family+"/"+arm.name, func(b *testing.B) {
				h := newBenchHost(b)
				if arm.conntrack {
					conntrackAlone(b)
				}
				if arm.table {
					h.write(b, arm.cfg, arm.sets)
				}
				uplink, far := benchFamily(family)
				packet := benchUDP(far, uplink.Addr())
				b.ReportAllocs()
				for b.Loop() {
					if _, err := unix.Write(h.uplink, packet); err != nil {
						b.Fatalf("write into %s: %v", benchUplink, err)
					}
				}
			})
		}
	}
}

// benchOwned is n ranges of one address each in family, none adjacent to
// another: every other address of the mesh's prefix from its first, then the
// uplink's address where held, else the address two past it
func benchOwned(family string, n int, held bool) []egress.Range {
	uplink, _ := benchFamily(family)
	base := benchMesh4.Addr()
	if family == "ipv6" {
		base = benchMesh6.Addr()
	}
	out := make([]egress.Range, 0, n)
	for i := range n - 1 {
		raw := base.AsSlice()
		binary.BigEndian.PutUint32(raw[len(raw)-4:], binary.BigEndian.Uint32(raw[len(raw)-4:])+uint32(2*i))
		address, _ := netip.AddrFromSlice(raw)
		out = append(out, egress.Range{First: address, Last: address})
	}
	last := uplink.Addr()
	if !held {
		last = last.Next().Next()
	}
	return append(out, egress.Range{First: last, Last: last})
}

// benchMeshAddress is an address of the mesh's in family, routed into the tun
func benchMeshAddress(family string) netip.Addr {
	if family == "ipv6" {
		return benchMesh6.Addr().Next().Next().Next().Next().Next().Next().Next()
	}
	return benchMesh4.Addr().Next().Next().Next().Next().Next().Next().Next()
}

// benchSocket is a UDP socket of family bound to the uplink's address and
// connected to to's port 9
func benchSocket(b *testing.B, family string, to netip.Addr) int {
	b.Helper()
	uplink, _ := benchFamily(family)
	domain := unix.AF_INET6
	var local, remote unix.Sockaddr = &unix.SockaddrInet6{Addr: uplink.Addr().As16()}, &unix.SockaddrInet6{Addr: to.As16(), Port: 9}
	if family == "ipv4" {
		domain = unix.AF_INET
		local, remote = &unix.SockaddrInet4{Addr: uplink.Addr().As4()}, &unix.SockaddrInet4{Addr: to.As4(), Port: 9}
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, local); err != nil {
		b.Fatal(err)
	}
	if err := unix.Connect(fd, remote); err != nil {
		b.Fatal(err)
	}
	return fd
}

// Arm B: the host's own datagram from the uplink's address into the mesh,
// routed into the tun, which the benchmark drains, b.N times in each family,
// unmarked and in its flow's original direction: with no table, with
// conntrack alone, through mesh_entry with an owned set of 1, 100 and 10,000
// ranges, one of which holds the source, which passes after the set's lookup,
// and with 10,000 that do not hold it, which mesh_entry drops with EPERM
func BenchmarkEntryChainSendIntoTheTun(b *testing.B) {
	for _, family := range benchFamilies {
		for _, arm := range []struct {
			name      string
			conntrack bool
			owned     int
			held      bool
		}{
			{"no table", false, 0, false},
			{"conntrack alone", true, 0, false},
			{"owned 1", false, 1, true},
			{"owned 100", false, 100, true},
			{"owned 10000", false, 10000, true},
			{"not owned 10000", false, 10000, false},
		} {
			b.Run(family+"/"+arm.name, func(b *testing.B) {
				h := newBenchHost(b)
				if arm.conntrack {
					conntrackAlone(b)
				}
				if arm.owned > 0 {
					h.write(b, nil, egress.BorderSets{Owned: benchOwned(family, arm.owned, arm.held)})
				}
				fd := benchSocket(b, family, benchMeshAddress(family))
				payload, buf := make([]byte, 8), make([]byte, 2048)
				b.ReportAllocs()
				for b.Loop() {
					_, err := unix.Write(fd, payload)
					switch {
					case err == nil && arm.owned > 0 && !arm.held:
						b.Fatal("mesh_entry passed a source no owned range holds")
					case err != nil && !(errors.Is(err, unix.EPERM) && !arm.held && arm.owned > 0):
						b.Fatalf("send into the tun: %v", err)
					}
					drain(h.tun, buf)
				}
			})
		}
	}
}

// Arm C: the underlay's own send, a datagram from the uplink's address to the
// far host out of the uplink, which the benchmark drains, b.N times in each
// family, as one datagram and as 8 segments of 1,200 bytes by UDP_SEGMENT:
// with no table, with conntrack on beforehand, and with the table, whose
// mesh_entry returns it at its first line
func BenchmarkUplinkSend(b *testing.B) {
	for _, family := range benchFamilies {
		for _, segments := range []int{1, 8} {
			for _, arm := range []struct {
				name             string
				conntrack, table bool
			}{
				{"no table", false, false},
				{"conntrack alone", true, false},
				{"table", false, true},
			} {
				b.Run(fmt.Sprintf("%s/%d segments/%s", family, segments, arm.name), func(b *testing.B) {
					h := newBenchHost(b)
					if arm.conntrack {
						conntrackAlone(b)
					}
					if arm.table {
						h.write(b, nil, egress.BorderSets{})
					}
					_, far := benchFamily(family)
					fd := benchSocket(b, family, far)
					payload := make([]byte, 8)
					if segments > 1 {
						payload = make([]byte, 1200*segments)
						if err := unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_SEGMENT, 1200); err != nil {
							b.Skipf("no UDP_SEGMENT: %v", err)
						}
					}
					buf := make([]byte, 2048)
					b.ReportAllocs()
					for b.Loop() {
						if _, err := unix.Write(fd, payload); err != nil {
							b.Fatalf("send out of %s: %v", benchUplink, err)
						}
						drain(h.uplink, buf)
					}
				})
			}
		}
	}
}

// benchLANs is n LANs of family none, every other one of its length, so no
// two touch: /30s of 198.18.0.0/15, the range RFC 2544 sets aside for
// benchmarks, and /64s of 2001:db8::/32
func benchLANs(family string, n int) []egress.Range {
	prefixes := make([]netip.Prefix, 0, n)
	for i := range n {
		if family == "ipv6" {
			prefixes = append(prefixes, deltaLAN(2*i))
			continue
		}
		raw := netip.MustParseAddr("198.18.0.0").As4()
		binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+uint32(8*i))
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(raw), 30))
	}
	return meshkernel.Ranges(prefixes)
}

// Arm D: one whole pass that moves a none set by one LAN, as a route change
// wakes it, at 1,000 and 10,000 LANs in each family: each iteration takes one
// LAN out and puts it back, two passes, each deriving the sets, reading the
// table back, sending the delta and reading it back again. It reports the
// element notifications every nf_tables listener received per iteration.
func BenchmarkNoneSetMovesByOneLAN(b *testing.B) {
	for _, family := range benchFamilies {
		for _, n := range []int{1000, 10000} {
			b.Run(fmt.Sprintf("%s/%d", family, n), func(b *testing.B) {
				h := newBenchHost(b)
				all := benchLANs(family, n+1)
				lans := all
				f := h.write(b, nil, egress.BorderSets{})
				f.rt.Sets = func(*egress.Border) egress.BorderSets { return egress.BorderSets{None: lans} }
				f.trigger = "routes"
				if err := f.reconcile(); err != nil {
					b.Fatal(err)
				}
				listener := openElementListener(b)
				listener.elements(b)
				b.ReportAllocs()
				for b.Loop() {
					for _, next := range [][]egress.Range{all[:n], all} {
						lans = next
						f.trigger = "routes"
						if err := f.reconcile(); err != nil || !f.ready {
							b.Fatalf("a pass moving one LAN: %v, ready %v (%s)", err, f.ready, f.unready)
						}
					}
				}
				sent, overflowed := listener.elements(b)
				if overflowed {
					b.Fatalf("the listener overflowed after %d element messages", sent)
				}
				b.ReportMetric(float64(sent)/float64(b.N), "elements/op")
			})
		}
	}
}

// benchTable is the mesh's table of an exit, and the classes it translates
type benchTable struct {
	routes  *netstack.RouteTable
	overlay []schema.Prefix
	classes []egress.Class
}

var benchPeer = &netstack.Peer{ID: "example/peer"}

func (t benchTable) set(lan netip.Prefix) { t.routes.Set(netip.Prefix{}, lan, benchPeer) }

func (t benchTable) forget(lan netip.Prefix) { t.routes.Remove(netip.Prefix{}, lan) }

// exitTable is the mesh's table of an exit whose none class is
// 2001:db8::/32, holding n /64 LANs drawn in it that other nodes advertise,
// with the sets a pass derives from it as the node derives them
func exitTable(n int) (benchTable, func(*egress.Border) egress.BorderSets) {
	t := benchTable{
		routes:  netstack.NewRouteTable(),
		overlay: []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("198.18.0.0/15")},
		classes: []egress.Class{{From: schema.MustPrefix("2001:db8::/32"), To: egress.Translation{None: true}}},
	}
	t.routes.SetOverlay(t.overlay)
	t.routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff::1/128"), netstack.Local)
	random := rand.New(rand.NewPCG(5, 5))
	for range n {
		raw := netip.MustParseAddr("2001:db8::").As16()
		binary.BigEndian.PutUint32(raw[4:], random.Uint32())
		t.set(netip.PrefixFrom(netip.AddrFrom16(raw), 64))
	}
	return t, func(*egress.Border) egress.BorderSets {
		snapshot := t.routes.Snapshot()
		return egress.BorderSets{Owned: meshkernel.OwnedSources(snapshot, t.overlay), None: meshkernel.NoneDestinations(t.classes, snapshot, t.overlay)}
	}
}

// Arm E: a pass that moves no set at an exit holding 10,000 /64 LANs drawn in
// the /32 of a none class, as each wake of the mesh's table runs it, over the
// fake backend so it needs no root: the derivation of the sets from the
// mesh's table, the rules and the comparison with the last pass. A burst is
// 100 passes, each run by reconcile itself and so with none of Run's
// coalescing, a LAN outside the none class going and coming with each, so no
// set moves.
func BenchmarkBorderPassThatMovesNothing(b *testing.B) {
	for _, burst := range []bool{false, true} {
		name := "one wake"
		if burst {
			name = "a burst of 100 passes"
		}
		b.Run(name, func(b *testing.B) {
			table, derive := exitTable(10000)
			rt := borderRuntime(nil)
			rt.Sets = derive
			backend := &fakeBorder{}
			f, err := startBorderFilter(nil, rt, backend)
			if err != nil {
				b.Fatal(err)
			}
			lan := netip.MustParsePrefix("198.51.100.0/24")
			b.ReportAllocs()
			for b.Loop() {
				if !burst {
					f.trigger = "routes"
					if err := f.reconcile(); err != nil {
						b.Fatal(err)
					}
					continue
				}
				for i := range 100 {
					if i%2 == 0 {
						table.set(lan)
					} else {
						table.forget(lan)
					}
					f.trigger = "routes"
					if err := f.reconcile(); err != nil {
						b.Fatal(err)
					}
				}
			}
			if moved := slices.IndexFunc(backend.entries(), func(entry string) bool { return strings.HasPrefix(entry, "fill") }); moved >= 0 {
				b.Fatalf("a pass moved a set: %s", backend.entries()[moved])
			}
		})
	}
}
