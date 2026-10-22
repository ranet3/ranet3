// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// addressSettle is how long the test below gives the kernel to put an address on a link that has just gone up
const addressSettle = 500 * time.Millisecond

// the egress device is made up, at the mesh's MTU, with multicast off, no
// address of either family, not even the link-local the kernel adds at up,
// router advertisements refused and rp_filter off
// a device of its name already there, held open or left persistent, refuses
// another, and closing it removes the link
func TestTUNEgressDeviceIsMadeWithNoAddress(t *testing.T) {
	enterEmptyNamespace(t)
	// a new link takes conf.default, which set to 2 here leaves the daemon's own write the only way to 0
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("2"), 0); err != nil {
		t.Fatalf("set conf.default.rp_filter: %v", err)
	}
	const name = "egtest0e"
	dev, err := NewEgressDevice(name, DefaultMTU)
	if err != nil {
		t.Fatalf("make the egress device: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = dev.Close()
		}
	})
	time.Sleep(addressSettle)

	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	if link.Flags&net.FlagUp == 0 || link.Flags&net.FlagMulticast != 0 {
		t.Errorf("%s carries the flags %v, want up without multicast", name, link.Flags)
	}
	if link.MTU != DefaultMTU {
		t.Errorf("%s runs at an MTU of %d, want %d", name, link.MTU, DefaultMTU)
	}
	if addresses, err := link.Addrs(); err != nil || len(addresses) != 0 {
		t.Errorf("%s carries the addresses %v (%v), want none", name, addresses, err)
	}
	for path, want := range map[string]string{
		"/proc/sys/net/ipv6/conf/" + name + "/addr_gen_mode": "1",
		"/proc/sys/net/ipv6/conf/" + name + "/accept_ra":     "0",
		"/proc/sys/net/ipv4/conf/" + name + "/rp_filter":     "0",
	} {
		if body, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(body)) != want {
			t.Errorf("%s reads %q (%v), want %s", path, body, err, want)
		}
	}

	if second, err := NewEgressDevice(name, DefaultMTU); err == nil || !strings.Contains(err.Error(), "already exists, and the egress device is always created and never attached to") {
		if second != nil {
			_ = second.Close()
		}
		t.Errorf("a second egress device of the name was made or refused with %v", err)
	}

	closed = true
	if err := dev.Close(); err != nil {
		t.Fatalf("close the egress device: %v", err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Errorf("%s outlived its close", name)
	}

	// a persistent tun with no queue takes any attach that does not ask for a new device
	persistTUN(t, name, 0)
	if left, err := NewEgressDevice(name, DefaultMTU); err == nil || !strings.Contains(err.Error(), "already exists, and the egress device is always created and never attached to") {
		if left != nil {
			_ = left.Close()
		}
		t.Errorf("the egress device was attached to a persistent tun of its name or refused with %v", err)
	}
}

// ipv6DeviceStat reads one counter of the kernel's IPv6 statistics for the link name
func ipv6DeviceStat(t *testing.T, name, key string) uint64 {
	t.Helper()
	body, err := os.ReadFile("/proc/thread-self/net/dev_snmp6/" + name)
	if err != nil {
		t.Fatalf("read the IPv6 statistics of %s: %v", name, err)
	}
	for line := range strings.Lines(string(body)) {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == key {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("%s of %s reads %q: %v", key, name, fields[1], err)
			}
			return value
		}
	}
	t.Fatalf("the IPv6 statistics of %s hold no %s", name, key)
	return 0
}

// on a host whose new links take disable_ipv6 = 1 from conf.default, the
// egress device is made with IPv6 on, so the kernel takes the steered IPv6
// packet the mesh writes into it rather than discard it
func TestTUNEgressDeviceTakesIPv6WhereTheHostTurnsItOffForNewLinks(t *testing.T) {
	enterEmptyNamespace(t)
	for path, value := range map[string]string{
		"/proc/sys/net/ipv6/conf/default/disable_ipv6": "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":       "1",
	} {
		if err := os.WriteFile(path, []byte(value), 0); err != nil {
			t.Fatalf("set %s: %v", path, err)
		}
	}
	const name = "egv6test0e"
	dev, err := NewEgressDevice(name, DefaultMTU)
	if err != nil {
		t.Fatalf("make the egress device: %v", err)
	}
	m, err := NewNamed(DefaultMTU, "egv6mesh0", nil)
	if err != nil {
		_ = dev.Close()
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetSegments(egressTable(t))
	m.SetEgress(dev)
	m.SetEgressReady(true, true)
	routeLeaf(t, m, netip.MustParseAddr("3fff:1:69c:1::5"))
	path := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
	if body, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(body)) != "0" {
		t.Errorf("%s reads %q (%v), want 0", path, body, err)
	}

	received, discarded := ipv6DeviceStat(t, name, "Ip6InReceives"), ipv6DeviceStat(t, name, "Ip6InDiscards")
	inner := udpPacket(netip.MustParseAddr("3fff:1:69c:1::5"), netip.MustParseAddr("2001:db8:1::1"), 40+8+16, false)
	m.DeliverInboundBatch(framed(steered(t, inner, headend, egressExit)), DefaultMTU, nil)
	waitUntil(t, "the kernel to receive the steered IPv6 packet on the egress device", func() bool {
		return ipv6DeviceStat(t, name, "Ip6InReceives") > received
	})
	if got := ipv6DeviceStat(t, name, "Ip6InDiscards"); got != discarded {
		t.Errorf("the kernel discarded %d IPv6 packets arriving on the egress device, want none", got-discarded)
	}
	if counters := m.SegmentCounters(); counters.Egressed != 1 || counters.NotReady != 0 {
		t.Errorf("the steered IPv6 packet counted %+v, want 1 egressed", counters)
	}
}

// reportSettle is how long past the device's unsolicited report interval the test below waits for the kernel's last MLD report
const reportSettle = 500 * time.Millisecond

// the kernel's MLD reports out of the egress device, at start and after a
// disable_ipv6 put-back on a host forwarding IPv6, are drained uncounted, and
// so is a packet to a link-local multicast address, while a packet to a
// multicast address of wider scope and a unicast packet each count
func TestTUNEgressDrainCountsOnlyWhatARouteSends(t *testing.T) {
	enterEmptyNamespace(t)
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0); err != nil {
		t.Fatalf("turn IPv6 forwarding on: %v", err)
	}
	const name = "egdrain0e"
	dev, err := NewEgressDevice(name, DefaultMTU)
	if err != nil {
		t.Fatalf("make the egress device: %v", err)
	}
	m, err := NewNamed(DefaultMTU, "egdrain0", nil)
	if err != nil {
		_ = dev.Close()
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetEgress(dev)

	conf := "/proc/sys/net/ipv6/conf/" + name + "/"
	body, err := os.ReadFile(conf + "mldv2_unsolicited_report_interval")
	if err != nil {
		t.Fatalf("read the device's unsolicited report interval: %v", err)
	}
	interval, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("the device's unsolicited report interval reads %q: %v", body, err)
	}
	settle := time.Duration(interval)*time.Millisecond + reportSettle
	time.Sleep(settle)
	if drained := m.SegmentCounters().Drained; drained != 0 {
		t.Errorf("drained reads %d after start, want 0", drained)
	}
	for _, value := range []string{"1", "0"} {
		if err := os.WriteFile(conf+"disable_ipv6", []byte(value), 0); err != nil {
			t.Fatalf("set disable_ipv6 to %s: %v", value, err)
		}
	}
	time.Sleep(settle)
	if drained := m.SegmentCounters().Drained; drained != 0 {
		t.Errorf("drained reads %d after disable_ipv6 went to 1 and back to 0, want 0", drained)
	}

	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	ipv6 := uint16(unix.ETH_P_IPV6)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(ipv6<<8|ipv6>>8))
	if err != nil {
		t.Fatalf("open an AF_PACKET socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	source := netip.MustParseAddr("2001:db8:1::5")
	// the device's one queue is read in order, so a packet that counts shows the drain read every packet sent before it
	for _, packet := range []struct {
		destination string
		drained     uint64
	}{
		{"ff02::1", 0},
		{"ff0e::1", 1},
		{"2001:db8:2::1", 2},
	} {
		raw := udpPacket(source, netip.MustParseAddr(packet.destination), 40+8+16, false)
		if err := unix.Sendto(fd, raw, 0, &unix.SockaddrLinklayer{Protocol: ipv6<<8 | ipv6>>8, Ifindex: link.Index}); err != nil {
			t.Fatalf("send a packet to %s out of %s: %v", packet.destination, name, err)
		}
		if packet.drained == 0 {
			continue
		}
		waitUntil(t, "the drain to count the packet to "+packet.destination, func() bool {
			return m.SegmentCounters().Drained >= packet.drained
		})
		if drained := m.SegmentCounters().Drained; drained != packet.drained {
			t.Errorf("drained reads %d after the packet to %s, want %d", drained, packet.destination, packet.drained)
		}
	}
}
