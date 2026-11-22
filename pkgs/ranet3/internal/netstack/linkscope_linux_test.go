// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// stateSettle is how far apart two reads of the tun's state have to agree before a test takes it as settled
const stateSettle = 100 * time.Millisecond

// a session's router advertisement to the tun's own link-local address, from a link-local source at hop limit 255, the one RFC 4861 section 6.1.2 accepts
// leaves the host's routes, the tun's addresses and its IPv6 MTU and hop limit as they were, on a tun at the kernel's neighbor discovery defaults
// on a tun whose kernel would ignore the advertisement it fails rather than pass, since the state then shows nothing
func TestSessionRouterAdvertisementLeavesTheTunAsItWas(t *testing.T) {
	netnstest.EnterEmpty(t)
	m, err := NewNamed(DefaultMTU, "scope0", false, nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	own := segPrefix("3fff::1/64")
	assignIPv6(t, m.Name, own)
	m.Routes.Set(netip.Prefix{}, hostPrefix(own.Addr()), Local)
	from := (&recordingPeer{}).peer(t, "from")
	var linkLocal netip.Addr
	waitUntil(t, "the tun's link-local address and its local route", func() bool {
		linkLocal = tunLinkLocal(t, m.Name)
		return linkLocal.IsValid() && hasLocalRoute(t, linkLocal)
	})
	// the kernel's first check: it takes a router advertisement where accept_ra is set on a link that does not forward, and where it is 2 on one that does, include/net/ipv6.h's ipv6_accept_ra
	// past it each change the state records has a setting of its own
	// where accept_ra_defrtr, accept_ra_pinfo, accept_ra_mtu and accept_ra_min_hop_limit keep all four off, the counter line below still catches a forwarded advertisement
	if accept, forwarding := tunConf(t, m.Name, "accept_ra"), tunConf(t, m.Name, "forwarding"); forwarding == "0" && accept == "0" || forwarding != "0" && accept != "2" {
		t.Fatalf("the tun's accept_ra is %s and its forwarding %s, so the kernel would ignore a router advertisement and the state would show nothing", accept, forwarding)
	}
	before := settledState(t, m.Name)
	received := tunReceived(t, m.Name)

	router := segAddr("fe80::99")
	m.DeliverInboundBatch(framed(routerAdvertisement(router, linkLocal, 255)), DefaultMTU, from, nil)
	// the decision counts the packet before a lane writes it, and the tun counts a write once the kernel's receive path has run on it, drivers/net/tun.c's tun_get_user
	if m.TransitCounters().Delivered != 0 {
		waitUntil(t, "the tun to count the router advertisement", func() bool { return tunReceived(t, m.Name) > received })
	}
	if after := tunState(t, m.Name); !slices.Equal(after, before) {
		t.Errorf("a router advertisement from %s to the tun's link-local address changed the host's state on the tun:\n%s", router, strings.Join(stateChanges(before, after), "\n"))
	}
	if got := m.TransitCounters(); got.Martian != 1 || got.Delivered != 0 {
		t.Errorf("the router advertisement counted %+v, want martian", got)
	}
}

// tunLinkLocal is the link-local address of the link name, the zero address while it has none
func tunLinkLocal(t *testing.T, name string) netip.Addr {
	t.Helper()
	for _, f := range procFields(t, "/proc/thread-self/net/if_inet6") {
		// the address in hex, the link index, the prefix length, the scope, the flags and the link name, net/ipv6/addrconf.c's if6_seq_show
		if len(f) != 6 || f[5] != name || f[3] != "20" {
			continue
		}
		var raw [16]byte
		for i := range raw {
			b, err := strconv.ParseUint(f[0][2*i:2*i+2], 16, 8)
			if err != nil {
				t.Fatalf("read the address %s of %s: %v", f[0], name, err)
			}
			raw[i] = byte(b)
		}
		return netip.AddrFrom16(raw)
	}
	return netip.Addr{}
}

// tunState lists the state a router advertisement the kernel takes on the link name changes
// every IPv6 route of every table, the link's IPv6 addresses, and its IPv6 MTU and hop limit
// a route's reference and use counts are left out, which traffic moves
func tunState(t *testing.T, name string) []string {
	t.Helper()
	var state []string
	for _, f := range procFields(t, "/proc/thread-self/net/ipv6_route") {
		// the destination, its length, the source, its length, the next hop, the metric, the reference and use counts, the flags and the link, net/ipv6/route.c's rt6_info_seq_show
		if len(f) == 10 {
			state = append(state, "route "+strings.Join(slices.Concat(f[:6], f[8:]), " "))
		}
	}
	for _, f := range procFields(t, "/proc/thread-self/net/if_inet6") {
		if len(f) == 6 && f[5] == name {
			state = append(state, "address "+strings.Join(f[:5], " "))
		}
	}
	for _, key := range []string{"mtu", "hop_limit"} {
		state = append(state, key+" "+tunConf(t, name, key))
	}
	slices.Sort(state)
	return state
}

// tunConf is the IPv6 setting key of the link name
func tunConf(t *testing.T, name, key string) string {
	t.Helper()
	value, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/" + key)
	if err != nil {
		t.Fatalf("read the %s of %s: %v", key, name, err)
	}
	return strings.TrimSpace(string(value))
}

// settledState is tunState once two reads stateSettle apart agree
func settledState(t *testing.T, name string) []string {
	t.Helper()
	state := tunState(t, name)
	for deadline := time.Now().Add(deliveryTimeout); ; {
		time.Sleep(stateSettle)
		now := tunState(t, name)
		if slices.Equal(now, state) {
			return now
		}
		if time.Now().After(deadline) {
			t.Fatalf("the state of %s kept changing for %s:\n%s", name, deliveryTimeout, strings.Join(stateChanges(state, now), "\n"))
		}
		state = now
	}
}

// stateChanges lists the lines of before that after lacks and the lines after adds
func stateChanges(before, after []string) []string {
	var changes []string
	for _, line := range before {
		if !slices.Contains(after, line) {
			changes = append(changes, "- "+line)
		}
	}
	for _, line := range after {
		if !slices.Contains(before, line) {
			changes = append(changes, "+ "+line)
		}
	}
	return changes
}

// tunReceived is the count of packets the link name received, written into it by the mesh
func tunReceived(t *testing.T, name string) uint64 {
	t.Helper()
	for _, f := range procFields(t, "/proc/thread-self/net/dev") {
		// the link name and its colon, then the received bytes and packets first, net/core/net-procfs.c's dev_seq_printf_stats
		if len(f) > 2 && f[0] == name+":" {
			n, err := strconv.ParseUint(f[2], 10, 64)
			if err != nil {
				t.Fatalf("read the packets %s received: %v", name, err)
			}
			return n
		}
	}
	t.Fatalf("%s is not in this namespace's link statistics", name)
	return 0
}

// procFields is the lines of the proc file at path, each split at its spaces
func procFields(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		lines = append(lines, strings.Fields(line))
	}
	return lines
}
