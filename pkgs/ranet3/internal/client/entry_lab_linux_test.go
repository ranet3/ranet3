// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

// entryDrop is mesh_entry's counted drop of each family, as the border's debug read names it
var entryDrop = map[int]string{4: "drop ipv4 entering the mesh", 6: "drop ipv6 entering the mesh"}

var (
	// entryPeer is a mesh peer inside the overlay, and entrySubnet a host of the subnet the mesh routes outside it
	entryPeer   = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.5/32"), 6: netip.MustParsePrefix("3fff::5/128")}
	entrySubnet = map[int]netip.Addr{4: netip.MustParseAddr("203.0.113.40"), 6: netip.MustParseAddr("2001:db8:300::4")}
	// entryNeighbor is an address on the tun's link no host holds
	entryNeighbor = netip.MustParseAddr("fe80::5")
)

// entryProbe is a datagram a host of the lab sends, numbered by its source port, whether mesh_entry lets it into the tun,
// from source where source is valid, and whether its send fails with EPERM, as a drop on the host's own output path fails it
type entryProbe struct {
	name   string
	from   *netnstest.Thread
	family int
	// send opens a socket in from's namespace and sends datagram n, answering the socket still open
	send    func(n int) (int, error)
	enters  bool
	refused bool
	source  netip.Addr
}

// entryUDP is a probe from host's socket of kind socket to destination
func entryUDP(name string, host *netnstest.Thread, socket rulesSocket, destination netip.Addr, enters, refused bool, source netip.Addr) entryProbe {
	family := 6
	if destination.Is4() {
		family = 4
	}
	return entryProbe{
		name: fmt.Sprintf("%s's datagram from a socket %s to %s", name, socket, destination), from: host, family: family,
		enters: enters, refused: refused, source: source,
		send: func(n int) (int, error) {
			fd, outcome, err := rulesSend(rulesProbe{destination, socket, "", 0}, "udp", n)
			switch outcome {
			case rulesUnreachable:
				return -1, fmt.Errorf("the route to %s refused it", destination)
			case rulesSwitchRefused:
				// rulesSend names every EPERM the switch's, and mesh_entry's drop refuses a send with EPERM too
				return -1, unix.EPERM
			}
			return fd, err
		},
	}
}

// entrySent is a probe sent, its number, its socket still open, and whether its send failed with EPERM
type entrySent struct {
	probe   entryProbe
	number  int
	fd      int
	refused bool
}

// entrySend sends each probe, numbering them on from next
func entrySend(t *testing.T, probes []entryProbe, next *int) []entrySent {
	t.Helper()
	var out []entrySent
	for _, p := range probes {
		*next++
		s := entrySent{probe: p, number: *next, fd: -1}
		if err := p.from.Do(func() error {
			fd, err := p.send(s.number)
			if errors.Is(err, unix.EPERM) {
				s.refused = true
				return nil
			}
			s.fd = fd
			return err
		}); err != nil {
			t.Fatalf("send %s: %v", p.name, err)
		}
		if s.fd >= 0 {
			t.Cleanup(func() { _ = unix.Close(s.fd) })
		}
		out = append(out, s)
	}
	return out
}

// entryCheck reads the tun's capture and fails each probe that entered it where it must not or did not where it must,
// entered from another source, or met EPERM other than it must. It answers the probes of each family that must stay out,
// and what else the capture read.
func entryCheck(t *testing.T, capture int, sent []entrySent) (map[int]uint64, switchSeen) {
	t.Helper()
	intoTun, seen := switchDrain(capture)
	out := map[int]uint64{}
	for _, s := range sent {
		source, entered := intoTun[rulesKey{"udp", s.number}]
		switch {
		case s.refused != s.probe.refused:
			t.Errorf("%s met EPERM %v, want %v", s.probe.name, s.refused, s.probe.refused)
		case entered != s.probe.enters:
			t.Errorf("%s entered the tun %v from %s, want %v", s.probe.name, entered, source, s.probe.enters)
		case entered && s.probe.source.IsValid() && source != s.probe.source:
			t.Errorf("%s entered the tun from %s, want %s", s.probe.name, source, s.probe.source)
		}
		if !s.probe.enters {
			out[s.probe.family]++
		}
	}
	return out, seen
}

// entryDropped is mesh_entry's drops of each family, read now
func entryDropped(t *testing.T, ns *netnstest.Thread, border *kernelexit.BorderFilter) map[int]uint64 {
	t.Helper()
	return map[int]uint64{4: borderDropped(t, ns, border, entryDrop[4]), 6: borderDropped(t, ns, border, entryDrop[6])}
}

// entryMoved fails the test where mesh_entry's drops of a family moved from before by other than want
func entryMoved(t *testing.T, before, after, want map[int]uint64) {
	t.Helper()
	for _, family := range []int{4, 6} {
		if after[family]-before[family] != want[family] {
			t.Errorf("mesh_entry dropped %d IPv%d packets, want %d", after[family]-before[family], family, want[family])
		}
	}
}

// entryBorder starts node's border filter in ns as main builds it, and runs it until the test ends
func entryBorder(t *testing.T, ns *netnstest.Thread, node *Client) *kernelexit.BorderFilter {
	t.Helper()
	var border *kernelexit.BorderFilter
	if err := ns.Do(func() (err error) {
		border, err = kernelexit.NewBorderFilter(node.config().Cap.Border, node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("start the border: %v", err)
	}
	entryRun(t, border)
	return border
}

// entryRun runs border until the test ends, then withdraws it
func entryRun(t *testing.T, border *kernelexit.BorderFilter) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := border.Run(ctx); err != nil {
			t.Errorf("the border: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// entryElements is the set name as the border's last pass asked for it
func entryElements(border *kernelexit.BorderFilter, name string) []egress.Range {
	for _, set := range border.Stats().Sets {
		if set.Name == name {
			return set.Elements
		}
	}
	return nil
}

// entrySetHolds reports whether the set name, as the border's last pass asked for it, holds address
func entrySetHolds(border *kernelexit.BorderFilter, name string, address netip.Addr) bool {
	return slices.ContainsFunc(entryElements(border, name), func(r egress.Range) bool {
		return r.First.Compare(address) <= 0 && address.Compare(r.Last) <= 0
	})
}

// entryCaughtUp waits until the border's last pass asked for the owned and none sets node derives now
func entryCaughtUp(t *testing.T, border *kernelexit.BorderFilter, node *Client) {
	t.Helper()
	waitFor(t, rulesSettle, "the border's sets to follow the mesh's table", func() bool {
		derived := node.borderSets()
		for name, ranges := range map[string][]egress.Range{"owned": derived.Owned, "none": derived.None} {
			for _, family := range []int{4, 6} {
				want := slices.DeleteFunc(slices.Clone(ranges), func(r egress.Range) bool { return r.First.Is4() != (family == 4) })
				if !slices.Equal(entryElements(border, fmt.Sprintf("%s%d", name, family)), want) {
					return false
				}
			}
		}
		return true
	})
}

// entrySet is the name of set's family of address
func entrySet(set string, address netip.Addr) string {
	if address.Is4() {
		return set + "4"
	}
	return set + "6"
}

// entryFarRoutes routes the peer and the subnet through the leaf at the far host, as any host on the uplink's network can
func entryFarRoutes(t *testing.T, far *netnstest.Thread) {
	t.Helper()
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		link, err := net.InterfaceByName(rulesFar)
		if err != nil {
			return err
		}
		var errs []error
		for _, family := range []int{4, 6} {
			for _, to := range []netip.Prefix{entryPeer[family], exitLabHost[family].subnet.Masked()} {
				errs = append(errs, netlink.RouteVia(link.Index, to, rulesHost[family].uplink.Addr()))
			}
		}
		return errors.Join(errs...)
	}); err != nil {
		t.Fatalf("route the mesh's peer and subnet through the leaf at the far host: %v", err)
	}
}

// a leaf in mode off forwarding for a stranger beyond its uplink, a LAN host and a container behind a bridge masqueraded at srcnat as
// Docker does, with its border running: the stranger's datagrams to a mesh peer and a mesh subnet and the unannounced LAN host's stay
// out of the tun, the container's enters translated to the tun's own address, the host's own unbound and overlay-bound sockets' enter
// from that address, and its socket bound to the uplink's address meets EPERM, each family's drops counted. With the LAN announced
// its host's datagram enters from its own address.
func TestTUNEntryTakesFromAForwardingHostOnlyWhatItOwns(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := newExitLab(t)
	d := startExitDaemon(t, lab.leaf)
	masqueradeBridge(t, lab.leaf)
	entryFarRoutes(t, lab.far)
	for _, family := range []int{4, 6} {
		d.node.Mesh.Routes.Set(netip.Prefix{}, entryPeer[family], d.learned)
		d.node.Mesh.Routes.Set(netip.Prefix{}, exitLabHost[family].subnet, d.learned)
	}
	waitFor(t, rulesSettle, "the mesh's table routing the peer and the subnet into the tun", func() bool {
		for _, family := range []int{4, 6} {
			if !labMeshRoute(t, lab.leaf, entryPeer[family]) || !labMeshRoute(t, lab.leaf, exitLabHost[family].subnet) {
				return false
			}
		}
		return true
	})
	border := entryBorder(t, lab.leaf, d.node)
	entryCaughtUp(t, border, d.node)
	var capture int
	if err := lab.leaf.Do(func() (err error) { capture, err = openCapture(rulesTUN, labRetry); return err }); err != nil {
		t.Fatalf("capture the tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })

	probes := func(announced bool) []entryProbe {
		var out []entryProbe
		for _, family := range []int{4, 6} {
			own, subnet, peer, lanHost := rulesHost[family].own.Addr(), entrySubnet[family], entryPeer[family].Addr(), exitLabHost[family].lanHost.Addr()
			out = append(out,
				entryUDP("the stranger", lab.far, rulesUnbound, subnet, false, false, netip.Addr{}),
				entryUDP("the stranger", lab.far, rulesUnbound, peer, false, false, netip.Addr{}),
				entryUDP("the LAN host", lab.lan, rulesUnbound, subnet, announced, false, lanHost),
				entryUDP("the container", lab.container, rulesUnbound, subnet, true, false, own),
				entryUDP("the host", lab.leaf, rulesUnbound, subnet, true, false, own),
				entryUDP("the host", lab.leaf, rulesFromOverlay, peer, true, false, own),
				entryUDP("the host", lab.leaf, rulesFromUplink, subnet, false, true, netip.Addr{}))
		}
		return out
	}
	next := 0
	exercise := func(t *testing.T, announced bool) {
		switchDrain(capture)
		before := entryDropped(t, lab.leaf, border)
		kept, _ := entryCheck(t, capture, entrySend(t, probes(announced), &next))
		entryMoved(t, before, entryDropped(t, lab.leaf, border), kept)
	}
	t.Run("the LAN unannounced", func(t *testing.T) { exercise(t, false) })
	for _, family := range []int{4, 6} {
		lan := exitLabHost[family].lan.Masked()
		d.node.Mesh.Routes.Set(netip.Prefix{}, lan, netstack.Local)
		t.Cleanup(func() { d.node.Mesh.Routes.Remove(netip.Prefix{}, lan) })
	}
	entryCaughtUp(t, border, d.node)
	t.Run("the LAN announced", func(t *testing.T) { exercise(t, true) })
}

// entryNotrack is the lab's chain at prerouting at raw's priority, which marks notrack each UDP datagram arriving on the uplink,
// as another program's notrack rule may
var entryNotrack = nftables.Chain{Table: "entrylabraw", Name: "notrack", Type: "filter", Hook: unix.NF_INET_PRE_ROUTING, Priority: -300}

// entryUntrack writes entryNotrack on the leaf, counting what it marks, deleted when the test ends
func entryUntrack(t *testing.T, leaf *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		rule, err := entryNotrack.Rule(unix.NFPROTO_INET, "notrack udp from the uplink", slices.Concat(
			nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rulesUplink),
			nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{unix.IPPROTO_UDP}),
			[][]byte{nftables.Expression("counter", nil), nftables.Expression("notrack", nil)}))
		if err != nil {
			return err
		}
		return conn.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, entryNotrack.Table), entryNotrack.Create(unix.NFPROTO_INET), rule})
	}); err != nil {
		t.Fatalf("write the lab's notrack chain: %v", err)
	}
	t.Cleanup(func() {
		if err := leaf.Do(func() error { return labDeleteTable(unix.NFPROTO_INET, entryNotrack.Table) }); err != nil {
			t.Errorf("delete the lab's notrack chain: %v", err)
		}
	})
}

// entryUntracked is the datagrams entryNotrack has marked, read now
func entryUntracked(t *testing.T, leaf *netnstest.Thread) uint64 {
	t.Helper()
	var out uint64
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		read, err := nftables.Contents{Chains: []nftables.Chain{entryNotrack}}.Read(conn, map[uint8]uint32{unix.NFPROTO_INET: 0}, unix.NFPROTO_INET)
		for _, rule := range read.Rules {
			out += rule.Packets
		}
		return err
	}); err != nil {
		t.Fatalf("read the lab's notrack chain: %v", err)
	}
	return out
}

// a leaf in mode off forwarding for a stranger beyond its uplink, with the lab's notrack chain marking the stranger's datagrams
// untracked before conntrack: an untracked datagram matches no reply line, so the stranger's datagrams to a mesh peer and a mesh
// subnet stay out of the tun, each counted by mesh_entry's drop of its family
func TestTUNEntryKeepsAnUntrackedStrangersDatagramOut(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := newExitLab(t)
	d := startExitDaemon(t, lab.leaf)
	entryFarRoutes(t, lab.far)
	for _, family := range []int{4, 6} {
		d.node.Mesh.Routes.Set(netip.Prefix{}, entryPeer[family], d.learned)
		d.node.Mesh.Routes.Set(netip.Prefix{}, exitLabHost[family].subnet, d.learned)
	}
	waitFor(t, rulesSettle, "the mesh's table routing the peer and the subnet into the tun", func() bool {
		for _, family := range []int{4, 6} {
			if !labMeshRoute(t, lab.leaf, entryPeer[family]) || !labMeshRoute(t, lab.leaf, exitLabHost[family].subnet) {
				return false
			}
		}
		return true
	})
	border := entryBorder(t, lab.leaf, d.node)
	entryCaughtUp(t, border, d.node)
	entryUntrack(t, lab.leaf)
	var capture int
	if err := lab.leaf.Do(func() (err error) { capture, err = openCapture(rulesTUN, labRetry); return err }); err != nil {
		t.Fatalf("capture the tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })
	var probes []entryProbe
	for _, family := range []int{4, 6} {
		probes = append(probes,
			entryUDP("the untracked stranger", lab.far, rulesUnbound, entrySubnet[family], false, false, netip.Addr{}),
			entryUDP("the untracked stranger", lab.far, rulesUnbound, entryPeer[family].Addr(), false, false, netip.Addr{}))
	}
	switchDrain(capture)
	before, marked := entryDropped(t, lab.leaf, border), entryUntracked(t, lab.leaf)
	next := 0
	kept, _ := entryCheck(t, capture, entrySend(t, probes, &next))
	entryMoved(t, before, entryDropped(t, lab.leaf, border), kept)
	if got := entryUntracked(t, lab.leaf) - marked; got < uint64(len(probes)) {
		t.Errorf("the lab's notrack chain marked %d datagrams, want the %d the stranger sent", got, len(probes))
	}
}

// entryAfter is the lab's chain after the kill switch's at postrouting, counting the UDP each family sends into the tun, and
// entryForward its chain at forward, counting the UDP the tun forwards to the LAN in each conntrack direction
var (
	entryAfter   = nftables.Chain{Table: "entrylab", Name: "after", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483647}
	entryForward = nftables.Chain{Table: "entrylab", Name: "forward", Type: "filter", Hook: unix.NF_INET_FORWARD, Priority: 0}
)

// entryCounters writes the lab's chains on the leaf, deleted when the test ends
func entryCounters(t *testing.T, leaf *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, entryAfter.Table), entryAfter.Create(unix.NFPROTO_INET), entryForward.Create(unix.NFPROTO_INET)}
		counter := [][]byte{nftables.Expression("counter", nil)}
		for _, family := range []int{4, 6} {
			proto := uint8(unix.NFPROTO_IPV6)
			if family == 4 {
				proto = unix.NFPROTO_IPV4
			}
			udp := slices.Concat(nftables.NFProto(proto), nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{unix.IPPROTO_UDP}))
			into, err := entryAfter.Rule(unix.NFPROTO_INET, fmt.Sprintf("ipv%d udp into the tun", family),
				slices.Concat(nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_EQ, rulesTUN), udp, counter))
			if err != nil {
				return err
			}
			requests = append(requests, into)
			for _, direction := range []struct {
				name  string
				value uint8
			}{{"original", nftables.CTOriginal}, {"reply", nftables.CTReply}} {
				forwarded, err := entryForward.Rule(unix.NFPROTO_INET, fmt.Sprintf("ipv%d udp to the lan in its %s direction", family, direction.name), slices.Concat(
					nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rulesTUN), nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_EQ, exitLAN), udp,
					[][]byte{nftables.CTLoad(unix.NFT_CT_DIRECTION), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{direction.value}))}, counter))
				if err != nil {
					return err
				}
				requests = append(requests, forwarded)
			}
		}
		return conn.Batch(requests)
	}); err != nil {
		t.Fatalf("write the lab's counting chains: %v", err)
	}
	t.Cleanup(func() {
		if err := leaf.Do(func() error { return labDeleteTable(unix.NFPROTO_INET, entryAfter.Table) }); err != nil {
			t.Errorf("delete the lab's counting chains: %v", err)
		}
	})
}

// entryCounted is the packets of each rule of the lab's chains, read now
func entryCounted(t *testing.T, leaf *netnstest.Thread) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		read, err := nftables.Contents{Chains: []nftables.Chain{entryAfter, entryForward}}.Read(conn, map[uint8]uint32{unix.NFPROTO_INET: 0}, unix.NFPROTO_INET)
		for _, rule := range read.Rules {
			out[rule.Spec] = rule.Packets
		}
		return err
	}); err != nil {
		t.Fatalf("read the lab's counting chains: %v", err)
	}
	return out
}

// entrySwitchDrops is the packets the last line of each chain of the kill switch's table has dropped, by chain, read now
func entrySwitchDrops(t *testing.T, leaf *netnstest.Thread) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	if err := leaf.Do(func() error {
		read, err := kernel.ReadFallback()
		for _, rule := range read.Rules {
			if rule.Spec == "counter drop" {
				out[rule.Chain] = rule.Packets
			}
		}
		return err
	}); err != nil {
		t.Fatalf("read the kill switch's table: %v", err)
	}
	return out
}

// entryLinkLocal is the tun's link-local address, once the kernel gave it one, and the tun's index
func entryLinkLocal(t *testing.T, leaf *netnstest.Thread) (netip.Addr, int) {
	t.Helper()
	var address netip.Addr
	var index int
	waitFor(t, rulesSettle, "the tun's link-local address", func() bool {
		_ = leaf.Do(func() error {
			link, err := net.InterfaceByName(rulesTUN)
			if err != nil {
				return err
			}
			held, err := link.Addrs()
			for _, one := range held {
				if prefix, err := netip.ParsePrefix(one.String()); err == nil && prefix.Addr().IsLinkLocalUnicast() {
					address, index = prefix.Addr(), link.Index
				}
			}
			return err
		})
		return address.IsValid()
	})
	return address, index
}

// entryToNeighbor is a probe of the host's datagram from the tun's link-local address local to entryNeighbor over the tun
func entryToNeighbor(leaf *netnstest.Thread, local netip.Addr, index int) entryProbe {
	return entryProbe{
		name: "the host's datagram from " + local.String() + " to " + entryNeighbor.String(), from: leaf, family: 6, enters: true, source: local,
		send: func(n int) (int, error) {
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return -1, err
			}
			if err := unix.Bind(fd, &unix.SockaddrInet6{Port: rulesPortBase + n, Addr: local.As16(), ZoneId: uint32(index)}); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			to := &unix.SockaddrInet6{Port: rulesDiscard, Addr: entryNeighbor.As16(), ZoneId: uint32(index)}
			if err := unix.Sendto(fd, []byte(fmt.Sprintf("probe %d", n)), 0, to); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			return fd, nil
		},
	}
}

// entrySolicit sends a neighbor solicitation of entryNeighbor over the tun from local, to its solicited-node group
func entrySolicit(local netip.Addr, index int) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := errors.Join(unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255),
		unix.Bind(fd, &unix.SockaddrInet6{Addr: local.As16(), ZoneId: uint32(index)})); err != nil {
		return err
	}
	// a neighbor solicitation of RFC 4861 section 4.3, its checksum written by the kernel, sent to the target's
	// solicited-node multicast address of RFC 4291 section 2.7.1
	target := entryNeighbor.As16()
	solicitation := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, target[:]...)
	group := [16]byte{0xff, 0x02, 11: 0x01, 12: 0xff, 13: target[13], 14: target[14], 15: target[15]}
	return unix.Sendto(fd, solicitation, 0, &unix.SockaddrInet6{Addr: group, ZoneId: uint32(index)})
}

// a leaf in mode 2 with fallback = "none", forwarding its announced LAN untranslated beside its border, with the mesh's defaults present:
// the LAN host's datagrams to the internet enter the tun from its own address, the exit's replies written into the tun reach its
// socket as conntrack's replies, the host's unbound socket enters from the tun's own address, its datagram to a neighbor's link-local
// address and its neighbor solicitation enter from the tun's link-local one, and the stranger's datagrams to the mesh's peer and subnet
// stay out, counted. The kill switch's chain at postrouting runs after mesh_entry and its chain at output before it, and neither
// drops anything here: a chain after both counts in the tun what mesh_entry passed alone, and both chains' drops stay as they were.
func TestTUNEntryPassesASubnetRoutersLANAndItsRepliesBesideTheKillSwitch(t *testing.T) {
	lab := newSwitchLab(t)
	entryFarRoutes(t, lab.far)
	for _, family := range []int{4, 6} {
		lan := exitLabHost[family].lan.Masked()
		lab.d.node.Mesh.Routes.Set(netip.Prefix{}, lan, netstack.Local)
		t.Cleanup(func() { lab.d.node.Mesh.Routes.Remove(netip.Prefix{}, lan) })
	}
	border := entryBorder(t, lab.leaf, lab.d.node)
	lab.settle(t, switchArm{name: "a subnet router", state: switchPresent, forward: []string{exitLAN}})
	entryCaughtUp(t, border, lab.d.node)
	entryCounters(t, lab.leaf)
	local, index := entryLinkLocal(t, lab.leaf)

	var probes []entryProbe
	for _, family := range []int{4, 6} {
		own, internet, lanHost := rulesHost[family].own.Addr(), exitLabHost[family].internet.Addr(), exitLabHost[family].lanHost.Addr()
		probes = append(probes,
			entryUDP("the LAN host", lab.lan, rulesUnbound, internet, true, false, lanHost),
			entryUDP("the host", lab.leaf, rulesUnbound, entrySubnet[family], true, false, own),
			entryUDP("the stranger", lab.far, rulesUnbound, entrySubnet[family], false, false, netip.Addr{}),
			entryUDP("the stranger", lab.far, rulesUnbound, entryPeer[family].Addr(), false, false, netip.Addr{}))
	}
	probes = append(probes, entryToNeighbor(lab.leaf, local, index))
	switchDrain(lab.tunCapture)
	before, counted, switched := entryDropped(t, lab.leaf, border), entryCounted(t, lab.leaf), entrySwitchDrops(t, lab.leaf)
	if len(switched) != 2 {
		t.Fatalf("the kill switch's table holds a drop in the chains %v, want fallback and output", switched)
	}
	next := lab.probe
	sent := entrySend(t, probes, &next)
	if err := lab.leaf.Do(func() error { return entrySolicit(local, index) }); err != nil {
		t.Errorf("solicit %s over the tun from %s: %v", entryNeighbor, local, err)
	}

	// the exit answers each of the LAN host's datagrams through the mesh, from the internet host it was sent to
	for _, s := range sent {
		if s.probe.from != lab.lan || s.fd < 0 {
			continue
		}
		internet, lanHost := exitLabHost[s.probe.family].internet.Addr(), exitLabHost[s.probe.family].lanHost.Addr()
		reply := []byte(fmt.Sprintf("reply %d", s.number))
		lab.d.node.Mesh.DeliverInbound(udpPacket(internet, lanHost, rulesDiscard, uint16(rulesPortBase+s.number), reply), 0)
		timeout := unix.NsecToTimeval(exitPingWait.Nanoseconds())
		buf := make([]byte, 1500)
		n, err := 0, unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
		if err == nil {
			n, _, err = unix.Recvfrom(s.fd, buf, 0)
		}
		if err != nil || string(buf[:n]) != string(reply) {
			t.Errorf("the LAN host's socket read %q (%v) of the exit's reply from %s, want %q", buf[:n], err, internet, reply)
		}
	}

	kept, seen := entryCheck(t, lab.tunCapture, sent)
	if !seen.solicited[entryNeighbor] {
		t.Errorf("no neighbor solicitation of %s entered the tun", entryNeighbor)
	}
	entryMoved(t, before, entryDropped(t, lab.leaf, border), kept)
	now := entryCounted(t, lab.leaf)
	for _, family := range []int{4, 6} {
		var entered uint64
		for _, s := range sent {
			if s.probe.family == family && s.probe.enters {
				entered++
			}
		}
		into := fmt.Sprintf("ipv%d udp into the tun", family)
		if got := now[into] - counted[into]; got != entered {
			t.Errorf("past the kill switch the tun took %d IPv%d datagrams, want the %d mesh_entry passed", got, family, entered)
		}
		for direction, want := range map[string]uint64{"original": 0, "reply": 1} {
			spec := fmt.Sprintf("ipv%d udp to the lan in its %s direction", family, direction)
			if got := now[spec] - counted[spec]; got != want {
				t.Errorf("the tun forwarded %d IPv%d datagrams to the LAN in their %s direction, want %d", got, family, direction, want)
			}
		}
	}
	if now := entrySwitchDrops(t, lab.leaf); !maps.Equal(now, switched) {
		t.Errorf("the kill switch's chains dropped %v, then %v, where mesh_entry alone keeps the stranger out", switched, now)
	}
	if state := lab.switchStatus(); state != "passing" {
		t.Errorf("the kill switch reads %s, want passing", state)
	}
}

// entryBlock is a block outside the overlay an exit translates none, entryOtherLAN another node's LAN inside it, entryOutside a
// mesh subnet outside every class, and entryLearned a LAN another node comes to advertise inside the block
var (
	entryBlock    = map[int]netip.Prefix{4: netip.MustParsePrefix("198.51.100.0/25"), 6: netip.MustParsePrefix("2001:db8:76::/47")}
	entryOtherLAN = map[int]netip.Prefix{4: netip.MustParsePrefix("198.51.100.64/26"), 6: netip.MustParsePrefix("2001:db8:77::/64")}
	entryOutside  = map[int]netip.Prefix{4: netip.MustParsePrefix("198.51.100.192/26"), 6: netip.MustParsePrefix("2001:db8:300::/64")}
	entryLearned  = map[int]netip.Prefix{4: netip.MustParsePrefix("198.51.100.32/27"), 6: netip.MustParsePrefix("2001:db8:76:5::/64")}
)

// entryNoneClasses is an exit's none classes beside its leaves': the overlay whole and the block
func entryNoneClasses() []egress.Class {
	var out []egress.Class
	for _, prefix := range []string{"203.0.113.0/24", "3fff::/20", entryBlock[4].String(), entryBlock[6].String()} {
		out = append(out, egress.Class{From: schema.MustPrefix(prefix), To: egress.Translation{None: true}})
	}
	return out
}

// the labs' exit with its none classes, written without cap.border and so with no local segment, advertising the defaults
// instead, is refused at load for its first none class: without the overlay its none sets would leave out the leaves' own
// addresses, which the mesh's table holds learned as it holds another node's LAN
func TestEntryLabsExitIsRefusedWithoutTheBorder(t *testing.T) {
	cfg := labConfig(t)
	exit := *cfg.Cap.Egress
	exit.Advertise = []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
	exit.Translate = entryNoneClasses()
	cfg.Cap.Egress, cfg.Cap.Border, cfg.Cap.Segment = &exit, nil, nil
	const says = "config: cap.egress translate class 203.0.113.0/24 is none and cap.border is absent"
	if err := cfg.Validate(); err == nil || !strings.HasPrefix(err.Error(), says) {
		t.Fatalf("the labs' exit without cap.border was refused with %v, want %q", err, says)
	}
}

// entryRouter is a synthetic peer advertising LANs to the exit
func entryRouter(t *testing.T) *netstack.Peer {
	t.Helper()
	router := netstack.NewPeer("example/router", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the router is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(router.Close)
	return router
}

// entryExitAddress is the exit's end of the uplink in each family
var entryExitAddress = map[int]netip.Addr{4: labExit4.Addr(), 6: labExit6.Addr()}

// an exit whose none classes cover the overlay and a block holding another node's LAN, with a mesh subnet outside them: an internet
// host's datagram to a leaf enters the tun, and its datagrams to the LAN host and to the subnet stay out, counted
func TestTUNEntryAtAnExitPassesItsNoneClassesLessAnotherNodesLAN(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := startBorderLab(t, entryNoneClasses()...)
	router := entryRouter(t)
	for _, family := range []int{4, 6} {
		for _, prefix := range []netip.Prefix{entryOtherLAN[family], entryOutside[family]} {
			lab.node.Mesh.Routes.Set(netip.Prefix{}, prefix, router)
			lab.routeFar(t, prefix, entryExitAddress[family])
		}
	}
	waitFor(t, convergeBudget, "the mesh's table routing the LAN and the subnet", func() bool {
		for _, family := range []int{4, 6} {
			if !labMeshRoute(t, lab.exit, entryOtherLAN[family]) || !labMeshRoute(t, lab.exit, entryOutside[family]) {
				return false
			}
		}
		return true
	})
	entryCaughtUp(t, lab.border, lab.node)
	far, leaves := map[int]netip.Addr{4: labFar4.Addr(), 6: labFar6.Addr()}, map[int]netip.Addr{4: labLeaf4, 6: labHeadend}
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("an internet host's datagram to the leaf over IPv%d", family), func(t *testing.T) {
			payload := []byte(fmt.Sprintf("from the internet to the leaf over IPv%d", family))
			labCaptureReply(t, lab.capture, leaves[family], payload, lab.sender(t, far[family], leaves[family], payload))
		})
		for _, to := range []struct {
			name string
			host netip.Addr
		}{{"another node's LAN", entryOtherLAN[family].Addr().Next()}, {"a mesh subnet outside the classes", entryOutside[family].Addr().Next()}} {
			t.Run(fmt.Sprintf("an internet host's datagram to %s over IPv%d", to.name, family), func(t *testing.T) {
				payload := []byte(fmt.Sprintf("from the internet to %s over IPv%d", to.name, family))
				before := lab.dropped(t, entryDrop[family])
				lab.quiet(t, payload, labReplyTo(to.host, payload), lab.sender(t, far[family], to.host, payload))
				lab.counts(t, entryDrop[family], before)
			})
		}
	}
}

const (
	// entryTrials is how many times each family's LAN is learned and forgotten
	entryTrials = 5
	// entrySpray is the gap between two of a stranger's datagrams to a LAN while it is learned or forgotten
	entrySpray = 200 * time.Microsecond
	// entrySettle is the reconciler's settleDelay, the window one settle holds open
	entrySettle = 250 * time.Millisecond
)

// entryRace learns prefix from router, or forgets it, while a stranger beyond the uplink sends to its first host every entrySpray.
// It answers when the mesh's table came to hold the route as the change asks, when the none set came to say so, how many datagrams
// went, and the send time of each that entered the tun, each from the change. A zero time is one that never came within rulesSettle.
func entryRace(t *testing.T, lab *borderLab, router *netstack.Peer, prefix netip.Prefix, learn bool, trial int) (route, set time.Duration, sent int, entered []time.Duration) {
	t.Helper()
	host, family := prefix.Addr().Next(), 6
	if host.Is4() {
		family = 4
	}
	from := map[int]netip.Addr{4: labFar4.Addr(), 6: labFar6.Addr()}[family]
	var conn *net.UDPConn
	if err := lab.far.Do(func() (err error) {
		conn, err = net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, labLeafPort)))
		return err
	}); err != nil {
		t.Fatalf("open the stranger's socket: %v", err)
	}
	defer conn.Close()
	switchDrain(lab.capture)
	label := fmt.Sprintf("race %d %v ", trial, learn)
	stop := make(chan struct{})
	var sentAt []time.Duration
	var spraying sync.WaitGroup
	start := time.Now()
	spraying.Go(func() {
		for seq := 0; ; seq++ {
			select {
			case <-stop:
				return
			default:
			}
			sentAt = append(sentAt, time.Since(start))
			// a send the kernel refuses is a datagram that never left, which the capture reads as such
			_, _ = conn.Write([]byte(label + strconv.Itoa(seq)))
			time.Sleep(entrySpray)
		}
	})
	if learn {
		lab.node.Mesh.Routes.Set(netip.Prefix{}, prefix, router)
	} else {
		lab.node.Mesh.Routes.Remove(netip.Prefix{}, prefix)
	}
	none := entrySet("none", host)
	for deadline := start.Add(rulesSettle); (route == 0 || set == 0) && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if route == 0 && labMeshRoute(t, lab.exit, prefix) == learn {
			route = time.Since(start)
		}
		if set == 0 && entrySetHolds(lab.border, none, host) != learn {
			set = time.Since(start)
		}
	}
	time.Sleep(entrySettle)
	close(stop)
	spraying.Wait()
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(lab.capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			break
		}
		to, _, payload, ok := labUDPOf(buf[:n])
		if !ok || to != host {
			continue
		}
		if rest, found := strings.CutPrefix(string(payload), label); found {
			if seq, err := strconv.Atoi(rest); err == nil && seq < len(sentAt) {
				entered = append(entered, sentAt[seq])
			}
		}
	}
	return route, set, len(sentAt), entered
}

// at an exit whose none classes cover a block, a LAN another node comes to advertise inside the block leaves the none set before the
// mesh's table routes it into the tun, while a stranger beyond the uplink sends to it, so none of the stranger's datagrams enters
// the tun on a learn, and a LAN no node advertises any more comes back into the set at most one settle after its route goes. The
// test logs, for each learn and each forget, when the route and the set moved and the stranger's datagrams that entered the tun.
func TestTUNEntryClosesALearnedLANWithinOneSettle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := startBorderLab(t, entryNoneClasses()...)
	router := entryRouter(t)
	for _, family := range []int{4, 6} {
		lab.routeFar(t, entryLearned[family], entryExitAddress[family])
	}
	waitFor(t, convergeBudget, "the none sets holding the block", func() bool {
		return entrySetHolds(lab.border, "none4", entryLearned[4].Addr().Next()) && entrySetHolds(lab.border, "none6", entryLearned[6].Addr().Next())
	})
	for trial := range entryTrials {
		for _, family := range []int{4, 6} {
			for _, learn := range []bool{true, false} {
				prefix := entryLearned[family]
				route, set, sent, entered := entryRace(t, lab, router, prefix, learn, trial)
				change := "learned"
				if !learn {
					change = "forgotten"
				}
				var span string
				if len(entered) > 0 {
					span = fmt.Sprintf(", sent from %v to %v", entered[0], entered[len(entered)-1])
				}
				t.Logf("IPv%d LAN %s, trial %d: the route at %v, the none set at %v, %d of %d datagrams entered the tun%s",
					family, change, trial, route, set, len(entered), sent, span)
				if route == 0 || set == 0 {
					t.Fatalf("the %s LAN %s left the route at %v and the none set at %v within %s", change, prefix, route, set, rulesSettle)
				}
				switch {
				case learn && len(entered) > 0:
					t.Errorf("a stranger's datagrams to the learned LAN %s entered the tun %d times, the first sent %v after the change", prefix, len(entered), entered[0])
				case learn && set > route:
					t.Errorf("the learned LAN %s left the none set %v after its route came", prefix, set-route)
				case !learn && set-route > entrySettle:
					t.Errorf("the forgotten LAN %s came back into the none set %v after its route went, past one settle of %v", prefix, set-route, entrySettle)
				}
			}
		}
	}
}

// entryHelperNamespace names the namespace TestEntryLabCrashHelper joins
const entryHelperNamespace = "RANET3_ENTRY_LAB_NAMESPACE"

// the crash helper of TestTUNEntryTableOutlivesAKilledNode, which starts the rules lab's node and its border in the namespace
// entryHelperNamespace names and waits to be killed
func TestEntryLabCrashHelper(t *testing.T) {
	path := os.Getenv(entryHelperNamespace)
	if path == "" {
		t.Skip("TestTUNEntryTableOutlivesAKilledNode runs the crash helper in a process of its own")
	}
	leaf := netnstest.JoinThread(t, path)
	cfg := rulesConfig(t)
	if err := leaf.Do(func() error {
		node, err := New(cfg, events.New())
		if err != nil {
			return err
		}
		_, err = kernelexit.NewBorderFilter(cfg.Cap.Border, node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("written")
	// the parent kills this process, and a parent gone before it closes stdin
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// startEntryHelper runs TestEntryLabCrashHelper in a process of its own in leaf's namespace until it wrote the table, and
// answers what kills it with SIGKILL
func startEntryHelper(t *testing.T, leaf *netnstest.Thread) func() {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(executable, "-test.run=^TestEntryLabCrashHelper$", "-test.v")
	helper.Env = append(os.Environ(), entryHelperNamespace+"="+leaf.Path)
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatalf("start the crash helper: %v", err)
	}
	kill := sync.OnceFunc(func() {
		_ = helper.Process.Signal(unix.SIGKILL)
		_ = helper.Wait()
		_ = stdin.Close()
	})
	t.Cleanup(kill)
	var written []string
	for lines := bufio.NewScanner(stdout); !slices.Contains(written, "written") && lines.Scan(); {
		written = append(written, lines.Text())
	}
	if !slices.Contains(written, "written") {
		kill()
		t.Fatalf("the crash helper did not write the table:\n%s", strings.Join(written, "\n"))
	}
	return kill
}

// a node killed with SIGKILL leaves its border's table, which keeps dropping a datagram forged from an overlay source on the
// uplink in each family while the gateway's reaches the host's socket, and the next start adopts the table without a write,
// its counters holding the forged datagrams of both lives
func TestTUNEntryTableOutlivesAKilledNode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	var receiver *net.UDPConn
	if err := leaf.Do(func() (err error) {
		receiver, err = net.ListenUDP("udp", &net.UDPAddr{Port: carvePort})
		return err
	}); err != nil {
		t.Fatalf("listen on the leaf: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	forged := map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.77"), 6: netip.MustParseAddr("3fff::77")}
	// send has the gateway and a forger of an overlay source on the uplink each send the leaf a datagram, and checks that its
	// socket took the gateway's alone
	send := func(t *testing.T, when string) {
		t.Helper()
		var want []string
		if err := far.Do(func() error {
			for _, family := range []int{4, 6} {
				to := rulesHost[family].uplink.Addr()
				for _, from := range []netip.Addr{rulesHost[family].gateway.Addr(), forged[family]} {
					if err := carveSend(from, to, when+" from "+from.String()); err != nil {
						return err
					}
				}
				want = append(want, when+" from "+rulesHost[family].gateway.Addr().String())
			}
			return nil
		}); err != nil {
			t.Fatalf("send to the leaf from the uplink: %v", err)
		}
		var delivered []string
		buf := make([]byte, 256)
		if err := receiver.SetReadDeadline(time.Now().Add(labQuiet)); err != nil {
			t.Fatal(err)
		}
		for {
			n, _, err := receiver.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			delivered = append(delivered, string(buf[:n]))
		}
		slices.Sort(delivered)
		slices.Sort(want)
		if !slices.Equal(delivered, want) {
			t.Errorf("%s the leaf's socket took %q, want the gateway's datagram in each family alone", when, delivered)
		}
	}
	kill := startEntryHelper(t, leaf)
	send(t, "while the node ran")
	kill()
	send(t, "once the node was killed")

	bus := events.New()
	var node *Client
	var border *kernelexit.BorderFilter
	if err := leaf.Do(func() (err error) {
		if node, err = New(rulesConfig(t), bus); err != nil {
			return err
		}
		border, err = kernelexit.NewBorderFilter(node.config().Cap.Border, node.BorderRuntime())
		return err
	}); err != nil {
		if node != nil {
			node.Close()
		}
		t.Fatalf("start the node again: %v", err)
	}
	t.Cleanup(node.Close)
	if passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "border.pass" }, 0); len(passes) != 0 {
		t.Errorf("the start over the table a killed node left wrote it: %v", passes)
	}
	entryRun(t, border)
	for _, spec := range []string{"drop ipv4 source 192.0.2.0/24", "drop ipv6 source 3fff::/20"} {
		if got := borderDropped(t, leaf, border, spec); got != 2 {
			t.Errorf("the adopted table's %q counted %d, want the forged datagram of each life", spec, got)
		}
	}
}

// entryTooBig is the ICMP error a router beyond an exit sends about a datagram from source to destination, as the router read
// them: Fragmentation Needed over IPv4 (RFC 792) and Packet Too Big over IPv6 (RFC 4443 section 3.2), each with a next hop's MTU
// of 1280 and the datagram's headers
func entryTooBig(source, destination netip.AddrPort) []byte {
	inner := udpPacket(source.Addr(), destination.Addr(), source.Port(), destination.Port(), []byte("too big"))
	if source.Addr().Is4() {
		message := append([]byte{3, 4, 0, 0, 0, 0, 0x05, 0x00}, inner[:28]...)
		binary.BigEndian.PutUint16(message[2:], ^uint16(packet.Sum(0, message)))
		return message
	}
	// the kernel writes an ICMPv6 checksum
	return append([]byte{2, 0, 0, 0, 0, 0, 0x05, 0x00}, inner...)
}

// entrySendError sends message, an ICMP or ICMPv6 message of to's family, to to from the calling thread's namespace
func entrySendError(to netip.Addr, message []byte) error {
	family, protocol := unix.AF_INET6, unix.IPPROTO_ICMPV6
	if to.Is4() {
		family, protocol = unix.AF_INET, unix.IPPROTO_ICMP
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, message, 0, rulesSockaddr(to, 0))
}

// entryErrorTo takes an ICMP Fragmentation Needed or an ICMPv6 Packet Too Big to destination
func entryErrorTo(destination netip.Addr) func([]byte) bool {
	return func(raw []byte) bool {
		switch {
		case len(raw) >= 28 && raw[0]>>4 == 4 && raw[9] == unix.IPPROTO_ICMP:
			icmp := raw[int(raw[0]&0x0f)*4:]
			return netip.AddrFrom4([4]byte(raw[16:20])) == destination && len(icmp) >= 2 && icmp[0] == 3 && icmp[1] == 4
		case len(raw) >= 48 && raw[0]>>4 == 6 && raw[6] == unix.IPPROTO_ICMPV6:
			return netip.AddrFrom16([16]byte(raw[24:40])) == destination && raw[40] == 2
		}
		return false
	}
}
