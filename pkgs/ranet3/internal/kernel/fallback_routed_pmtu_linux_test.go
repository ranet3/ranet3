// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// The router itself has an own-prefix source, but the live UDP connection
// quoted by its real PMTU error has neither endpoint in the protected set.
// The error therefore reaches form e rather than an inbound-service line,
// and the outside client acts on it before completing a smaller exchange.
func TestNetlinkFallbackRoutedRelatedRouterPMTU(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			_, client, _, server := routedServiceSwitch(t)
			const port = 54321
			var sender, listener *net.UDPConn
			if err := client.Do(func() (err error) {
				sender, err = net.DialUDP(family.network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.outsideServer.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			if err := server.Do(func() (err error) {
				listener, err = net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.outsideServer.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if family.outsideServer.Addr().Is4() {
				routedServiceSocket(t, sender, func(fd int) error {
					return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				})
			}
			if mtu := routedServiceMTU(t, sender, family); mtu <= 1280 {
				t.Fatalf("the first path MTU is %d, want greater than the router's 1280", mtu)
			}
			trace := routedTraceFor(t, 2)
			before := routedCounters(t)
			if n, err := sender.Write(bytes.Repeat([]byte{'x'}, 1400)); err != nil || n != 1400 {
				t.Fatalf("the first datagram wrote %d bytes (%v), want the oversized request", n, err)
			}
			waitFor(t, func() bool { return routedServiceMTU(t, sender, family) == 1280 })
			after := routedCounters(t)
			icmp4, icmp6 := uint64(0), uint64(0)
			first, form := "ip saddr != @from4 accept", "icmp errors 3/11/12 related outside from4 counter accept"
			if family.outsideServer.Addr().Is6() {
				icmp6 = 1
				first, form = "ip6 saddr != @from6 accept", "icmpv6 errors 1-4 related outside from6 counter accept"
			} else {
				icmp4 = 1
			}
			if after.drop != before.drop || after.icmp4-before.icmp4 != icmp4 || after.icmp6-before.icmp6 != icmp6 {
				t.Errorf("the router's related error changed forward counters from %+v to %+v, want a single form-e accept in this family", before, after)
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "request outside the class", in: "ranetup0", source: family.client.Addr().String(), target: family.outsideServer.Addr().String(), first: first, pass: true},
				{name: "related router PMTU error", in: "ranetother0", source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: form, pass: true},
			})
			routedServiceSocket(t, sender, func(fd int) error {
				pending, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if err != nil {
					return err
				}
				if pending != int(unix.EMSGSIZE) {
					return fmt.Errorf("pending socket error %d, want EMSGSIZE", pending)
				}
				return nil
			})
			payload := bytes.Repeat([]byte{'f'}, 1000)
			if n, err := sender.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("the fitted request wrote %d bytes (%v), want %d", n, err, len(payload))
			}
			if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1100)
			n, address, err := listener.ReadFromUDP(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("the outside server read %d bytes (%v), want the fitted request", n, err)
			}
			if _, err := listener.WriteToUDP([]byte("done"), address); err != nil {
				t.Fatal(err)
			}
			if err := sender.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			n, err = sender.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], []byte("done")) {
				t.Errorf("the client read %q (%v), want the completed exchange", buf[:n], err)
			}
		})
	}
}

// A second router sits outside the protected source set, between the switch
// and a second address of the client. Only this path has a narrow client-side
// link. An own-prefix reply therefore reaches that router before its PMTU
// error returns to the own-prefix server through the switch.
func routedServiceOutsideRouter(t *testing.T, family routedServiceFamily, client, ownRouter, server *netnstest.Thread) (netip.Addr, netip.Addr) {
	t.Helper()
	edge := netnstest.StartThread(t)
	routedServiceAtOnce(t, edge)
	root, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	if err := root.AddVeth("ranetedge0", "edge0", 0, edge.Path); err != nil {
		t.Fatal(err)
	}
	in := func(ns *netnstest.Thread, action func(netnstest.Netlink) error) {
		t.Helper()
		if err := ns.Do(func() error {
			conn, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer conn.Close()
			return action(conn)
		}); err != nil {
			t.Fatal(err)
		}
	}
	in(edge, func(conn netnstest.Netlink) error {
		return conn.AddVeth("edge1", "client1", 1280, client.Path)
	})
	rootEdge, edgeNear, edgeFar, clientExtra := prefix("203.0.115.1/30"), prefix("203.0.115.2/30"), prefix("203.0.115.5/30"), prefix("203.0.115.6/30")
	if family.server.Addr().Is6() {
		rootEdge, edgeNear, edgeFar, clientExtra = prefix("2001:db8:bf::1/126"), prefix("2001:db8:bf::2/126"), prefix("2001:db8:bf::5/126"), prefix("2001:db8:bf::6/126")
	}
	hostBits := 32
	if clientExtra.Addr().Is6() {
		hostBits = 128
	}
	clientHost := netip.PrefixFrom(clientExtra.Addr(), hostBits)
	if err := root.AddAddresses("ranetedge0", rootEdge); err != nil {
		t.Fatal(err)
	}
	rootLink, err := net.InterfaceByName("ranetedge0")
	if err != nil {
		t.Fatal(err)
	}
	if err := root.RouteVia(rootLink.Index, clientHost, edgeNear.Addr()); err != nil {
		t.Fatal(err)
	}
	in(edge, func(conn netnstest.Netlink) error {
		if err := conn.AddAddresses("edge0", edgeNear); err != nil {
			return err
		}
		if err := conn.AddAddresses("edge1", edgeFar); err != nil {
			return err
		}
		link, err := net.InterfaceByName("edge0")
		if err != nil {
			return err
		}
		return conn.RouteVia(link.Index, family.serverNet, rootEdge.Addr())
	})
	in(client, func(conn netnstest.Netlink) error {
		if err := conn.AddAddresses("client1", clientExtra); err != nil {
			return err
		}
		link, err := net.InterfaceByName("client1")
		if err != nil {
			return err
		}
		return conn.RouteVia(link.Index, family.serverNet, edgeFar.Addr())
	})
	in(ownRouter, func(conn netnstest.Netlink) error {
		link, err := net.InterfaceByName("router0")
		if err != nil {
			return err
		}
		if err := conn.RouteVia(link.Index, clientHost, family.rootNear.Addr()); err != nil {
			return err
		}
		if err := conn.RouteVia(link.Index, edgeNear.Masked(), family.rootNear.Addr()); err != nil {
			return err
		}
		far, err := net.InterfaceByName("router1")
		if err != nil {
			return err
		}
		return netnstest.SetLinkMTU(far.Index, 1500)
	})
	in(server, func(conn netnstest.Netlink) error {
		link, err := net.InterfaceByName("server0")
		if err != nil {
			return err
		}
		if err := conn.RouteVia(link.Index, clientHost, family.routerFar.Addr()); err != nil {
			return err
		}
		if err := conn.RouteVia(link.Index, edgeNear.Masked(), family.routerFar.Addr()); err != nil {
			return err
		}
		return netnstest.SetLinkMTU(link.Index, 1500)
	})
	if err := edge.Do(func() error {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return clientExtra.Addr(), edgeNear.Addr()
}

// A client-side router outside the protected set quotes a listed own-prefix
// server's oversized reply. Its real PMTU error crosses this switch toward
// that server, passes the earlier outside-source line and changes the
// server's actual path MTU before a smaller reply reaches the client.
func TestNetlinkFallbackRoutedOutsideRouterPMTU(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			_, client, ownRouter, server := routedServiceSwitch(t)
			extra, edgeSource := routedServiceOutsideRouter(t, family, client, ownRouter, server)
			const port = 53
			var sender, listener *net.UDPConn
			if err := client.Do(func() (err error) {
				sender, err = net.DialUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(extra, 0)),
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			if err := server.Do(func() (err error) {
				listener, err = net.DialUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), port)), sender.LocalAddr().(*net.UDPAddr))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if family.server.Addr().Is4() {
				routedServiceSocket(t, listener, func(fd int) error {
					return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				})
			}
			if mtu := routedServiceMTU(t, listener, family); mtu <= 1280 {
				t.Fatalf("the server's first path MTU is %d, want greater than the client-side router's 1280", mtu)
			}
			trace := routedTraceFor(t, 3)
			before := routedCounters(t)
			if _, err := sender.Write([]byte("asked")); err != nil {
				t.Fatal(err)
			}
			if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1100)
			if n, err := listener.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("asked")) {
				t.Fatalf("the server read %q (%v), want the client's request", buf[:n], err)
			}
			if n, err := listener.Write(bytes.Repeat([]byte{'x'}, 1400)); err != nil || n != 1400 {
				t.Fatalf("the server's oversized reply wrote %d bytes (%v), want 1400", n, err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for routedServiceMTU(t, listener, family) != 1280 {
				if time.Now().After(deadline) {
					t.Fatalf("the outside router left the server's PMTU at %d; counters %+v; trace:\n%s",
						routedServiceMTU(t, listener, family), routedCounters(t), trace())
				}
				time.Sleep(10 * time.Millisecond)
			}
			after := routedCounters(t)
			if after != before {
				t.Errorf("the outside router's PMTU error changed forward counters from %+v to %+v, want no form-e accept or drop", before, after)
			}
			outside := "ip saddr != @from4 accept"
			if family.server.Addr().Is6() {
				outside = "ip6 saddr != @from6 accept"
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "client request", in: "ranetedge0", source: extra.String(), target: family.server.Addr().String(), first: outside, pass: true},
				{name: "server reply", in: "ranetother0", source: family.server.Addr().String(), target: extra.String(), first: "ct direction reply ct protocol udp ct original proto-dst @udpports accept", pass: true},
				{name: "outside router PMTU error", in: "ranetedge0", source: edgeSource.String(), target: family.server.Addr().String(), first: outside, pass: true},
			})
			routedServiceSocket(t, listener, func(fd int) error {
				pending, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if err != nil {
					return err
				}
				if pending != int(unix.EMSGSIZE) {
					return fmt.Errorf("pending socket error %d, want EMSGSIZE", pending)
				}
				return nil
			})
			payload := bytes.Repeat([]byte{'f'}, 1000)
			if n, err := listener.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("the fitted reply wrote %d bytes (%v), want %d", n, err, len(payload))
			}
			if err := sender.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := sender.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
				t.Errorf("the client read %d bytes (%v), want the completed fitted reply", n, err)
			}
		})
	}
}

// An outside server opens the flow, so the oversized client reply and the
// router's resulting error use the opposite conntrack directions from the
// preceding PMTU case. Both quoted endpoints remain outside the source set.
// The real error still takes form e and lowers the replying client's PMTU.
func TestNetlinkFallbackRoutedRelatedRouterPMTUInOriginalDirection(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			_, client, _, server := routedServiceSwitch(t)
			const port = 54321
			var opener, replier *net.UDPConn
			if err := server.Do(func() (err error) {
				opener, err = net.DialUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.outsideServer.Addr(), 0)),
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opener.Close() })
			if err := client.Do(func() (err error) {
				replier, err = net.DialUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)), opener.LocalAddr().(*net.UDPAddr))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = replier.Close() })
			if family.server.Addr().Is4() {
				routedServiceSocket(t, replier, func(fd int) error {
					return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				})
			}
			if mtu := routedServiceMTU(t, replier, family); mtu <= 1280 {
				t.Fatalf("the client's first path MTU is %d, want greater than the router's 1280", mtu)
			}
			trace := routedTraceFor(t, 3)
			before := routedCounters(t)
			if _, err := opener.Write([]byte("opened")); err != nil {
				t.Fatal(err)
			}
			if err := replier.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1100)
			if n, err := replier.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("opened")) {
				t.Fatalf("the outside client read %q (%v), want the server's opening request", buf[:n], err)
			}
			if n, err := replier.Write(bytes.Repeat([]byte{'x'}, 1400)); err != nil || n != 1400 {
				t.Fatalf("the client's oversized reply wrote %d bytes (%v), want 1400", n, err)
			}
			waitFor(t, func() bool { return routedServiceMTU(t, replier, family) == 1280 })
			after := routedCounters(t)
			icmp4, icmp6 := uint64(1), uint64(0)
			outside, form := "ip saddr != @from4 accept", "icmp errors 3/11/12 related outside from4 counter accept"
			if family.server.Addr().Is6() {
				icmp4, icmp6 = 0, 1
				outside, form = "ip6 saddr != @from6 accept", "icmpv6 errors 1-4 related outside from6 counter accept"
			}
			if after.drop != before.drop || after.icmp4-before.icmp4 != icmp4 || after.icmp6-before.icmp6 != icmp6 {
				t.Errorf("the router's original-direction error changed forward counters from %+v to %+v, want one form-e accept", before, after)
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "server opening request", in: "ranetother0", source: family.outsideServer.Addr().String(), target: family.client.Addr().String(), first: outside, pass: true},
				{name: "client oversized reply", in: "ranetup0", source: family.client.Addr().String(), target: family.outsideServer.Addr().String(), first: outside, pass: true},
				{name: "router error in the original direction", in: "ranetother0", source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: form, pass: true},
			})
			routedServiceSocket(t, replier, func(fd int) error {
				pending, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if err != nil {
					return err
				}
				if pending != int(unix.EMSGSIZE) {
					return fmt.Errorf("pending socket error %d, want EMSGSIZE", pending)
				}
				return nil
			})
			payload := bytes.Repeat([]byte{'f'}, 1000)
			if n, err := replier.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("the fitted reply wrote %d bytes (%v), want %d", n, err, len(payload))
			}
			if err := opener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := opener.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("the outside server read %d bytes (%v), want the fitted reply", n, err)
			}
			if _, err := opener.Write([]byte("done")); err != nil {
				t.Fatal(err)
			}
			if err := replier.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := replier.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("done")) {
				t.Errorf("the outside client read %q (%v), want the completed exchange", buf[:n], err)
			}
		})
	}
}

// A router with no route to an outside destination generates its own
// Destination Unreachable for a live UDP request. The own-prefix error
// crosses this node toward the outside client, meets form e and reaches the
// client's error queue with the kernel's actual type and code.
func TestNetlinkFallbackRoutedRelatedRouterUnreachable(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			_, client, _, _ := routedServiceSwitch(t)
			destination := prefix("203.0.116.9/32")
			if family.server.Addr().Is6() {
				destination = prefix("2001:db8:c0::9/128")
			}
			root, err := netnstest.OpenNetlink()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(root.Close)
			near, err := net.InterfaceByName("ranetother0")
			if err != nil {
				t.Fatal(err)
			}
			if err := root.RouteVia(near.Index, destination, family.routerNear.Addr()); err != nil {
				t.Fatal(err)
			}
			if err := client.Do(func() error {
				conn, err := netnstest.OpenNetlink()
				if err != nil {
					return err
				}
				defer conn.Close()
				link, err := net.InterfaceByName("client0")
				if err != nil {
					return err
				}
				return conn.RouteVia(link.Index, destination, family.rootUp.Addr())
			}); err != nil {
				t.Fatal(err)
			}
			var sender *net.UDPConn
			if err := client.Do(func() (err error) {
				sender, err = net.DialUDP(family.network, nil,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination.Addr(), 54321)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			level, option := unix.IPPROTO_IP, unix.IP_RECVERR
			if family.server.Addr().Is6() {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
			}
			routedServiceSocket(t, sender, func(fd int) error {
				return unix.SetsockoptInt(fd, level, option, 1)
			})
			trace := routedTraceFor(t, 2)
			before := routedCounters(t)
			if _, err := sender.Write([]byte("no route beyond the router")); err != nil {
				t.Fatal(err)
			}
			kind, code := routedServiceQueuedError(t, sender, family)
			after := routedCounters(t)
			wantKind, wantCode := byte(3), byte(0)
			icmp4, icmp6 := uint64(1), uint64(0)
			outside, form := "ip saddr != @from4 accept", "icmp errors 3/11/12 related outside from4 counter accept"
			if family.server.Addr().Is6() {
				wantKind, icmp4, icmp6 = 1, 0, 1
				outside, form = "ip6 saddr != @from6 accept", "icmpv6 errors 1-4 related outside from6 counter accept"
			}
			if kind != wantKind || code != wantCode {
				t.Errorf("the client's error queue gave type %d code %d, want router-generated type %d code %d", kind, code, wantKind, wantCode)
			}
			if after.drop != before.drop || after.icmp4-before.icmp4 != icmp4 || after.icmp6-before.icmp6 != icmp6 {
				t.Errorf("the router's unreachable changed forward counters from %+v to %+v, want one form-e accept", before, after)
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "client request without a downstream route", in: "ranetup0",
					source: family.client.Addr().String(), target: destination.Addr().String(), first: outside, pass: true},
				{name: "router unreachable to the outside client", in: "ranetother0",
					source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: form, pass: true},
			})
		})
	}
}

// An ordinary outside client's expiring UDP request meets the own-prefix
// router after the flow has been confirmed. The router-generated Time
// Exceeded takes form e in both families and reaches the real client's
// socket error queue with the expected type and code.
func TestNetlinkFallbackRoutedRelatedRouterTimeExceeded(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			_, client, _, server := routedServiceSwitch(t)
			const port = 54321
			var sender, listener *net.UDPConn
			if err := client.Do(func() (err error) {
				sender, err = net.DialUDP(family.network, nil,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.outsideServer.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			if err := server.Do(func() (err error) {
				listener, err = net.ListenUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.outsideServer.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if _, err := sender.Write([]byte("opened")); err != nil {
				t.Fatal(err)
			}
			if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, peer, err := listener.ReadFromUDP(buf)
			if err != nil || !bytes.Equal(buf[:n], []byte("opened")) {
				t.Fatalf("the outside server read %q (%v), want the opening request", buf[:n], err)
			}
			if _, err := listener.WriteToUDP([]byte("answered"), peer); err != nil {
				t.Fatal(err)
			}
			if err := sender.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := sender.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("answered")) {
				t.Fatalf("the client read %q (%v), want the confirmed response", buf[:n], err)
			}
			level, hopOption, errorOption, wantKind := unix.IPPROTO_IP, unix.IP_TTL, unix.IP_RECVERR, byte(11)
			if family.server.Addr().Is6() {
				level, hopOption, errorOption, wantKind = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, unix.IPV6_RECVERR, 3
			}
			routedServiceSocket(t, sender, func(fd int) error {
				return errors.Join(unix.SetsockoptInt(fd, level, errorOption, 1), unix.SetsockoptInt(fd, level, hopOption, 2))
			})
			trace := routedTraceFor(t, 2)
			before := routedCounters(t)
			if _, err := sender.Write([]byte("expires at the router")); err != nil {
				t.Fatal(err)
			}
			kind, code := routedServiceQueuedError(t, sender, family)
			after := routedCounters(t)
			icmp4, icmp6 := uint64(1), uint64(0)
			outside, form := "ip saddr != @from4 accept", "icmp errors 3/11/12 related outside from4 counter accept"
			if family.server.Addr().Is6() {
				icmp4, icmp6 = 0, 1
				outside, form = "ip6 saddr != @from6 accept", "icmpv6 errors 1-4 related outside from6 counter accept"
			}
			if kind != wantKind || code != 0 {
				t.Errorf("the client's error queue gave type %d code %d, want Time Exceeded type %d code 0", kind, code, wantKind)
			}
			if after.drop != before.drop || after.icmp4-before.icmp4 != icmp4 || after.icmp6-before.icmp6 != icmp6 {
				t.Errorf("the router's Time Exceeded changed forward counters from %+v to %+v, want one form-e accept", before, after)
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "client request with short hop limit", in: "ranetup0",
					source: family.client.Addr().String(), target: family.outsideServer.Addr().String(), first: outside, pass: true},
				{name: "router's related Time Exceeded", in: "ranetother0",
					source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: form, pass: true},
			})
		})
	}
}
