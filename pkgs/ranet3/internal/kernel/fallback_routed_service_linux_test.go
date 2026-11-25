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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// routedServiceFamily places the client outside the destination exceptions,
// the router and one server address inside the protected source set, and a
// second address of the same server outside it.
type routedServiceFamily struct {
	name, network                                           string
	rootUp, client, rootNear, routerNear, routerFar, server netip.Prefix
	clientNet, ownNet, serverNet                            netip.Prefix
	outsideRouterFar, outsideServer, outsideNet             netip.Prefix
}

var routedServiceFamilies = []routedServiceFamily{
	{
		name: "IPv4", network: "udp4",
		rootUp: prefix("198.51.100.129/25"), client: prefix("198.51.100.200/25"),
		rootNear: prefix("192.0.2.1/30"), routerNear: prefix("192.0.2.2/30"),
		routerFar: prefix("192.0.2.9/30"), server: prefix("192.0.2.10/30"),
		clientNet: prefix("198.51.100.128/25"), ownNet: prefix("192.0.2.0/25"), serverNet: prefix("192.0.2.8/30"),
		outsideRouterFar: prefix("203.0.114.9/30"), outsideServer: prefix("203.0.114.10/30"), outsideNet: prefix("203.0.114.8/30"),
	},
	{
		name: "IPv6", network: "udp6",
		rootUp: prefix("2001:db8:e::1/64"), client: prefix("2001:db8:e::200/64"),
		rootNear: prefix("3fff:1::1/126"), routerNear: prefix("3fff:1::2/126"),
		routerFar: prefix("3fff:1::9/126"), server: prefix("3fff:1::a/126"),
		clientNet: prefix("2001:db8:e::/64"), ownNet: prefix("3fff:1::/64"), serverNet: prefix("3fff:1::8/126"),
		outsideRouterFar: prefix("2001:db8:be::9/126"), outsideServer: prefix("2001:db8:be::a/126"), outsideNet: prefix("2001:db8:be::8/126"),
	},
}

// The client reaches an own-prefix server through this node and its router.
// All three links and the kernel's forwarding live in disposable namespaces.
func routedServiceSwitch(t *testing.T) (*netlinkPlatform, *netnstest.Thread, *netnstest.Thread, *netnstest.Thread) {
	t.Helper()
	plat := rootRulePlatform(t, fallbackSample.tun)
	client, router, server := netnstest.StartThread(t), netnstest.StartThread(t), netnstest.StartThread(t)
	writeBatchSysctl(t, "ipv6/conf/default/accept_dad", "0")
	for _, ns := range []*netnstest.Thread{client, router, server} {
		routedServiceAtOnce(t, ns)
	}
	root, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	if err := root.AddVeth("ranetup0", "client0", 0, client.Path); err != nil {
		t.Fatal(err)
	}
	if err := root.AddVeth("ranetother0", "router0", 0, router.Path); err != nil {
		t.Fatal(err)
	}
	in := func(ns *netnstest.Thread, name string, action func(netnstest.Netlink) error) {
		t.Helper()
		if err := ns.Do(func() error {
			conn, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer conn.Close()
			return action(conn)
		}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	in(router, "router link", func(conn netnstest.Netlink) error {
		return conn.AddVeth("router1", "server0", 1280, server.Path)
	})
	for _, family := range routedServiceFamilies {
		for _, link := range []struct {
			name    string
			address netip.Prefix
		}{{"ranetup0", family.rootUp}, {"ranetother0", family.rootNear}} {
			if err := root.AddAddresses(link.name, link.address); err != nil {
				t.Fatal(err)
			}
		}
		near, err := net.InterfaceByName("ranetother0")
		if err != nil {
			t.Fatal(err)
		}
		if err := root.RouteVia(near.Index, family.serverNet, family.routerNear.Addr()); err != nil {
			t.Fatal(err)
		}
		if err := root.RouteVia(near.Index, family.outsideNet, family.routerNear.Addr()); err != nil {
			t.Fatal(err)
		}
		in(client, "client routes", func(conn netnstest.Netlink) error {
			if err := conn.AddAddresses("client0", family.client); err != nil {
				return err
			}
			link, err := net.InterfaceByName("client0")
			if err != nil {
				return err
			}
			return errors.Join(conn.RouteVia(link.Index, family.ownNet, family.rootUp.Addr()),
				conn.RouteVia(link.Index, family.outsideNet, family.rootUp.Addr()))
		})
		in(router, "router routes", func(conn netnstest.Netlink) error {
			if err := conn.AddAddresses("router0", family.routerNear); err != nil {
				return err
			}
			if err := conn.AddAddresses("router1", family.routerFar); err != nil {
				return err
			}
			if err := conn.AddAddresses("router1", family.outsideRouterFar); err != nil {
				return err
			}
			link, err := net.InterfaceByName("router0")
			if err != nil {
				return err
			}
			return conn.RouteVia(link.Index, family.clientNet, family.rootNear.Addr())
		})
		in(server, "server routes", func(conn netnstest.Netlink) error {
			if err := conn.AddAddresses("server0", family.server); err != nil {
				return err
			}
			if err := conn.AddAddresses("server0", family.outsideServer); err != nil {
				return err
			}
			link, err := net.InterfaceByName("server0")
			if err != nil {
				return err
			}
			return conn.RouteVia(link.Index, family.clientNet, family.routerFar.Addr())
		})
	}
	for _, path := range []string{"ipv4/ip_forward", "ipv6/conf/all/forwarding"} {
		writeBatchSysctl(t, path, "1")
	}
	for _, name := range []string{"all", "default", "ranetup0", "ranetother0"} {
		writeBatchSysctl(t, "ipv4/conf/"+name+"/rp_filter", "0")
	}
	in(router, "router forwarding", func(netnstest.Netlink) error {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		return nil
	})
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	return plat, client, router, server
}

// routedServiceAtOnce has every link made in ns from now on skip duplicate
// address detection, as the switch's own namespace does. While a link's
// link-local address is tentative, the kernel sends no neighbor solicitation
// for a packet it forwards out of that link (ndisc_send_ns in ndisc.c), so the
// first packets of a flow wait out the solicitation's retransmit or are lost.
func routedServiceAtOnce(t *testing.T, ns *netnstest.Thread) {
	t.Helper()
	if err := ns.Do(func() error {
		return os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0o644)
	}); err != nil {
		t.Fatalf("have new links skip duplicate address detection: %v", err)
	}
}

// A subtest has a new goroutine. Its trace and counter sockets must join the
// parent thread's network namespace, not the outer test process's.
func routedServiceJoin(t *testing.T, path string) {
	t.Helper()
	runtime.LockOSThread()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	_ = unix.Close(fd)
}

// A confirmed UDP request to a server behind an own-prefix router passes
// from outside the source set. Its reply takes the inbound line only for the
// original destination port the switch lists. An unlisted server still gets
// the request, but its reply meets the counted forward drop.
func TestNetlinkFallbackRoutedUDPServiceReplies(t *testing.T) {
	_, client, _, server := routedServiceSwitch(t)
	// Each child joins this thread's namespace to observe the same switch.
	here := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
	for _, family := range routedServiceFamilies {
		for _, service := range []struct {
			name   string
			port   int
			listed bool
		}{{"listed", 53, true}, {"unlisted", 54321, false}} {
			t.Run(family.name+" "+service.name, func(t *testing.T) {
				routedServiceJoin(t, here)
				var sender, listener *net.UDPConn
				if err := client.Do(func() (err error) {
					sender, err = net.DialUDP(family.network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sender.Close() })
				if err := server.Do(func() (err error) {
					listener, err = net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				trace := routedTraceFor(t, 2)
				before := routedCounters(t)
				if _, err := sender.Write([]byte("asked")); err != nil {
					t.Fatal(err)
				}
				if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, address, err := listener.ReadFromUDP(buf)
				if err != nil || !bytes.Equal(buf[:n], []byte("asked")) {
					t.Fatalf("the own-prefix server read %q (%v), want the client's request", buf[:n], err)
				}
				if _, err := listener.WriteToUDP([]byte("answered"), address); err != nil {
					t.Fatal(err)
				}
				deadline := 350 * time.Millisecond
				if family.server.Addr().Is6() {
					// A newly addressed veth can still need neighbor
					// discovery for the server's first IPv6 reply.
					deadline = 3 * time.Second
				}
				if err := sender.SetReadDeadline(time.Now().Add(deadline)); err != nil {
					t.Fatal(err)
				}
				n, err = sender.Read(buf)
				if service.listed && (err != nil || !bytes.Equal(buf[:n], []byte("answered"))) {
					t.Errorf("the listed client's reply was %q (%v), want answered", buf[:n], err)
				} else if !service.listed {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Errorf("the unlisted client read %q (%v), want no reply", buf[:n], err)
					}
				}
				after := routedCounters(t)
				wantDrop := uint64(0)
				if !service.listed {
					wantDrop = 1
				}
				if after.drop-before.drop != wantDrop || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
					t.Errorf("forward counters changed from %+v to %+v, want %d drop and no error accept", before, after, wantDrop)
				}
				outside, reply := "ip saddr != @from4 accept", "ct direction reply ct protocol udp ct original proto-dst @udpports accept"
				if family.server.Addr().Is6() {
					outside = "ip6 saddr != @from6 accept"
				}
				if !service.listed {
					reply = fallbackDrop
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "client request", in: "ranetup0", source: family.client.Addr().String(), target: family.server.Addr().String(), first: outside, pass: true},
					{name: "server reply", in: "ranetother0", source: family.server.Addr().String(), target: family.client.Addr().String(), first: reply, pass: service.listed},
				})
			})
		}
	}
}

func routedServiceSocket(t *testing.T, conn *net.UDPConn, action func(int) error) {
	t.Helper()
	socket, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var operation error
	err = socket.Control(func(fd uintptr) { operation = action(int(fd)) })
	if err := errors.Join(err, operation); err != nil {
		t.Fatal(err)
	}
}

func routedServiceMTU(t *testing.T, conn *net.UDPConn, family routedServiceFamily) int {
	t.Helper()
	level, option := unix.IPPROTO_IP, unix.IP_MTU
	if family.server.Addr().Is6() {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU
	}
	var mtu int
	routedServiceSocket(t, conn, func(fd int) (err error) {
		mtu, err = unix.GetsockoptInt(fd, level, option)
		return err
	})
	return mtu
}

// The kernel supplies the type and code through the connected UDP socket's
// real error queue. The caller enables IP_RECVERR or IPV6_RECVERR before the
// probe. A missing error is not replaced by a trace or an encoder claim.
func routedServiceQueuedError(t *testing.T, conn *net.UDPConn, family routedServiceFamily) (byte, byte) {
	t.Helper()
	level, option := unix.IPPROTO_IP, unix.IP_RECVERR
	if family.server.Addr().Is6() {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
	}
	data, control := make([]byte, 64), make([]byte, 256)
	var kind, code byte
	received := false
	waitFor(t, func() bool {
		routedServiceSocket(t, conn, func(fd int) error {
			_, n, _, _, err := unix.Recvmsg(fd, data, control, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) {
				return nil
			}
			if err != nil {
				return err
			}
			messages, err := unix.ParseSocketControlMessage(control[:n])
			if err != nil {
				return err
			}
			for _, message := range messages {
				if int(message.Header.Level) == level && int(message.Header.Type) == option && len(message.Data) >= 7 {
					kind, code, received = message.Data[5], message.Data[6], true
				}
			}
			return nil
		})
		return received
	})
	return kind, code
}

// The own-prefix router's smaller server link generates a real fragmentation
// needed or Packet Too Big about the client's ordinary UDP request. An error
// for a listed service reaches that socket and reduces its path MTU.
// An unlisted service's error meets the forward drop instead. A smaller request
// then reaches the server, and a listed server completes the exchange.
func TestNetlinkFallbackRoutedRouterPMTUAndUDPReply(t *testing.T) {
	for _, family := range routedServiceFamilies {
		for _, service := range []struct {
			name   string
			port   int
			listed bool
		}{{"listed", 53, true}, {"unlisted", 54321, false}} {
			t.Run(family.name+" "+service.name, func(t *testing.T) {
				_, client, _, server := routedServiceSwitch(t)
				var sender, listener *net.UDPConn
				if err := client.Do(func() (err error) {
					sender, err = net.DialUDP(family.network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sender.Close() })
				if err := server.Do(func() (err error) {
					listener, err = net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				if family.server.Addr().Is4() {
					routedServiceSocket(t, sender, func(fd int) error {
						return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
					})
				}
				initial := routedServiceMTU(t, sender, family)
				if initial <= 1280 {
					t.Fatalf("the first path MTU is %d, want greater than the router's 1280", initial)
				}
				trace := routedTraceFor(t, 2)
				before := routedCounters(t)
				if n, err := sender.Write(bytes.Repeat([]byte{'x'}, 1400)); err != nil || n != 1400 {
					t.Fatalf("the first datagram wrote %d bytes (%v), want 1400 sent to the smaller link", n, err)
				}
				if service.listed {
					waitFor(t, func() bool { return routedServiceMTU(t, sender, family) == 1280 })
				} else {
					waitFor(t, func() bool { return routedCounters(t).drop == before.drop+1 })
					if mtu := routedServiceMTU(t, sender, family); mtu != initial {
						t.Errorf("an unlisted error changed the client's PMTU from %d to %d", initial, mtu)
					}
				}
				after := routedCounters(t)
				wantDrop := uint64(0)
				if !service.listed {
					wantDrop = 1
				}
				if after.drop-before.drop != wantDrop || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
					t.Errorf("the router's PMTU error changed forward counters from %+v to %+v, want %d drops and no form-e accepts", before, after, wantDrop)
				}
				outside, reply := "ip saddr != @from4 accept", "ct direction reply ct protocol udp ct original proto-dst @udpports accept"
				if family.server.Addr().Is6() {
					outside = "ip6 saddr != @from6 accept"
				}
				if !service.listed {
					reply = fallbackDrop
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "client oversized request", in: "ranetup0", source: family.client.Addr().String(), target: family.server.Addr().String(), first: outside, pass: true},
					{name: "router PMTU error", in: "ranetother0", source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: reply, pass: service.listed},
				})
				if service.listed {
					// Consume the asynchronous error of the first oversized
					// datagram before sending one that fits the learned PMTU.
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
				}
				payload := bytes.Repeat([]byte{'f'}, 1000)
				if n, err := sender.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("the fitted datagram wrote %d bytes (%v), want %d", n, err, len(payload))
				}
				if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1100)
				n, address, err := listener.ReadFromUDP(buf)
				if err != nil || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("the own-prefix server read %d bytes (%v), want the fitted datagram", n, err)
				}
				if !service.listed {
					return
				}
				if _, err := listener.WriteToUDP([]byte("done"), address); err != nil {
					t.Fatal(err)
				}
				if err := sender.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				n, err = sender.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], []byte("done")) {
					t.Errorf("the client read %q (%v), want the completed reply", buf[:n], err)
				}
			})
		}
	}
}

// A live UDP flow's next request expires at the own-prefix router, which
// generates a Time Exceeded rather than the test constructing an ICMP packet.
// The listed service's client reads the error from its socket's error queue.
// The unlisted service's error meets the counted forward drop instead.
func TestNetlinkFallbackRoutedRouterTimeExceeded(t *testing.T) {
	for _, family := range routedServiceFamilies {
		for _, service := range []struct {
			name   string
			port   int
			listed bool
		}{{"listed", 53, true}, {"unlisted", 54321, false}} {
			t.Run(family.name+" "+service.name, func(t *testing.T) {
				_, client, _, server := routedServiceSwitch(t)
				var sender, listener *net.UDPConn
				if err := client.Do(func() (err error) {
					sender, err = net.DialUDP(family.network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sender.Close() })
				if err := server.Do(func() (err error) {
					listener, err = net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
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
				n, address, err := listener.ReadFromUDP(buf)
				if err != nil || !bytes.Equal(buf[:n], []byte("opened")) {
					t.Fatalf("the server read %q (%v), want the opening request", buf[:n], err)
				}
				if _, err := listener.WriteToUDP([]byte("answered"), address); err != nil {
					t.Fatal(err)
				}
				if service.listed {
					if err := sender.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if n, err := sender.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("answered")) {
						t.Fatalf("the listed client read %q (%v), want the server's reply", buf[:n], err)
					}
				}
				level, hopOption, errorOption, expected := unix.IPPROTO_IP, unix.IP_TTL, unix.IP_RECVERR, byte(11)
				if family.server.Addr().Is6() {
					level, hopOption, errorOption, expected = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, unix.IPV6_RECVERR, 3
				}
				routedServiceSocket(t, sender, func(fd int) error {
					return errors.Join(unix.SetsockoptInt(fd, level, errorOption, 1), unix.SetsockoptInt(fd, level, hopOption, 2))
				})
				trace := routedTraceFor(t, 2)
				before := routedCounters(t)
				if _, err := sender.Write([]byte("expires")); err != nil {
					t.Fatal(err)
				}
				if service.listed {
					var kind, code byte
					waitFor(t, func() bool {
						received := false
						routedServiceSocket(t, sender, func(fd int) error {
							data, control := make([]byte, 64), make([]byte, 256)
							_, n, _, _, err := unix.Recvmsg(fd, data, control, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
							if errors.Is(err, unix.EAGAIN) {
								return nil
							}
							if err != nil {
								return err
							}
							messages, err := unix.ParseSocketControlMessage(control[:n])
							if err != nil {
								return err
							}
							for _, message := range messages {
								if int(message.Header.Level) == level && int(message.Header.Type) == errorOption && len(message.Data) >= 7 {
									kind, code, received = message.Data[5], message.Data[6], true
								}
							}
							return nil
						})
						return received
					})
					if kind != expected || code != 0 {
						t.Errorf("the client's error queue gave type %d code %d, want Time Exceeded type %d code 0", kind, code, expected)
					}
				} else {
					waitFor(t, func() bool { return routedCounters(t).drop == before.drop+1 })
					routedServiceSocket(t, sender, func(fd int) error {
						_, _, _, _, err := unix.Recvmsg(fd, make([]byte, 64), make([]byte, 256), unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
						if !errors.Is(err, unix.EAGAIN) {
							return fmt.Errorf("unlisted client error queue: %v, want no error", err)
						}
						return nil
					})
				}
				after := routedCounters(t)
				wantDrop := uint64(0)
				if !service.listed {
					wantDrop = 1
				}
				if after.drop-before.drop != wantDrop || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
					t.Errorf("the router's Time Exceeded changed forward counters from %+v to %+v, want %d drops and no form-e accepts", before, after, wantDrop)
				}
				outside, reply := "ip saddr != @from4 accept", "ct direction reply ct protocol udp ct original proto-dst @udpports accept"
				if family.server.Addr().Is6() {
					outside = "ip6 saddr != @from6 accept"
				}
				if !service.listed {
					reply = fallbackDrop
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "client expiring request", in: "ranetup0", source: family.client.Addr().String(), target: family.server.Addr().String(), first: outside, pass: true},
					{name: "router Time Exceeded", in: "ranetother0", source: family.routerNear.Addr().String(), target: family.client.Addr().String(), first: reply, pass: service.listed},
				})
			})
		}
	}
}

// The client's connected network has a main-table route longer than a
// default. Even with the exit up, an own-prefix source inside the overlay
// cannot use that public route just because the destination offers a listed
// inbound port. The forward hook, not the later source NAT, refuses it.
func TestNetlinkFallbackRoutedOwnSourceOnLongerRouteWhileUp(t *testing.T) {
	for _, family := range routedServiceFamilies {
		t.Run(family.name, func(t *testing.T) {
			plat, client, _, server := routedServiceSwitch(t)
			if err := plat.writeFallback(fallbackSample, true); err != nil {
				t.Fatal(err)
			}
			if read, err := plat.readFallback(fallbackSample); err != nil || read.fault != "" {
				t.Fatalf("the up switch was not held: %+v, %v", read, err)
			}
			const port = 53
			var sender, listener *net.UDPConn
			if err := server.Do(func() (err error) {
				sender, err = net.DialUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), 0)),
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sender.Close() })
			if err := client.Do(func() (err error) {
				listener, err = net.ListenUDP(family.network,
					net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			trace := routedTraceFor(t, 1)
			before := routedCounters(t)
			if _, err := sender.Write([]byte("toward the public longer route")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return routedCounters(t).drop == before.drop+1 })
			after := routedCounters(t)
			if after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
				t.Errorf("the refused ordinary request changed form-e counters from %+v to %+v", before, after)
			}
			if err := listener.SetReadDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			if n, _, err := listener.ReadFromUDP(buf); err == nil {
				t.Errorf("the client received %d bytes from the own-prefix source, want none", n)
			} else {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Errorf("the client's refusal read: %v, want a timeout", err)
				}
			}
			routedFirstMatches(t, trace, []routedCase{
				{name: "own source inside the overlay on a longer public route", in: "ranetother0",
					source: family.server.Addr().String(), target: family.client.Addr().String(), first: fallbackDrop},
			})
		})
	}
}

// A TCP server behind the own-prefix router can complete an inbound
// connection only when the external client's original destination port is
// listed. An unlisted SYN still arrives, but its SYN-ACK meets F99.
func TestNetlinkFallbackRoutedTCPServiceReplies(t *testing.T) {
	for _, family := range routedServiceFamilies {
		for _, service := range []struct {
			name   string
			port   int
			listed bool
		}{{"listed", 22, true}, {"unlisted", 54321, false}} {
			t.Run(family.name+" "+service.name, func(t *testing.T) {
				_, client, _, server := routedServiceSwitch(t)
				var listener *net.TCPListener
				if err := server.Do(func() (err error) {
					listener, err = net.ListenTCP(strings.Replace(family.network, "udp", "tcp", 1),
						net.TCPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), uint16(service.port))))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				trace := routedTraceFor(t, 2)
				before := routedCounters(t)
				var connection net.Conn
				if err := client.Do(func() (err error) {
					connection, err = net.DialTimeout(strings.Replace(family.network, "udp", "tcp", 1),
						net.JoinHostPort(family.server.Addr().String(), strconv.Itoa(service.port)), 3*time.Second)
					return err
				}); service.listed {
					if err != nil {
						t.Fatalf("the listed TCP connect: %v", err)
					}
				} else {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatalf("the unlisted TCP connect: %v, want no SYN-ACK", err)
					}
				}
				if service.listed {
					t.Cleanup(func() { _ = connection.Close() })
					if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					accepted, err := listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = accepted.Close() })
					if err := accepted.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := connection.Write([]byte("asked")); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 64)
					if n, err := accepted.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("asked")) {
						t.Fatalf("the own-prefix TCP server read %q (%v), want asked", buf[:n], err)
					}
					if _, err := accepted.Write([]byte("answered")); err != nil {
						t.Fatal(err)
					}
					if n, err := connection.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("answered")) {
						t.Errorf("the outside TCP client read %q (%v), want answered", buf[:n], err)
					}
				}
				after := routedCounters(t)
				if after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 ||
					(service.listed && after.drop != before.drop) ||
					(!service.listed && after.drop <= before.drop) {
					t.Errorf("TCP forward counters changed from %+v to %+v, want no error accepts and a drop only for the unlisted reply", before, after)
				}
				outside, reply := "ip saddr != @from4 accept", "ct direction reply ct protocol tcp ct original proto-dst @tcpports accept"
				if family.server.Addr().Is6() {
					outside = "ip6 saddr != @from6 accept"
				}
				if !service.listed {
					reply = fallbackDrop
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "client TCP SYN", in: "ranetup0", source: family.client.Addr().String(), target: family.server.Addr().String(), first: outside, pass: true},
					{name: "server TCP SYN-ACK", in: "ranetother0", source: family.server.Addr().String(), target: family.client.Addr().String(), first: reply, pass: service.listed},
				})
			})
		}
	}
}
