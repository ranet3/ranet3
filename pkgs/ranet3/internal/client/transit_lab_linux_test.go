// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

const (
	// labMeshPort is each lab node's IKE and ESP port, free in a namespace of its own
	labMeshPort = 4500
	// labPoll is how often a read of a socket's error queue is tried again
	labPoll = 10 * time.Millisecond
	// lineNarrow is the MTU of the link between b and c, under which b's session to c carries less than a's session to b
	lineNarrow = 1360
	// lineListen is the port c's listener reads a's datagrams on
	lineListen = 9000
)

var (
	// labOverlay is the prefixes a lab's mesh addresses come from, which each tun holding one of them routes
	labOverlay = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("3fff::/20")}
	// lineA, lineB and lineC are each node's router-id by family, a host route it announces
	lineA = map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.1"), 6: netip.MustParseAddr("3fff::1")}
	lineB = map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.2"), 6: netip.MustParseAddr("3fff::2")}
	lineC = map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.3"), 6: netip.MustParseAddr("3fff::3")}
	// lineHeld is a network c announces, and lineHold the half of it b holds unreachable
	lineHeld = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.48/28"), 6: netip.MustParsePrefix("3fff:0:0:30::/64")}
	lineHold = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.48/29"), 6: netip.MustParsePrefix("3fff:0:0:30::/65")}
	// lineFar is another network c announces, whose first host c's tun holds
	lineFar = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.64/28"), 6: netip.MustParsePrefix("3fff:0:0:c::/64")}
	// lineCover is the network of each family b announces where it carries no transit, covering a's and c's router-ids and not lineFar
	lineCover = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.0/26"), 6: netip.MustParsePrefix("3fff::/64")}
	// lineSID is b's End.DT46 SID, inside lineSIDs, a network b announces
	lineSIDs = netip.MustParsePrefix("3fff:0:0:b::/64")
	lineSID  = netip.MustParseAddr("3fff:0:0:b::46")
	// lineLinks are the veth pairs a to b and b to c, each a /30 of the underlay, b to c at lineNarrow
	lineLinks = []labLink{
		{places: [2]int{0, 1}, ends: [2]netip.Prefix{netip.MustParsePrefix("198.51.100.1/30"), netip.MustParsePrefix("198.51.100.2/30")}},
		{places: [2]int{1, 2}, ends: [2]netip.Prefix{netip.MustParsePrefix("198.51.100.5/30"), netip.MustParsePrefix("198.51.100.6/30")}, mtu: lineNarrow},
	}
	// exitUplink is the exit lab's uplink, e's end and then i's, each with an address of each family
	exitUplink = [2][2]netip.Prefix{
		{netip.MustParsePrefix("198.51.100.9/30"), netip.MustParsePrefix("2001:db8:1::1/64")},
		{netip.MustParsePrefix("198.51.100.10/30"), netip.MustParsePrefix("2001:db8:1::2/64")},
	}
)

// a, b and c in a line, each in a network namespace of its own, a's sessions to c going through b's
// cap.transit is on at b, b's kernel forwards neither family and b's tun holds no address
// a's datagrams of each family reach c through b, which the mesh forwards in process
// and b answers as a router from its router-id, time exceeded at a hop limit of 1 where 2 reaches c
// packet too big and fragmentation needed with its session to c's size, which a caches and then fits
// and destination unreachable inside a prefix b holds, host unreachable over IPv4
// an IPv6 link-local source draws beyond the scope of the source back on a's session, which a writes into its tun
// with no address of either family b answers IPv4 from the dummy address, a packet too big from its destination and IPv6's time exceeded not at all
// b's kernel forwards nothing and reads nothing from its tun throughout
func TestTUNLineCarriesTransitThroughItsMiddleNodeAndAnswersAsARouter(t *testing.T) {
	nodes := startLab(t, lineSpecs(true), lineLinks)
	a, b, c := nodes[0], nodes[1], nodes[2]
	run(t, a.loopbackNode, b.loopbackNode, c.loopbackNode)
	for _, family := range labFamilies {
		v := family.version
		labRoutes(t, a, lineC[v], lineHeld[v].Addr().Next(), lineFar[v].Addr().Next())
		labRoutes(t, c, lineA[v])
	}
	narrow := esp.Inner(lineNarrow, 20)
	labSession(t, b, lineC[4], narrow)
	labSession(t, a, lineB[4], netstack.DefaultMTU)
	listener := labListen(t, c)

	for _, family := range labFamilies {
		v := family.version
		t.Run(family.name, func(t *testing.T) {
			t.Run("through b to c", func(t *testing.T) {
				before := b.client.Mesh.TransitCounters().Forwarded
				fd := labDatagrams(t, a, family, lineC[v], 0)
				payload := []byte("through b over " + family.name)
				labReceive(t, listener, payload, labWrite(fd, payload))
				if got := b.client.Mesh.TransitCounters().Forwarded; got <= before {
					t.Errorf("c read a's datagram and b counted %d forwarded, as before it", got)
				}
			})
			t.Run("expired at b", func(t *testing.T) {
				got := labAwaitError(t, labDatagrams(t, a, family, lineC[v], 1), family, []byte("one hop"))
				if got.kind != family.expired || got.from != lineB[v] {
					t.Errorf("a hop limit of 1 drew type %d from %s, want time exceeded from b's router-id %s", got.kind, got.from, lineB[v])
				}
				payload := []byte("two hops over " + family.name)
				labReceive(t, listener, payload, labWrite(labDatagrams(t, a, family, lineC[v], 2), payload))
			})
			t.Run("too big for b's session to c", func(t *testing.T) {
				fd := labDatagrams(t, a, family, lineC[v], 0)
				got := labAwaitError(t, fd, family, make([]byte, netstack.DefaultMTU-family.header))
				if got.kind != family.tooBig || got.info != uint32(narrow) || got.from != lineB[v] {
					t.Errorf("a datagram past b's session to c drew type %d naming %d from %s, want %d from b's router-id %s", got.kind, got.info, got.from, narrow, lineB[v])
				}
				if cached, err := unix.GetsockoptInt(fd, family.level, family.pathMTU); err != nil || cached != narrow {
					t.Errorf("a's path to c is %d (%v), want the %d b answered", cached, err, narrow)
				}
				fits := []byte(strings.Repeat("f", narrow-family.header))
				labReceive(t, listener, fits, labWrite(fd, fits))
			})
			t.Run("held at b", func(t *testing.T) {
				// as Babel holds a prefix it had selected once it is retracted, RFC 8966 section 3.5.4
				hold := lineHold[v]
				b.client.Mesh.Routes.Set(netip.Prefix{}, hold, netstack.Unreachable)
				defer b.client.Mesh.Routes.Remove(netip.Prefix{}, hold)
				got := labAwaitError(t, labDatagrams(t, a, family, hold.Addr().Next(), 0), family, []byte("into the hold"))
				if got.kind != family.unreachable || got.code != family.held || got.from != lineB[v] {
					t.Errorf("a datagram into b's hold drew type %d code %d from %s, want type %d code %d from %s", got.kind, got.code, got.from, family.unreachable, family.held, lineB[v])
				}
			})
		})
	}

	t.Run("an IPv6 link-local source", func(t *testing.T) {
		// RFC 4443 section 3.1 code 2, beyond the scope of the source, sent back on the session the packet came through
		var capture int
		if err := a.ns.Do(func() (err error) {
			capture, err = openCapture(a.client.Mesh.Name, labRetry)
			return err
		}); err != nil {
			t.Fatalf("capture a's tun: %v", err)
		}
		defer unix.Close(capture)
		linkLocal := netip.MustParseAddr("fe80::1")
		raw := make([]byte, 40)
		raw[0], raw[6], raw[7] = 0x60, unix.IPPROTO_NONE, 64
		copy(raw[8:], linkLocal.AsSlice())
		copy(raw[24:], lineC[6].AsSlice())
		fd := -1
		if err := a.ns.Do(func() (err error) {
			fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
			return err
		}); err != nil {
			t.Fatalf("open a raw socket at a: %v", err)
		}
		defer unix.Close(fd)
		beyondScope := func(packet []byte) bool {
			return len(packet) >= 48 && packet[0]>>4 == 6 && packet[6] == unix.IPPROTO_ICMPV6 && packet[40] == 1 && packet[41] == 2 &&
				netip.AddrFrom16([16]byte(packet[8:24])) == lineB[6] && netip.AddrFrom16([16]byte(packet[24:40])) == linkLocal
		}
		waitFor(t, convergeBudget, "b's answer to a link-local source to reach a's tun", func() bool {
			_ = unix.Sendto(fd, raw, 0, &unix.SockaddrInet6{Addr: lineC[6].As16()})
			return labCaptured(capture, beyondScope)
		})
	})

	t.Run("a middle node with no address of either family", func(t *testing.T) {
		bare := *b.cfg
		bare.Cap.Route = nil
		writeConfig(t, b.configPath, &bare)
		if err := b.ns.Do(func() error { return b.client.ReloadFrom(b.configPath) }); err != nil {
			t.Fatalf("b's reload to announce nothing was refused: %v", err)
		}
		if got := b.client.Mesh.AnswerSources(); got != (netstack.AnswerSources{}) {
			t.Fatalf("b announcing nothing answers from %+v", got)
		}
		dummy := netip.MustParseAddr("192.0.0.8")
		// a host reaches the dummy address by its default route, which a holds none of here
		labRouteTUN(t, a, netip.PrefixFrom(dummy, 32))
		v4, v6 := labFamilies[0], labFamilies[1]
		if got := labAwaitError(t, labDatagrams(t, a, v4, lineC[4], 1), v4, []byte("one hop")); got.kind != v4.expired || got.from != dummy {
			t.Errorf("an IPv4 hop limit of 1 drew type %d from %s, want time exceeded from %s", got.kind, got.from, dummy)
		}
		unanswered := b.client.Mesh.TransitCounters().Unanswered
		fd := labDatagrams(t, a, v6, lineC[6], 1)
		waitFor(t, convergeBudget, "b to count an IPv6 time exceeded it had no address to send from", func() bool {
			labWrite(fd, []byte("one hop"))()
			return b.client.Mesh.TransitCounters().Unanswered > unanswered
		})
		if got, ok := labReadError(t, fd, v6, labQuiet); ok {
			t.Errorf("b with no IPv6 address answered from %s", got.from)
		}
		for _, family := range labFamilies {
			far := lineFar[family.version].Addr().Next()
			got := labAwaitError(t, labDatagrams(t, a, family, far, 0), family, make([]byte, netstack.DefaultMTU-family.header))
			if got.kind != family.tooBig || got.info != uint32(narrow) || got.from != far {
				t.Errorf("an %s datagram past b's session to c drew type %d naming %d from %s, want %d from its destination", family.name, got.kind, got.info, got.from, narrow)
			}
		}
	})

	labForwardedNothing(t, b)
}

// l, e and t, each in a network namespace of its own, l's and t's sessions going through e's, and i on e's uplink
// e is an exit announcing a default of each family, its kernel forwarding both and routing every destination out of its uplink to i
// l's datagrams of each family reach t through e, which the mesh forwards in process
// so e's kernel forwards none of them and i reads none, where the kernel's own forwarding would carry them out to i
func TestTUNExitCarriesTransitInProcessAndNothingOutOfItsUplink(t *testing.T) {
	specs := lineSpecs(true)
	specs[1].announce = append(specs[1].announce, "0.0.0.0/0", "::/0")
	specs[1].forwards = true
	nodes := startLab(t, specs, lineLinks)
	l, e, far := nodes[0], nodes[1], nodes[2]
	_, capture := labExitUplink(t, e)

	run(t, l.loopbackNode, e.loopbackNode, far.loopbackNode)
	// l reaches t by e's default as soon as it learns it, and e egresses into its tun what it holds no route to t for
	labRoutes(t, e, lineC[4], lineC[6])
	labRoutes(t, l, lineC[4], lineC[6])
	listener := labListen(t, far)
	for _, family := range labFamilies {
		t.Run(family.name, func(t *testing.T) {
			before := e.client.Mesh.TransitCounters().Forwarded
			payload := []byte("through the exit over " + family.name)
			labReceive(t, listener, payload, labWrite(labDatagrams(t, l, family, lineC[family.version], 0), payload))
			if got := e.client.Mesh.TransitCounters().Forwarded; got <= before {
				t.Errorf("t read l's datagram and e counted %d forwarded, as before it", got)
			}
		})
	}
	if labCaptured(capture, func(packet []byte) bool {
		to, _, _, ok := labUDPOf(packet)
		return ok && (to == lineC[4] || to == lineC[6])
	}) {
		t.Errorf("i read a datagram for t on e's uplink")
	}
	labForwardedNothing(t, e)
}

// e, an exit advertising the internet of each family through cap.egress as a default, a pair of halves or four quarters, runs the translator main builds
// l's datagrams of each family to i leave e's uplink translated to e's address there, mode 2
// a datagram l carries from a source the mesh routes no reply to is refused at e and counted, with nothing at i
// and so is the answer e owes such a source, a datagram from it expiring at e on its way to t drawing nothing at i
// a datagram l carries to an IPv4 link-local address is a martian at e, from l's source and from a stranger's, with nothing at i
// and e's host takes one to an IPv6 link-local address from its tun and sends nothing of it out of its uplink
// though i holds that address there and reads a datagram e's host sends it
func TestTUNExitEgressesEachShapeOfTheInternetTranslated(t *testing.T) {
	for _, shape := range []struct {
		name     string
		prefixes []string
	}{
		{"a default", []string{"0.0.0.0/0", "::/0"}},
		{"a pair of halves", []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}},
		{"four quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "::/2", "4000::/2", "8000::/2", "c000::/2"}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			specs := lineSpecs(true)
			specs[1].forwards = true
			transit := specs[1].change
			specs[1].change = func(cfg *config.Config) {
				transit(cfg)
				cfg.Cap.Egress = &egress.Egress{}
				for _, prefix := range shape.prefixes {
					cfg.Cap.Egress.Advertise = append(cfg.Cap.Egress.Advertise, schema.MustPrefix(prefix))
				}
			}
			nodes := startLab(t, specs, lineLinks)
			l, e, far := nodes[0], nodes[1], nodes[2]
			i, capture := labExitUplink(t, e)
			// e's kernel routes a reply to the overlay back into its tun, as the reconciler installs a learned route
			for _, prefix := range labOverlay {
				labRouteTUN(t, e, prefix)
			}
			run(t, l.loopbackNode, e.loopbackNode, far.loopbackNode)
			labTranslate(t, e)
			internet := map[int]netip.Addr{4: exitUplink[1][0].Addr(), 6: exitUplink[1][1].Addr()}
			for _, address := range internet {
				labRouteTUN(t, l, netip.PrefixFrom(address, address.BitLen()))
			}
			labRoutes(t, l, internet[4], internet[6])
			listener := labListen(t, i)
			for side, family := range labFamilies {
				t.Run(family.name, func(t *testing.T) {
					before := e.client.Mesh.TransitCounters().Delivered
					payload := []byte("out of the exit over " + family.name)
					from := labReceive(t, listener, payload, labWrite(labDatagrams(t, l, family, internet[family.version], 0), payload))
					if want := exitUplink[0][side].Addr(); from.Addr().Unmap() != want {
						t.Errorf("i read l's datagram from %s, want e's uplink address %s", from, want)
					}
					if got := e.client.Mesh.TransitCounters().Delivered; got <= before {
						t.Errorf("i read l's datagram and e counted %d delivered, as before it", got)
					}
				})
			}
			stranger := map[int]netip.Addr{4: netip.MustParseAddr("203.0.113.66"), 6: netip.MustParseAddr("2001:db8:66::6")}
			t.Run("from a source the mesh routes no reply to", func(t *testing.T) {
				for _, family := range labFamilies {
					payload := []byte("from a stranger over " + family.name)
					to := internet[family.version]
					raw := udpPacket(stranger[family.version], to, labLeafPort, lineListen, payload)
					refused := e.client.Mesh.TransitCounters().UnroutedSource
					waitFor(t, convergeBudget, "e to count l's "+family.name+" datagram from a stranger's source refused", func() bool {
						labSendRaw(t, l, raw, to, 0)
						return e.client.Mesh.TransitCounters().UnroutedSource > refused
					})
					if labCaptured(capture, func(packet []byte) bool {
						_, _, carried, ok := labUDPOf(packet)
						return ok && string(carried) == string(payload)
					}) {
						t.Errorf("i read l's %s datagram from a stranger's source on e's uplink", family.name)
					}
				}
			})
			t.Run("an answer to a source the mesh routes no reply to", func(t *testing.T) {
				labRoutes(t, e, lineC[4], lineC[6])
				labRoutes(t, l, lineC[4], lineC[6])
				for _, family := range labFamilies {
					raw := udpPacket(stranger[family.version], lineC[family.version], labLeafPort, lineListen, []byte("expiring at e over "+family.name))
					// a hop limit of 1, which e answers expired, the kernel filling in the IPv4 header's checksum, raw(7)
					if family.version == 4 {
						raw[8] = 1
					} else {
						raw[7] = 1
					}
					expired := e.client.Mesh.TransitCounters().Expired
					waitFor(t, convergeBudget, "e to count l's "+family.name+" datagram from a stranger's source expired", func() bool {
						labSendRaw(t, l, raw, lineC[family.version], 0)
						return e.client.Mesh.TransitCounters().Expired > expired
					})
					if labCaptured(capture, labErrorTo(stranger[family.version])) {
						t.Errorf("i read an ICMP error to %s on e's uplink", stranger[family.version])
					}
				}
			})
			t.Run("to a link-local address", func(t *testing.T) {
				metadata, linkLocal := netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fe80::a9fe:a9fe")
				labRouteTUN(t, l, netip.PrefixFrom(metadata, metadata.BitLen()))
				labRouteTUN(t, l, netip.PrefixFrom(linkLocal, linkLocal.BitLen()))
				labRoutes(t, l, metadata, linkLocal)
				// i holds the IPv6 one on its end of the uplink, so a datagram e's host forwarded there would reach the capture
				if err := i.ns.Do(func() error {
					netlink, err := netnstest.OpenNetlink()
					if err != nil {
						return err
					}
					defer netlink.Close()
					return labAddress(netlink, "vdb", netip.PrefixFrom(linkLocal, 64))
				}); err != nil {
					t.Fatalf("give i %s: %v", linkLocal, err)
				}
				control := []byte("from e's host to i's link-local address")
				labReceive(t, listener, control, func() {
					if err := e.ns.Do(func() error {
						conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: linkLocal.AsSlice(), Port: lineListen, Zone: "vbd"})
						if err != nil {
							return err
						}
						defer conn.Close()
						_, err = conn.Write(control)
						return err
					}); err != nil {
						t.Errorf("send the control datagram from e's host to %s: %v", linkLocal, err)
					}
				})
				var zone uint32
				if err := l.ns.Do(func() error {
					link, err := net.InterfaceByName(l.client.Mesh.Name)
					if err == nil {
						zone = uint32(link.Index)
					}
					return err
				}); err != nil {
					t.Fatalf("find l's tun: %v", err)
				}
				martian := func(c netstack.TransitCounters) uint64 { return c.Martian }
				delivered := func(c netstack.TransitCounters) uint64 { return c.Delivered }
				for _, c := range []struct {
					name     string
					from, to netip.Addr
					zone     uint32
					counted  func(netstack.TransitCounters) uint64
				}{
					{"IPv4 from l's source", lineA[4], metadata, 0, martian},
					{"IPv4 from a stranger's source", stranger[4], metadata, 0, martian},
					{"IPv6 from l's source", lineA[6], linkLocal, zone, delivered},
				} {
					payload := []byte("to a link-local address " + c.name)
					raw := udpPacket(c.from, c.to, labLeafPort, lineListen, payload)
					before := c.counted(e.client.Mesh.TransitCounters())
					waitFor(t, convergeBudget, "e to count l's datagram to a link-local address "+c.name, func() bool {
						labSendRaw(t, l, raw, c.to, c.zone)
						return c.counted(e.client.Mesh.TransitCounters()) > before
					})
					if labCaptured(capture, func(packet []byte) bool {
						_, _, carried, ok := labUDPOf(packet)
						return ok && string(carried) == string(payload)
					}) {
						t.Errorf("i read l's datagram to %s %s on e's uplink", c.to, c.name)
					}
				}
			})
		})
	}
}

// labSendRaw sends raw, an IP packet with its header, from node's namespace to to, through the interface zone names where it is not 0
// a send that fails is the caller's to retry, as a wait for what it should cause does
func labSendRaw(t *testing.T, node *labNode, raw []byte, to netip.Addr, zone uint32) {
	t.Helper()
	domain, address := unix.AF_INET6, unix.Sockaddr(&unix.SockaddrInet6{Addr: to.As16(), ZoneId: zone})
	if to.Is4() {
		domain, address = unix.AF_INET, &unix.SockaddrInet4{Addr: to.As4()}
	}
	if err := node.ns.Do(func() error {
		fd, err := unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		_ = unix.Sendto(fd, raw, 0, address)
		return nil
	}); err != nil {
		t.Fatalf("open a raw socket at %s: %v", node.name, err)
	}
}

// labErrorTo takes an ICMP or ICMPv6 message to destination
func labErrorTo(destination netip.Addr) func([]byte) bool {
	return func(packet []byte) bool {
		switch {
		case len(packet) >= 20 && packet[0]>>4 == 4:
			return packet[9] == unix.IPPROTO_ICMP && netip.AddrFrom4([4]byte(packet[16:20])) == destination
		case len(packet) >= 40 && packet[0]>>4 == 6:
			return packet[6] == unix.IPPROTO_ICMPV6 && netip.AddrFrom16([16]byte(packet[24:40])) == destination
		}
		return false
	}
}

// a node with cap.egress and no egress segment egresses mode 2 through the prefixes cap.egress advertises into its tun
// for each family the exit holds ready and lets it announce as Republish last read, and is dropped and counted not ready for a family it does not
// whatever the border's chain reads back, which holds the egress SIDs alone
func TestTUNModeTwoEgressFollowsTheAnnouncementWithNoEgressSegment(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	every := map[int]netip.Prefix{4: netip.MustParsePrefix("0.0.0.0/0"), 6: netip.MustParsePrefix("::/0")}
	internet := map[int]netip.Addr{4: netip.MustParseAddr("203.0.113.9"), 6: netip.MustParseAddr("2001:db8::9")}
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Cap.Egress = &egress.Egress{Advertise: []schema.Prefix{schema.PrefixFrom(every[4]), schema.PrefixFrom(every[6])}}
		cfg.Cap.Border = &egress.Border{}
		for _, prefix := range labOverlay {
			cfg.Cap.Border.Overlay = append(cfg.Cap.Border.Overlay, schema.PrefixFrom(prefix))
		}
	})
	if err := netnstest.StartThread(t).Do(func() (err error) {
		c.Mesh, err = netstack.NewNamed(0, labTUN, nil)
		return err
	}); err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(c.Mesh.Close)
	startDecision(c.Mesh, c.config())
	leaf := netstack.NewPeer("example/leaf", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the leaf is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(leaf.Close)
	for _, family := range []int{4, 6} {
		c.Mesh.Routes.Set(netip.Prefix{}, netip.PrefixFrom(lineA[family], lineA[family].BitLen()), leaf)
		// the entry the speaker writes for a prefix this node originates, which this speaker writes into a mesh of its own
		c.Mesh.Routes.Set(netip.Prefix{}, every[family], netstack.Local)
	}
	egressed := func(t *testing.T) (families [2]bool) {
		t.Helper()
		for side, family := range []int{4, 6} {
			before := c.Mesh.TransitCounters()
			c.Mesh.DeliverInbound(udpPacket(lineA[family], internet[family], labLeafPort, lineListen, []byte("mode 2")), 0)
			after := c.Mesh.TransitCounters()
			families[side] = after.Delivered == before.Delivered+1
			if !families[side] && after.NotReady != before.NotReady+1 {
				t.Errorf("an IPv%d datagram through %s counted %+v after %+v, want one more delivered or not ready", family, every[family], after, before)
			}
		}
		return families
	}
	// the exit writes into the tun, as the kernel exit does
	var announced []netip.Prefix
	c.SetExit(&fakeExit{announce: func() []netip.Prefix { return announced }, write: c.Mesh.WriteHost})
	// the exit holds both families ready, as it does for every family it lets the node announce
	c.SetEgressReady(true, true, false)
	for _, step := range []struct {
		announced []netip.Prefix
		border    bool
	}{
		{nil, true},
		{[]netip.Prefix{every[4], every[6]}, true},
		{[]netip.Prefix{every[6]}, true},
		{[]netip.Prefix{every[4], every[6]}, false},
		{[]netip.Prefix{every[4]}, false},
		{nil, false},
	} {
		announced = step.announced
		c.SetBorderReady(step.border)
		want := [2]bool{slices.Contains(step.announced, every[4]), slices.Contains(step.announced, every[6])}
		if got := egressed(t); got != want {
			t.Errorf("with the translator letting the node announce %v and the border ready %v the mesh egressed %v, want %v", step.announced, step.border, got, want)
		}
	}
}

// labExitUplink joins e, the exit at place 1, to a node i at place 3 on exitUplink, e routing every destination out of it to i
// and returns i and a capture of i's end of it
func labExitUplink(t *testing.T, e *labNode) (*labNode, int) {
	t.Helper()
	i := &labNode{loopbackNode: &loopbackNode{name: "lab-i"}, ns: netnstest.StartThread(t)}
	labPair(t, e, i, labLink{places: [2]int{1, 3}, ends: [2]netip.Prefix{exitUplink[0][0], exitUplink[1][0]}})
	// as labPair names the two ends of the pair joining places 1 and 3
	uplink := [2]string{"vbd", "vdb"}
	for side, end := range []*labNode{e, i} {
		if err := end.ns.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if err := labAddress(netlink, uplink[side], exitUplink[side][1]); err != nil || side == 1 {
				return err
			}
			link, err := net.InterfaceByName(uplink[0])
			if err != nil {
				return err
			}
			for _, gateway := range exitUplink[1] {
				every := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
				if gateway.Addr().Is4() {
					every = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
				}
				if err := labRouteVia(netlink, link.Index, every, gateway.Addr()); err != nil {
					return fmt.Errorf("route %s through i: %w", every, err)
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("join %s to i: %v", e.name, err)
		}
	}
	var capture int
	if err := i.ns.Do(func() (err error) {
		capture, err = openCapture(uplink[1], labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture i's end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })
	return i, capture
}

// labTranslator builds the exit the command builds for client's cap.egress, in ns, and hands it to client
func labTranslator(t *testing.T, ns *netnstest.Thread, client *Client, bus *events.Bus) *kernelexit.Translator {
	t.Helper()
	cfg := client.config()
	in := func(f func()) { _ = ns.Do(func() error { f(); return nil }) }
	var translator *kernelexit.Translator
	if err := ns.Do(func() (err error) {
		translator, err = kernelexit.New(*cfg.Egress(), kernelexit.Runtime{
			Interface:     client.Mesh.Name,
			MeshAddresses: MeshAddresses(cfg),
			// the sysctls and the route lookups are read in ns, which the translator's own goroutine is not in
			Forwarding: func() (v4, v6 bool) { in(func() { v4, v6 = Forwarding() }); return v4, v6 },
			Lookup: func(lookups []kernelexit.Lookup) (answers []kernelexit.Answer, err error) {
				in(func() { answers, err = RouteLookups(lookups) })
				return answers, err
			},
			Sysctl:  func(path string) (value string) { in(func() { value = Sysctl(path) }); return value },
			Members: client.EgressMembers,
			Write:   client.Mesh.WriteHost,
			Steered: len(cfg.Segments().Egress()) != 0,
			Hooks:   egress.Hooks{Ready: client.SetEgressReady, Republish: client.Republish, Events: bus},
		})
		return err
	}); err != nil {
		t.Fatalf("build the translator: %v", err)
	}
	client.SetExit(translator)
	return translator
}

// labTranslate runs labTranslator's exit for node until the test ends
func labTranslate(t *testing.T, node *labNode) {
	t.Helper()
	translator := labTranslator(t, node.ns, node.client, node.events)
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	runs.Go(func() {
		if err := translator.Run(ctx); err != nil {
			t.Errorf("%s's translator: %v", node.name, err)
		}
	})
	t.Cleanup(func() {
		cancel()
		runs.Wait()
	})
}

// labForwardedNothing fails the test where node's kernel forwarded a packet of either family or read one from node's tun
func labForwardedNothing(t *testing.T, node *labNode) {
	t.Helper()
	if err := node.ns.Do(func() error {
		for _, counter := range []struct{ file, name string }{
			{"/proc/thread-self/net/snmp", "ForwDatagrams"},
			{"/proc/thread-self/net/snmp6", "Ip6OutForwDatagrams"},
		} {
			if got, err := labKernelCount(counter.file, counter.name); err != nil || got != 0 {
				return fmt.Errorf("%s's kernel counts %d %s (%v), want none", node.name, got, counter.name, err)
			}
		}
		if got, err := labTUNReceived(node.client.Mesh.Name); err != nil || got != 0 {
			return fmt.Errorf("%s's kernel read %d packets from its tun (%v), want none", node.name, got, err)
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// a, b and c in the line, with cap.transit off at b, which announces a network covering a's and c's router-ids
// and an End.DT46 SID delivering to the mesh, which a steers its datagrams for another network of c's through
// b answers a datagram for c administratively prohibited from its router-id
// and carries the one a steers through its SID to c all the same
// a datagram inside b's overlay that b holds no route for draws host unreachable, and network unreachable once a reload moves the overlay off IPv4
func TestTUNLineRefusesTransitWhileItIsOffButNotThroughAnEndDT46SID(t *testing.T) {
	nodes := startLab(t, lineSpecs(false), lineLinks)
	a, b, c := nodes[0], nodes[1], nodes[2]
	run(t, a.loopbackNode, b.loopbackNode, c.loopbackNode)
	labRoutes(t, a, lineC[4], lineC[6], lineSID)
	labRoutes(t, b, lineFar[4].Addr().Next(), lineFar[6].Addr().Next())
	listener := labListen(t, c)
	for _, family := range labFamilies {
		v := family.version
		t.Run(family.name, func(t *testing.T) {
			t.Run("refused at b", func(t *testing.T) {
				before := b.client.Mesh.TransitCounters().Refused
				got := labAwaitError(t, labDatagrams(t, a, family, lineC[v], 0), family, []byte("past b"))
				if got.kind != family.unreachable || got.code != family.prohibited || got.from != lineB[v] {
					t.Errorf("a datagram for c drew type %d code %d from %s, want type %d code %d from b's router-id %s", got.kind, got.code, got.from, family.unreachable, family.prohibited, lineB[v])
				}
				if got := b.client.Mesh.TransitCounters().Refused; got <= before {
					t.Errorf("b answered and counted %d refused, as before it", got)
				}
			})
			t.Run("through b's End.DT46 SID", func(t *testing.T) {
				before := b.client.Mesh.TransitCounters().Forwarded
				payload := []byte("through b's SID over " + family.name)
				labReceive(t, listener, payload, labWrite(labDatagrams(t, a, family, lineFar[v].Addr().Next(), 0), payload))
				if got := b.client.Mesh.TransitCounters().Forwarded; got <= before {
					t.Errorf("c read the steered datagram and b counted %d forwarded, as before it", got)
				}
			})
		})
	}

	t.Run("no route inside the overlay", func(t *testing.T) {
		// a sends what no prefix b announces holds to b, as a default b announced would
		unrouted := netip.MustParseAddr("192.0.2.200")
		toB := netip.PrefixFrom(unrouted, 32)
		defer a.client.Mesh.Routes.Remove(netip.Prefix{}, toB)
		v4 := labFamilies[0]
		answer := func() labError {
			fd := labDatagrams(t, a, v4, unrouted, 0)
			var got labError
			waitFor(t, convergeBudget, "b to answer a datagram it holds no route for", func() bool {
				peer, verdict, _ := a.client.Mesh.Routes.Resolve(netip.Addr{}, lineB[4])
				if verdict != netstack.RoutePeer {
					return false
				}
				a.client.Mesh.Routes.Set(netip.Prefix{}, toB, peer)
				labWrite(fd, []byte("nowhere"))()
				var ok bool
				got, ok = labReadError(t, fd, v4, labRetry)
				return ok
			})
			return got
		}
		// RFC 1812 section 5.2.7.1, host unreachable where other hosts of the overlay may be reachable, and network unreachable outside it
		const hostUnreachable, networkUnreachable = 1, 0
		if got := answer(); got.kind != v4.unreachable || got.code != hostUnreachable || got.from != lineB[4] {
			t.Errorf("a datagram inside b's overlay that b holds no route for drew type %d code %d from %s, want host unreachable from %s", got.kind, got.code, got.from, lineB[4])
		}
		moved := *b.cfg
		moved.Cap.Border = &egress.Border{Overlay: []schema.Prefix{schema.PrefixFrom(labOverlay[1])}}
		writeConfig(t, b.configPath, &moved)
		if err := b.ns.Do(func() error { return b.client.ReloadFrom(b.configPath) }); err != nil {
			t.Fatalf("b's reload moving its overlay off IPv4 was refused: %v", err)
		}
		if got := answer(); got.kind != v4.unreachable || got.code != networkUnreachable || got.from != lineB[4] {
			t.Errorf("a datagram b holds no route for, outside its overlay once reloaded, drew type %d code %d from %s, want network unreachable from %s", got.kind, got.code, got.from, lineB[4])
		}
	})
}

// lineSpecs is the line's three nodes, with cap.transit at b as transit says
// where it is off b announces lineCover and lineSIDs with its SID, and a steers lineFar through that SID
func lineSpecs(transit bool) []labSpec {
	hosts := func(addresses map[int]netip.Addr) []string {
		return []string{netip.PrefixFrom(addresses[4], 32).String(), netip.PrefixFrom(addresses[6], 128).String()}
	}
	tunHosts := func(addresses ...netip.Addr) []netip.Prefix {
		var out []netip.Prefix
		for _, address := range addresses {
			out = append(out, netip.PrefixFrom(address, address.BitLen()))
		}
		return out
	}
	a := labSpec{announce: hosts(lineA), hosts: tunHosts(lineA[4], lineA[6]), dial: []int{1}}
	b := labSpec{announce: hosts(lineB)}
	c := labSpec{
		announce: append(hosts(lineC), lineHeld[4].String(), lineHeld[6].String(), lineFar[4].String(), lineFar[6].String()),
		hosts:    tunHosts(lineC[4], lineC[6], lineFar[4].Addr().Next(), lineFar[6].Addr().Next()),
		dial:     []int{1},
	}
	if transit {
		b.change = func(cfg *config.Config) {
			on := true
			cfg.Cap.Transit = &babel.Transit{Enable: &on}
		}
		return []labSpec{a, b, c}
	}
	b.announce = append(b.announce, lineCover[4].String(), lineCover[6].String(), lineSIDs.String())
	b.change = func(cfg *config.Config) {
		cfg.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{{SID: schema.AddrFrom(lineSID), Behavior: srv6.BehaviorEndDT46}}}
		cfg.Cap.Border = &egress.Border{}
		for _, prefix := range labOverlay {
			cfg.Cap.Border.Overlay = append(cfg.Cap.Border.Overlay, schema.PrefixFrom(prefix))
		}
	}
	a.change = func(cfg *config.Config) {
		via := []schema.Addr{schema.AddrFrom(lineSID)}
		cfg.Cap.Segment = &srv6.Segments{Source: schema.AddrFrom(lineA[6]), Steer: []srv6.Steer{
			{To: schema.PrefixFrom(lineFar[4]), Via: via},
			{To: schema.PrefixFrom(lineFar[6]), Via: via},
		}}
	}
	return []labSpec{a, b, c}
}

// labSpec is one node of a lab mesh, which runs in a network namespace of its own
type labSpec struct {
	// announce lists the prefixes cap.route announces
	announce []string
	// hosts are the addresses its tun holds, beside a route to labOverlay through the tun where it holds any
	hosts []netip.Prefix
	// dial is the places of the nodes it dials, each at the end the link between the two gives it
	dial []int
	// change edits its configuration before it starts, nil for none
	change func(*config.Config)
	// forwards turns its kernel's forwarding of both families on, which is off where it is false
	// whatever the namespace the lab starts in holds, which a new namespace takes its IPv4 settings from
	forwards bool
}

// labLink is a veth pair between the nodes at places, their ends addressed ends, at mtu bytes or the kernel's default where it is zero
type labLink struct {
	places [2]int
	ends   [2]netip.Prefix
	mtu    int
}

// labNode is a lab mesh's node, built on a tun of its own in the namespace ns holds
type labNode struct {
	*loopbackNode
	ns *netnstest.Thread
}

// startLab builds a node for each of specs, not yet running, joined by links
// each has an endpoint at each end of its links, with the serial of its place among them, and its tun is named after its place
func startLab(t *testing.T, specs []labSpec, links []labLink) []*labNode {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	org := registry.Organization{PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Organization: "example"}
	mesh := meshCounter.Add(1)
	nodes := make([]*labNode, len(specs))
	// serials[i][j] is the serial of i's endpoint on its link to j
	serials := make([]map[int]string, len(specs))
	for i := range specs {
		nodes[i] = &labNode{loopbackNode: &loopbackNode{name: fmt.Sprintf("lab-%c-%d", 'a'+i, mesh), port: labMeshPort, events: events.New()}, ns: netnstest.StartThread(t)}
		serials[i] = map[int]string{}
		value := []byte("0\n")
		if specs[i].forwards {
			value = []byte("1\n")
		}
		if err := nodes[i].ns.Do(func() error {
			for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
				if err := os.WriteFile(path, value, 0o644); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("set %s's forwarding: %v", nodes[i].name, err)
		}
		org.Nodes = append(org.Nodes, registry.Node{CommonName: nodes[i].name})
	}
	for _, link := range links {
		for side, place := range link.places {
			serial := strconv.Itoa(len(org.Nodes[place].Endpoints))
			serials[place][link.places[1-side]] = serial
			address := link.ends[side].Addr().String()
			org.Nodes[place].Endpoints = append(org.Nodes[place].Endpoints, registry.Endpoint{SerialNumber: serial, AddressFamily: "ip4", Address: &address, Port: labMeshPort})
		}
	}
	dir := t.TempDir()
	registryPath, keyPath := filepath.Join(dir, "registry.json"), filepath.Join(dir, "key.pem")
	document, err := json.Marshal(registry.Registry{org})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	writeKey(t, keyPath, private)

	for i, spec := range specs {
		node := nodes[i]
		var body strings.Builder
		fmt.Fprintf(&body, "node: example/%s\nauth:\n  key: %s\n  trust: %s\nlink:\n  port: %d\n  endpoints:\n", node.name, keyPath, registryPath, labMeshPort)
		for _, endpoint := range org.Nodes[i].Endpoints {
			fmt.Fprintf(&body, "    - serial: %q\n      family: ip4\n", endpoint.SerialNumber)
		}
		body.WriteString("  listen: true\n")
		if len(spec.dial) != 0 {
			body.WriteString("dial:\n  to:\n")
			for _, j := range spec.dial {
				fmt.Fprintf(&body, "    - example/%s:%s\n", nodes[j].name, serials[j][i])
			}
		}
		body.WriteString("cap:\n  babel:\n    hello: 200ms\n    update: 400ms\n")
		if len(spec.announce) != 0 {
			body.WriteString("  route:\n    announce:\n")
			for _, prefix := range spec.announce {
				fmt.Fprintf(&body, "      - %q\n", prefix)
			}
		}
		node.configPath = filepath.Join(dir, node.name+".yaml")
		if err := os.WriteFile(node.configPath, []byte(body.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if node.cfg, err = config.Load(node.configPath); err != nil {
			t.Fatalf("%s: %v", node.name, err)
		}
		if spec.change != nil {
			spec.change(node.cfg)
			if err := node.cfg.Validate(); err != nil {
				t.Fatalf("%s's configuration is refused: %v", node.name, err)
			}
			writeConfig(t, node.configPath, node.cfg)
		}
	}

	// as New opens the tun and hands the mesh the tables of cap.segment
	meshes := make([]*netstack.Mesh, len(nodes))
	for i, node := range nodes {
		segments, steering, err := node.cfg.SegmentTables()
		if err != nil {
			t.Fatalf("%s: %v", node.name, err)
		}
		mtu, err := steeredMTU(node.cfg.Link.SessionMTU(), steering)
		if err != nil {
			t.Fatalf("%s: %v", node.name, err)
		}
		if err := node.ns.Do(func() (err error) {
			meshes[i], err = netstack.NewNamed(mtu, fmt.Sprintf("mesh%c", 'a'+i), node.events.Emit)
			return err
		}); err != nil {
			t.Fatalf("open %s's tun: %v", node.name, err)
		}
		t.Cleanup(meshes[i].Close)
		meshes[i].SetSegments(segments)
		meshes[i].SetSteering(steering)
	}
	for _, link := range links {
		labPair(t, nodes[link.places[0]], nodes[link.places[1]], link)
	}
	for i, spec := range specs {
		if len(spec.hosts) == 0 {
			continue
		}
		if err := nodes[i].ns.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if err := labAddress(netlink, meshes[i].Name, spec.hosts...); err != nil {
				return err
			}
			for _, prefix := range labOverlay {
				if err := labRouteDevice(netlink, unix.RTM_NEWROUTE, meshes[i].Name, prefix); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("address %s's tun: %v", nodes[i].name, err)
		}
	}
	x := trust(t, registry.Registry{org})
	for i, node := range nodes {
		if err := node.ns.Do(func() (err error) {
			node.client, err = newClient(node.cfg, private, x, meshes[i], nil, node.events)
			return err
		}); err != nil {
			for _, built := range nodes[:i] {
				built.client.Close()
			}
			t.Fatalf("build %s: %v", node.name, err)
		}
		node.client.probeTimeout, node.client.confirmEvery = holeProbeTimeout, holeConfirm
	}
	return nodes
}

// labPair makes link's veth pair from here's namespace to there's and addresses each end, named for the places it joins
func labPair(t *testing.T, here, there *labNode, link labLink) {
	t.Helper()
	names := [2]string{fmt.Sprintf("v%c%c", 'a'+link.places[0], 'a'+link.places[1]), fmt.Sprintf("v%c%c", 'a'+link.places[1], 'a'+link.places[0])}
	var mtu []byte
	if link.mtu != 0 {
		mtu = netnstest.Attr(unix.IFLA_MTU, netnstest.U32(uint32(link.mtu)))
	}
	other, err := unix.Open(there.ns.Path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s's namespace: %v", there.name, err)
	}
	defer unix.Close(other)
	peer := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(names[1])), mtu, netnstest.Attr(unix.IFLA_NET_NS_FD, netnstest.U32(uint32(other))))
	kind := slices.Concat(netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("veth")), netnstest.Attr(unix.IFLA_INFO_DATA, netnstest.Attr(netnstest.VethPeer, peer)))
	pair := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(names[0])), mtu, netnstest.Attr(unix.IFLA_LINKINFO, kind))
	for side, end := range []*labNode{here, there} {
		if err := end.ns.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if side == 0 {
				if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, pair); err != nil {
					return fmt.Errorf("make the veth pair: %w", err)
				}
			}
			return labAddress(netlink, names[side], link.ends[side])
		}); err != nil {
			t.Fatalf("join %s to %s: %v", here.name, there.name, err)
		}
	}
}

// labRouteTUN routes to through node's tun in its namespace
func labRouteTUN(t *testing.T, node *labNode, to netip.Prefix) {
	t.Helper()
	if err := node.ns.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		return labRouteDevice(netlink, unix.RTM_NEWROUTE, node.client.Mesh.Name, to)
	}); err != nil {
		t.Fatalf("route %s through %s's tun: %v", to, node.name, err)
	}
}

// labRoutes waits until node forwards to each of addresses through a session
func labRoutes(t *testing.T, node *labNode, addresses ...netip.Addr) {
	t.Helper()
	waitFor(t, convergeBudget, fmt.Sprintf("%s to forward to %v", node.name, addresses), func() bool {
		for _, address := range addresses {
			if _, verdict, _ := node.client.Mesh.Routes.Resolve(netip.Addr{}, address); verdict != netstack.RoutePeer {
				return false
			}
		}
		return true
	})
}

// labSession waits until node's session toward address carries packets of mtu bytes
// looked up on every poll, since a simultaneous open replaces the first session and its peer with it
func labSession(t *testing.T, node *labNode, address netip.Addr, mtu int) {
	t.Helper()
	waitFor(t, convergeBudget, fmt.Sprintf("%s's session toward %s to carry %d", node.name, address, mtu), func() bool {
		peer, verdict, _ := node.client.Mesh.Routes.Resolve(netip.Addr{}, address)
		return verdict == netstack.RoutePeer && peer.MTU() == mtu
	})
}

// labListen is a UDP socket of node's on lineListen, for both families
func labListen(t *testing.T, node *labNode) *net.UDPConn {
	t.Helper()
	var listener *net.UDPConn
	if err := node.ns.Do(func() (err error) {
		listener, err = net.ListenUDP("udp", &net.UDPAddr{Port: lineListen})
		return err
	}); err != nil {
		t.Fatalf("listen at %s: %v", node.name, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// labFamily holds the options a lab's datagram socket of one family sets and reads, and the ICMP types and codes it is answered with
type labFamily struct {
	name    string
	version int
	// domain, level and the options at level that set the hop limit, queue errors, set DF and read the path MTU, and the type of the queued error's message
	domain, level                          int
	hops, recvErr, discover, pathMTU, cmsg int
	// dontFragment is the value of discover that sets DF and never fragments
	dontFragment int
	// header is the IP and UDP headers ahead of a datagram's payload
	header int
	origin uint8
	// the ICMP types of time exceeded, destination unreachable and a packet too big
	expired, unreachable, tooBig uint8
	// the codes of destination unreachable for a hold and for transit refused
	held, prohibited uint8
	// offenderLen is the size of the address the error names its sender by, which offender reads
	offenderLen int
	offender    func([]byte) netip.Addr
	address     func(netip.AddrPort) unix.Sockaddr
}

var labFamilies = []labFamily{
	{
		name: "IPv4", version: 4, domain: unix.AF_INET, level: unix.IPPROTO_IP,
		hops: unix.IP_TTL, recvErr: unix.IP_RECVERR, discover: unix.IP_MTU_DISCOVER, pathMTU: unix.IP_MTU, cmsg: unix.IP_RECVERR, dontFragment: unix.IP_PMTUDISC_DO,
		header: 28, origin: unix.SO_EE_ORIGIN_ICMP,
		// RFC 792, and RFC 1812 section 5.2.7.1 for host unreachable and administratively prohibited
		expired: 11, unreachable: 3, tooBig: 3, held: 1, prohibited: 13,
		offenderLen: unix.SizeofSockaddrInet4,
		// struct sockaddr_in, its address at byte 4
		offender: func(raw []byte) netip.Addr { return netip.AddrFrom4([4]byte(raw[4:8])) },
		address: func(to netip.AddrPort) unix.Sockaddr {
			return &unix.SockaddrInet4{Port: int(to.Port()), Addr: to.Addr().As4()}
		},
	},
	{
		name: "IPv6", version: 6, domain: unix.AF_INET6, level: unix.IPPROTO_IPV6,
		hops: unix.IPV6_UNICAST_HOPS, recvErr: unix.IPV6_RECVERR, discover: unix.IPV6_MTU_DISCOVER, pathMTU: unix.IPV6_MTU, cmsg: unix.IPV6_RECVERR, dontFragment: unix.IPV6_PMTUDISC_DO,
		header: 48, origin: unix.SO_EE_ORIGIN_ICMP6,
		// RFC 4443 sections 3.1 to 3.3
		expired: 3, unreachable: 1, tooBig: 2, held: 0, prohibited: 1,
		offenderLen: unix.SizeofSockaddrInet6,
		// struct sockaddr_in6, its address at byte 8
		offender: func(raw []byte) netip.Addr { return netip.AddrFrom16([16]byte(raw[8:24])) },
		address: func(to netip.AddrPort) unix.Sockaddr {
			return &unix.SockaddrInet6{Port: int(to.Port()), Addr: to.Addr().As16()}
		},
	},
}

// labDatagrams is a datagram socket of node's of family, connected to lineListen at to, which queues the errors it is answered with and sends with DF
// hops is its hop limit where it is not zero
func labDatagrams(t *testing.T, node *labNode, family labFamily, to netip.Addr, hops int) int {
	t.Helper()
	options := map[int]int{family.recvErr: 1, family.discover: family.dontFragment}
	if hops != 0 {
		options[family.hops] = hops
	}
	fd := -1
	if err := node.ns.Do(func() (err error) {
		if fd, err = unix.Socket(family.domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return err
		}
		for option, value := range options {
			if err := unix.SetsockoptInt(fd, family.level, option, value); err != nil {
				return fmt.Errorf("set socket option %d: %w", option, err)
			}
		}
		return unix.Connect(fd, family.address(netip.AddrPortFrom(to, lineListen)))
	}); err != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("open a socket at %s to %s: %v", node.name, to, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// labWrite is a write of payload on fd
// a write after an error returns that error and sends nothing, and the write after it sends again
func labWrite(fd int, payload []byte) func() {
	return func() { _, _ = unix.Write(fd, payload) }
}

// labError is an ICMP error the kernel queued on a socket, as struct sock_extended_err of include/uapi/linux/errqueue.h gives it, and its sender
type labError struct {
	kind, code uint8
	info       uint32
	from       netip.Addr
}

// labAwaitError writes payload on fd until the kernel queues an error on it, and returns that error
func labAwaitError(t *testing.T, fd int, family labFamily, payload []byte) labError {
	t.Helper()
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		labWrite(fd, payload)()
		if got, ok := labReadError(t, fd, family, labRetry); ok {
			return got
		}
	}
	t.Fatalf("no error reached the socket within %s", convergeBudget)
	return labError{}
}

// labReadError reads the next error the kernel queues on fd within wait, false where none comes
// struct sock_extended_err holds the origin at byte 4, the type at 5, the code at 6 and the info at 8, then the offender's address
func labReadError(t *testing.T, fd int, family labFamily, wait time.Duration) (labError, bool) {
	t.Helper()
	buf, oob := make([]byte, 1<<16), make([]byte, 512)
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(labPoll) {
		_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			t.Fatalf("read the socket's error queue: %v", err)
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			t.Fatalf("parse the socket's control messages: %v", err)
		}
		for _, message := range messages {
			if int(message.Header.Level) != family.level || int(message.Header.Type) != family.cmsg || len(message.Data) < 16+family.offenderLen {
				continue
			}
			if origin := message.Data[4]; origin != family.origin {
				t.Fatalf("the socket read an error of origin %d, want one of ICMP", origin)
			}
			return labError{kind: message.Data[5], code: message.Data[6], info: binary.NativeEndian.Uint32(message.Data[8:]), from: family.offender(message.Data[16:])}, true
		}
	}
	return labError{}, false
}

// labKernelCount reads the counter name from file, a table of the calling thread's namespace in /proc/net/snmp's form or /proc/net/snmp6's
func labKernelCount(file, name string) (uint64, error) {
	body, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(body), "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		// snmp6 gives a name and its value on each line
		if len(fields) == 2 && fields[0] == name {
			return strconv.ParseUint(fields[1], 10, 64)
		}
		// snmp gives a line of names, then a line of their values under the same prefix
		if column := slices.Index(fields, name); column > 0 && i+1 < len(lines) {
			values := strings.Fields(lines[i+1])
			if column < len(values) && values[0] == fields[0] {
				return strconv.ParseUint(values[column], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("%s holds no %s", file, name)
}

// labTUNReceived is the packets the kernel received on the link name, read from the calling thread's namespace
func labTUNReceived(name string) (uint64, error) {
	file, err := os.Open("/proc/thread-self/net/dev")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		link, counters, found := strings.Cut(scanner.Text(), ":")
		if !found || strings.TrimSpace(link) != name {
			continue
		}
		// the received bytes, then the received packets
		fields := strings.Fields(counters)
		if len(fields) < 2 {
			return 0, fmt.Errorf("%s's line of /proc/net/dev holds %q", name, counters)
		}
		return strconv.ParseUint(fields[1], 10, 64)
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("/proc/net/dev holds no %s", name)
}
