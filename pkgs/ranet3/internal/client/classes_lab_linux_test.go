// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
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
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

const (
	classesLAN  = "labl"
	classesHost = "labh"
	// classesUplink and classesFar are the ends labUplink makes
	classesUplink = "labx"
	classesFar    = "labf"
	classesDial   = 5 * time.Second
	classesSeq    = 1000
	classesMSS    = 1460
	// classesSYN and classesACK are TCP's flags of those names, RFC 9293 section 3.1
	classesSYN = 0x02
	classesACK = 0x10
	// classesOverlayRule, classesMainRule and classesOwnRule are internal/kernel's priorities of the overlay's lookup of the mesh's table, of main's, and of this node's own sources'
	classesOverlayRule = 5110
	classesMainRule    = 5410
	classesOwnRule     = 5430
)

// classesFamily is the lab's addresses in one family
type classesFamily struct {
	name string
	// none is a leaf inside the class of none, and address one inside the class translating to class, which the exit holds on lo
	none, address, class netip.Addr
	// mesh is the exit's own mesh address, which the class of address covers, and server the far host's address beyond the uplink
	mesh, server netip.Addr
	// exit and far are the uplink's ends
	exit, far netip.Addr
	// lanExit and lanHost are the LAN's ends, and the network of lanExit is the prefix cap.egress advertises for it
	lanExit, lanHost netip.Prefix
}

var classesFamilies = []classesFamily{{
	name: "IPv4", none: labLeaf4, address: netip.MustParseAddr("203.0.113.65"), class: netip.MustParseAddr("198.51.100.200"),
	mesh: netip.MustParseAddr("203.0.113.129"), server: netip.MustParseAddr("198.51.100.129"),
	exit: labExit4.Addr(), far: labFar4.Addr(),
	lanExit: netip.MustParsePrefix("198.51.100.1/26"), lanHost: netip.MustParsePrefix("198.51.100.2/26"),
}, {
	name: "IPv6", none: labHeadend, address: netip.MustParseAddr("3fff:a:1::1"), class: netip.MustParseAddr("2001:db8:e::10"),
	mesh: netip.MustParseAddr("3fff:e::1"), server: netip.MustParseAddr("2001:db8:d::1"),
	exit: labExit6.Addr(), far: labFar6.Addr(),
	lanExit: netip.MustParsePrefix("2001:db8:c::1/64"), lanHost: netip.MustParsePrefix("2001:db8:c::2/64"),
}}

// classesTranslate is each family's class of none narrower than its class of an address
var classesTranslate = []egress.Class{
	{From: schema.MustPrefix("203.0.113.0/26"), To: egress.Translation{None: true}},
	{From: schema.MustPrefix("203.0.113.0/24"), To: egress.Translation{Addr: classesFamilies[0].class}},
	{From: schema.MustPrefix("3fff:a::/48"), To: egress.Translation{None: true}},
	{From: schema.MustPrefix("3fff::/20"), To: egress.Translation{Addr: classesFamilies[1].class}},
}

// an exit in a namespace of its own, started through New with the border, the reconciler in mode off and the translator main builds,
// with an egress segment, a LAN it advertises under return, a far host beyond its uplink and a host on the LAN, each in a namespace of its own
// and in each family, over UDP and TCP from real sockets at the far host, at the LAN host and on the exit:
// a leaf's flow steered through the SID from inside the class of none reaches the far host from the leaf's address, its reply takes
// the rule at 5110 into the tun toward the leaf, and status counts it untranslated
// one from inside the class of an address reaches the far host from that address, its reply enters the tun toward the leaf, and status counts it translated
// the LAN host's flow to a leaf reaches the tun from the exit's mesh address, and its reply reaches the host by main at 5410
// and the exit's own flow from its mesh address reaches the far host from its class's address by the uplink while another exit's halves are learned
// while the mesh's edge counts nothing forged, of an unowned source or looped in each arm, and the stop leaves no tun, table, rule or route of the node's in the exit's namespace
func TestTUNExitTranslatesEachClassUnderTheDerivedRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	exit, far, host := netnstest.StartThread(t), netnstest.StartThread(t), netnstest.StartThread(t)
	labUplink(t, exit, far)
	every := func(address netip.Addr) netip.Prefix { return netip.PrefixFrom(address, 0).Masked() }
	if err := exit.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddVeth(classesLAN, classesHost, 0, host.Path); err != nil {
			return fmt.Errorf("make the LAN's veth pair: %w", err)
		}
		uplink, err := net.InterfaceByName(classesUplink)
		if err != nil {
			return err
		}
		for _, family := range classesFamilies {
			if err := netlink.RouteVia(uplink.Index, every(family.far), family.far); err != nil {
				return fmt.Errorf("route the exit's default through the far host: %w", err)
			}
			if err := netlink.AddAddresses(classesLAN, family.lanExit); err != nil {
				return err
			}
			if err := netlink.AddAddresses("lo", netip.PrefixFrom(family.class, family.class.BitLen())); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("make the exit's links: %v", err)
	}
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		uplink, err := net.InterfaceByName(classesFar)
		if err != nil {
			return err
		}
		// the far host routes the leaves untranslated and the classes' addresses back to the exit, as an upstream accepting them would
		for _, family := range classesFamilies {
			if err := netlink.AddAddresses(classesFar, netip.PrefixFrom(family.server, family.server.BitLen())); err != nil {
				return err
			}
			back := []netip.Prefix{netip.PrefixFrom(family.class, family.class.BitLen())}
			for _, leaves := range labLeafPrefixes() {
				if leaves.Addr().Is4() == family.server.Is4() {
					back = append(back, leaves)
				}
			}
			for _, prefix := range back {
				if err := netlink.RouteVia(uplink.Index, prefix, family.exit); err != nil {
					return fmt.Errorf("route %s back to the exit: %w", prefix, err)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("make the far host's addresses and routes: %v", err)
	}
	if err := host.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		lan, err := net.InterfaceByName(classesHost)
		if err != nil {
			return err
		}
		for _, family := range classesFamilies {
			if err := netlink.AddAddresses(classesHost, family.lanHost); err != nil {
				return err
			}
			if err := netlink.RouteVia(lan.Index, every(family.far), family.lanExit.Addr()); err != nil {
				return fmt.Errorf("route the LAN host's default through the exit: %w", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("make the LAN host's addresses and routes: %v", err)
	}

	cfg := labConfig(t)
	cfg.Cap.Egress.Return = true
	cfg.Cap.Egress.Translate = classesTranslate
	for _, family := range classesFamilies {
		cfg.Cap.Table.Addresses = append(cfg.Cap.Table.Addresses, schema.PrefixFrom(netip.PrefixFrom(family.mesh, family.mesh.BitLen())))
		cfg.Cap.Egress.Advertise = append(cfg.Cap.Egress.Advertise, schema.PrefixFrom(family.lanExit.Masked()))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the exit's classes are refused: %v", err)
	}
	bus := events.New()
	var node *Client
	if err := exit.Do(func() (err error) {
		node, err = New(cfg, bus)
		return err
	}); err != nil {
		t.Fatalf("start the exit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	stop := sync.OnceFunc(func() {
		cancel()
		runs.Wait()
		node.Close()
	})
	t.Cleanup(stop)

	synthetic := func(name string) *netstack.Peer {
		peer := netstack.NewPeer(name, func(int) (netstack.BatchSealer, error) {
			return nil, errors.New("the peer is synthetic")
		}, func([][]byte) error { return nil }, nil)
		t.Cleanup(peer.Close)
		return peer
	}
	leaf, other := synthetic("example/leaf"), synthetic("example/other-exit")
	// the mesh's table as the speaker holds it: the leaves' prefixes, this node's own addresses and the LAN it advertises
	for _, prefix := range labLeafPrefixes() {
		node.Mesh.Routes.Set(netip.Prefix{}, prefix, leaf)
	}
	for _, family := range classesFamilies {
		node.Mesh.Routes.Set(netip.Prefix{}, netip.PrefixFrom(family.mesh, family.mesh.BitLen()), netstack.Assigned)
		node.Mesh.Routes.Set(netip.Prefix{}, family.lanExit.Masked(), netstack.Local)
	}

	var routes *kernel.Reconciler
	var border *kernelexit.BorderFilter
	if err := exit.Do(func() (err error) {
		if border, err = kernelexit.NewBorderFilter(*cfg.Cap.Border, node.BorderRuntime()); err != nil {
			return err
		}
		rt := node.KernelRuntime()
		// a session counts as live throughout, so the gate is open and only the exit's own rule keeps another exit's halves out of the mesh's table
		rt.Sessions = func() int { return 1 }
		routes, err = kernel.New(*cfg.ReconcilerTable(), rt, node.Mesh.Routes)
		return err
	}); err != nil {
		t.Fatalf("build the border and the reconciler: %v", err)
	}
	translator := labTranslator(t, exit, node, bus)
	node.SetBorder(border)
	for _, owner := range []struct {
		name string
		run  func(context.Context) error
	}{{"the reconciler", routes.Run}, {"the translator", translator.Run}, {"the border", border.Run}} {
		runs.Go(func() {
			if err := owner.run(ctx); err != nil {
				t.Errorf("%s: %v", owner.name, err)
			}
		})
	}
	// the exit's own traffic from a mesh address meets the rule at 5430 from it, whose table holds none of another exit's halves
	waitFor(t, convergeBudget, "both families ready, the SID's /128 originated, the leaves in the mesh table and a rule at 5430 from each mesh address", func() bool {
		stats := translator.Status()
		if !stats.Ready4 || !stats.Ready6 || stats.Skipped != "" || !sidOriginated(node, labSID.String()) {
			return false
		}
		for _, prefix := range labLeafPrefixes() {
			if !labMeshRoute(t, exit, prefix) {
				return false
			}
		}
		rules := classesRules(t, exit)
		for _, family := range classesFamilies {
			if !slices.ContainsFunc(rules, func(rule kernel.DumpedRule) bool {
				return rule.Priority == classesOwnRule && rule.From == netip.PrefixFrom(family.mesh, family.mesh.BitLen())
			}) {
				return false
			}
		}
		return true
	})

	var capture int
	if err := exit.Do(func() (err error) {
		capture, err = openCapture(node.Mesh.Name, labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture the mesh tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })
	udp, tcp := make([]*net.UDPConn, len(classesFamilies)), make([]*net.TCPListener, len(classesFamilies))
	if err := far.Do(func() (err error) {
		for i, family := range classesFamilies {
			at := netip.AddrPortFrom(family.server, labPort)
			if udp[i], err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(at)); err != nil {
				return err
			}
			if tcp[i], err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("listen on the far host: %v", err)
	}
	t.Cleanup(func() {
		for i := range classesFamilies {
			_ = udp[i].Close()
			_ = tcp[i].Close()
		}
	})
	steer := func(inner []byte) {
		outer, err := srv6.Encapsulate(inner, labHeadend, []netip.Addr{labSID})
		if err != nil {
			t.Fatalf("encapsulate toward %s: %v", labSID, err)
		}
		node.Mesh.DeliverInbound(outer, 0)
	}
	edge := func(t *testing.T) func() {
		before := node.Mesh.TransitCounters()
		return func() {
			got := node.Mesh.TransitCounters()
			if forged, unowned, looped := got.Forged-before.Forged, got.UnownedSource-before.UnownedSource, got.Looped-before.Looped; forged != 0 || unowned != 0 || looped != 0 {
				t.Errorf("the mesh's edge counted %d forged, %d of an unowned source and %d looped in this arm, want none", forged, unowned, looped)
			}
		}
	}
	leafFlows := func(t *testing.T, i int, source, want netip.Addr) {
		t.Helper()
		family := classesFamilies[i]
		payload := []byte("from " + source.String())
		from := labReceive(t, udp[i], payload, func() { steer(udpPacket(source, family.server, labLeafPort, labPort, payload)) })
		if from.Addr().Unmap() != want {
			t.Errorf("the far host read the leaf's UDP from %s from %s, want %s", source, from, want)
		}
		reply := []byte("to " + source.String())
		labCaptureReply(t, capture, source, reply, func() {
			if _, err := udp[i].WriteToUDPAddrPort(reply, from); err != nil {
				t.Fatalf("reply from the far host: %v", err)
			}
		})
		if from := classesAccepted(t, capture, tcp[i], steer, source, family.server); from.Addr().Unmap() != want {
			t.Errorf("the far host accepted the leaf's TCP from %s from %s, want %s", source, from, want)
		}
	}

	t.Run("a class of none", func(t *testing.T) {
		defer edge(t)()
		before := translator.Status().Rules.Untranslated
		for i, family := range classesFamilies {
			t.Run(family.name, func(t *testing.T) {
				leafFlows(t, i, family.none, family.none)
				if priority, table, device := classesTaken(t, exit, family.server, family.none, classesUplink); priority != classesOverlayRule || table != uint32(kernel.DefaultTable) || device != labTUN {
					t.Errorf("a reply to %s from %s arriving on the uplink ends at the rule at %d in table %d by %s, want %d in %d by %s",
						family.none, family.server, priority, table, device, classesOverlayRule, kernel.DefaultTable, labTUN)
				}
			})
		}
		waitFor(t, convergeBudget, "status to count the flows of none untranslated", func() bool { return translator.Status().Rules.Untranslated > before })
	})

	t.Run("a class of an address", func(t *testing.T) {
		defer edge(t)()
		before := translator.Status().Rules.Flows
		for i, family := range classesFamilies {
			t.Run(family.name, func(t *testing.T) { leafFlows(t, i, family.address, family.class) })
		}
		waitFor(t, convergeBudget, "status to count the flows of the address translated", func() bool { return translator.Status().Rules.Flows > before })
	})

	t.Run("return from the LAN", func(t *testing.T) {
		defer edge(t)()
		for _, family := range classesFamilies {
			t.Run(family.name, func(t *testing.T) {
				member := netip.AddrPortFrom(family.address, labPort)
				var conn *net.UDPConn
				if err := host.Do(func() (err error) {
					conn, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.lanHost.Addr(), labLeafPort)))
					return err
				}); err != nil {
					t.Fatalf("open the LAN host's socket: %v", err)
				}
				defer conn.Close()
				payload := []byte("from the LAN over " + family.name)
				in := classesAwait(t, capture, func() { _, _ = conn.WriteToUDPAddrPort(payload, member) }, func(h classesHeader) bool {
					return h.protocol == unix.IPPROTO_UDP && h.destination == member && bytes.Equal(h.payload, payload)
				})
				if in.source.Addr() != family.mesh {
					t.Errorf("the LAN host's UDP reached the tun from %s, want the exit's mesh address %s", in.source, family.mesh)
				}
				reply := []byte("to the LAN over " + family.name)
				if from := labReceive(t, conn, reply, func() {
					node.Mesh.DeliverInbound(udpPacket(member.Addr(), in.source.Addr(), member.Port(), in.source.Port(), reply), 0)
				}); from.Addr().Unmap() != member.Addr() || from.Port() != member.Port() {
					t.Errorf("the LAN host read the reply from %s, want %s", from, member)
				}

				dialed := make(chan error, 1)
				go func() {
					dialed <- host.Do(func() error {
						dialer := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(family.lanHost.Addr(), 0)), Timeout: classesDial}
						conn, err := dialer.Dial("tcp", member.String())
						if err == nil {
							_ = conn.Close()
						}
						return err
					})
				}()
				syn := classesAwait(t, capture, func() {}, func(h classesHeader) bool {
					return h.protocol == unix.IPPROTO_TCP && h.destination == member && h.flags&(classesSYN|classesACK) == classesSYN
				})
				if syn.source.Addr() != family.mesh {
					t.Errorf("the LAN host's SYN reached the tun from %s, want the exit's mesh address %s", syn.source, family.mesh)
				}
				synAck := classesTCP(member.Addr(), syn.source.Addr(), member.Port(), syn.source.Port(), classesSeq, syn.seq+1, classesSYN|classesACK)
				for answered := false; !answered; {
					node.Mesh.DeliverInbound(synAck, 0)
					select {
					case err := <-dialed:
						answered = true
						if err != nil {
							t.Errorf("the LAN host's connect to %s: %v", member, err)
						}
					case <-time.After(labRetry):
					}
				}
				if priority, table, device := classesTaken(t, exit, member.Addr(), family.lanHost.Addr(), labTUN); priority != classesMainRule || table != unix.RT_TABLE_MAIN || device != classesLAN {
					t.Errorf("a reply to %s from %s arriving on the tun ends at the rule at %d in table %d by %s, want %d in main by %s",
						family.lanHost.Addr(), member.Addr(), priority, table, device, classesMainRule, classesLAN)
				}
			})
		}
	})

	t.Run("the exit's own traffic beside another exit's halves", func(t *testing.T) {
		defer edge(t)()
		halves := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"), netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
		}
		// a subnet of the other exit's, set after the halves, whose route in the mesh table marks a pass that read them
		subnet := netip.MustParsePrefix("198.51.100.64/26")
		for _, prefix := range append(halves, subnet) {
			node.Mesh.Routes.Set(netip.Prefix{}, prefix, other)
		}
		t.Cleanup(func() {
			for _, prefix := range append(halves, subnet) {
				node.Mesh.Routes.Remove(netip.Prefix{}, prefix)
			}
		})
		waitFor(t, convergeBudget, "a pass reading the other exit's halves and its subnet", func() bool { return labMeshRoute(t, exit, subnet) })
		for i, family := range classesFamilies {
			t.Run(family.name, func(t *testing.T) {
				var conn *net.UDPConn
				if err := exit.Do(func() (err error) {
					conn, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.mesh, 0)))
					return err
				}); err != nil {
					t.Fatalf("open the exit's socket on %s: %v", family.mesh, err)
				}
				defer conn.Close()
				payload := []byte("from the exit's own " + family.mesh.String())
				server := netip.AddrPortFrom(family.server, labPort)
				if from := labReceive(t, udp[i], payload, func() { _, _ = conn.WriteToUDPAddrPort(payload, server) }); from.Addr().Unmap() != family.class {
					t.Errorf("the far host read the exit's own UDP from %s, want its class's address %s", from, family.class)
				}
				if labCaptured(capture, func(packet []byte) bool {
					_, _, carried, ok := labUDPOf(packet)
					return ok && bytes.Equal(carried, payload)
				}) {
					t.Errorf("the exit's own UDP from %s crossed the tun", family.mesh)
				}
				if err := exit.Do(func() error {
					dialer := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(family.mesh, 0)), Timeout: classesDial}
					conn, err := dialer.Dial("tcp", server.String())
					if err == nil {
						_ = conn.Close()
					}
					return err
				}); err != nil {
					t.Fatalf("the exit's own connect from %s to %s: %v", family.mesh, server, err)
				}
				if err := tcp[i].SetDeadline(time.Now().Add(classesDial)); err != nil {
					t.Fatal(err)
				}
				accepted, err := tcp[i].AcceptTCP()
				if err != nil {
					t.Fatalf("the far host accepted no connection from the exit: %v", err)
				}
				from := accepted.RemoteAddr().(*net.TCPAddr).AddrPort()
				_ = accepted.Close()
				if from.Addr().Unmap() != family.class {
					t.Errorf("the far host accepted the exit's own TCP from %s, want its class's address %s", from, family.class)
				}
			})
		}
	})

	stop()
	if err := exit.Do(func() error {
		if _, err := net.InterfaceByName(labTUN); err == nil {
			return fmt.Errorf("%s outlived the node", labTUN)
		}
		for _, family := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6, unix.NFPROTO_INET} {
			if err := labDeleteTable(family, kernelexit.TableName); !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("deleting the table of family %d once the node stopped answered %v, want it gone", family, err)
			}
		}
		rules, err := dumpRules()
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if rule.protocol == kernel.DefaultProtocol {
				return fmt.Errorf("a rule of the reconciler's outlived it: %v", rule)
			}
		}
		left, err := dumpRoutes()
		if err != nil {
			return err
		}
		for _, route := range left {
			if route.protocol == kernel.DefaultProtocol {
				return fmt.Errorf("a route of the reconciler's outlived it: %v", route)
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

func classesRules(t *testing.T, exit *netnstest.Thread) []kernel.DumpedRule {
	t.Helper()
	var rules []kernel.DumpedRule
	if err := exit.Do(func() (err error) {
		rules, err = kernel.DumpRules()
		return err
	}); err != nil {
		t.Fatalf("dump the exit's rules: %v", err)
	}
	return rules
}

// classesTaken is the priority of the rule the exit's kernel ends a lookup from src to dst arriving on iif at, the table it read and the device of the route's first hop
func classesTaken(t *testing.T, exit *netnstest.Thread, src, dst netip.Addr, iif string) (uint32, uint32, string) {
	t.Helper()
	rules := classesRules(t, exit)
	var route kernel.MatchedRoute
	if err := exit.Do(func() (err error) {
		route, err = kernel.RouteGet(src, dst, iif)
		return err
	}); err != nil {
		t.Fatalf("look up %s from %s arriving on %s: %v", dst, src, iif, err)
	}
	taken := kernel.TakeRule(rules, src, dst, iif, route, nil)
	if !taken.Found || len(route.NextHops) == 0 {
		t.Fatalf("the lookup of %s from %s arriving on %s found %+v, which no rule or hop of the exit's names", dst, src, iif, route)
	}
	return taken.Rule.Priority, route.Table, route.NextHops[0].Device
}

// classesHeader is an IP packet with no extension header as the lab reads it: its addresses and ports, its transport protocol,
// for TCP its sequence number and flags, and what it carries past its transport header
type classesHeader struct {
	source, destination netip.AddrPort
	protocol            byte
	seq                 uint32
	flags               byte
	payload             []byte
}

func classesHeaderOf(raw []byte) (classesHeader, bool) {
	var h classesHeader
	source, destination, version := packet.Addrs(raw)
	var l4 []byte
	switch version {
	case 4:
		h.protocol, l4 = raw[9], raw[int(raw[0]&0x0f)*4:]
	case 6:
		h.protocol, l4 = raw[6], raw[40:]
	default:
		return h, false
	}
	switch {
	case h.protocol == unix.IPPROTO_UDP && len(l4) >= 8:
		h.payload = l4[8:]
	case h.protocol == unix.IPPROTO_TCP && len(l4) >= 20 && len(l4) >= int(l4[12]>>4)*4:
		h.seq, h.flags, h.payload = binary.BigEndian.Uint32(l4[4:]), l4[13], l4[int(l4[12]>>4)*4:]
	default:
		return h, false
	}
	h.source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(l4))
	h.destination = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(l4[2:]))
	return h, true
}

func classesAwait(t *testing.T, capture int, send func(), match func(classesHeader) bool) classesHeader {
	t.Helper()
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		send()
		var got classesHeader
		if labCaptured(capture, func(packet []byte) bool {
			h, ok := classesHeaderOf(packet)
			if ok && match(h) {
				got = h
				return true
			}
			return false
		}) {
			return got
		}
	}
	t.Fatalf("the tun carried no packet the arm waits for within %s", convergeBudget)
	return classesHeader{}
}

// classesTCP is synTo's packet from src to dst made a segment from port sport to dport of seq, ack and flags, its MSS option kept
func classesTCP(src, dst netip.Addr, sport, dport uint16, seq, ack uint32, flags byte) []byte {
	raw := synTo(src, dst, classesMSS)
	segment := raw[tcpOffset(raw):]
	binary.BigEndian.PutUint16(segment[0:], sport)
	binary.BigEndian.PutUint16(segment[2:], dport)
	binary.BigEndian.PutUint32(segment[4:], seq)
	binary.BigEndian.PutUint32(segment[8:], ack)
	segment[13] = flags
	sumTCP(raw)
	return raw
}

// classesAccepted steers the leaf's SYN from source to server's labPort until the capture reads the SYN-ACK to it,
// then its ACK until listener accepts the connection, and answers where the far host read it from
func classesAccepted(t *testing.T, capture int, listener *net.TCPListener, steer func([]byte), source, server netip.Addr) netip.AddrPort {
	t.Helper()
	leaf := netip.AddrPortFrom(source, labLeafPort)
	synAck := classesAwait(t, capture, func() { steer(classesTCP(source, server, labLeafPort, labPort, classesSeq, 0, classesSYN)) }, func(h classesHeader) bool {
		return h.protocol == unix.IPPROTO_TCP && h.destination == leaf && h.flags&(classesSYN|classesACK) == classesSYN|classesACK
	})
	ack := classesTCP(source, server, labLeafPort, labPort, classesSeq+1, synAck.seq+1, classesACK)
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		steer(ack)
		if err := listener.SetDeadline(time.Now().Add(labRetry)); err != nil {
			t.Fatal(err)
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			continue
		}
		from := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		_ = conn.Close()
		return from
	}
	t.Fatalf("the far host accepted no connection from %s within %s", source, convergeBudget)
	return netip.AddrPort{}
}
