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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

const (
	// labTUN is the exit's mesh tun
	labTUN = "lab0"
	// labPort is the far host's listening port, and labLeafPort the port the leaf sends from
	labPort     = 9000
	labLeafPort = 40000
	// labRetry is how long one read waits before a packet is sent again, and labQuiet how long a packet that must not arrive is waited for
	labRetry = 250 * time.Millisecond
	labQuiet = time.Second
	// labAheadPriority is a rule's the lab puts ahead of labConfig's to rules
	labAheadPriority = 50
	// labSkipped6 is the translator's word for an exit whose mesh routes no IPv6 member
	labSkipped6 = "lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay"
)

var (
	labSID     = netip.MustParseAddr("3fff:1:69c:8c6::3")
	labHeadend = netip.MustParseAddr("3fff:a::1")
	labLeaf4   = netip.MustParseAddr("198.18.104.1")
	labOutside = netip.MustParseAddr("10.9.9.9")
	// the exit's and the far host's ends of the uplink
	labExit4 = netip.MustParsePrefix("192.0.2.1/24")
	labFar4  = netip.MustParsePrefix("192.0.2.2/24")
	labExit6 = netip.MustParsePrefix("2001:db8:f::1/64")
	labFar6  = netip.MustParsePrefix("2001:db8:f::2/64")
	// labLeaves is the allow list, and the prefixes the to rules send into the mesh table
	labLeaves = []string{"3fff:a::/32", "198.18.104.0/24"}
	// labDefaults is the default of each family the exit of the egress lab advertises
	labDefaults = map[int]netip.Prefix{4: netip.MustParsePrefix("0.0.0.0/0"), 6: netip.MustParsePrefix("::/0")}
)

// an exit in a namespace of its own, started through New with the border, the reconciler and the translator main builds, holds the tun, the uplink and the loopback and no other link
// a synthetic leaf's packets of each family, steered through its egress SID and sent through the default it advertises, leave its one tun and its uplink translated to the exit's uplink address
// a route sending a lookup's address back into the tun, a rule sending the leaf's address out of the uplink and IPv4 forwarding off on the tun each hold their family not ready with the reason naming it
// and the rule with strict reverse path filtering on the tun holds IPv4 by its forward lookup, naming the filter
// its default and the SID's /128 retracted and nothing of it reaching the far host, until the change goes
// an inner packet to the leaf at the SID is refused and counted, with nothing at the far host or the leaf
// and with the leaf's IPv6 prefix gone the IPv6 lookups are skipped, said so, and IPv6 egresses from a network of the leaf's outside the overlay
func TestTUNExitEgressesBothModesThroughItsOneTun(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	exit, far := netnstest.StartThread(t), netnstest.StartThread(t)
	labUplink(t, exit, far, "")
	// the exit routes every other destination out of its uplink to the far host, as an exit does, which the translator's lookups read
	if err := exit.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		uplink, err := net.InterfaceByName("labx")
		if err != nil {
			return err
		}
		for _, gateway := range []netip.Addr{labFar4.Addr(), labFar6.Addr()} {
			every := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			if gateway.Is4() {
				every = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			if err := labRouteVia(netlink, uplink.Index, every, gateway); err != nil {
				return fmt.Errorf("route %s through the far host: %w", every, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("route the exit's default out of its uplink: %v", err)
	}
	cfg := labConfig(t)
	for _, prefix := range labDefaults {
		cfg.Cap.Egress.Advertise = append(cfg.Cap.Egress.Advertise, schema.PrefixFrom(prefix))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the exit advertising a default of each family is refused: %v", err)
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
	steer := func(inner []byte) {
		t.Helper()
		outer, err := srv6.Encapsulate(inner, labHeadend, []netip.Addr{labSID})
		if err != nil {
			t.Fatalf("encapsulate toward %s: %v", labSID, err)
		}
		node.Mesh.DeliverInbound(outer, 0)
	}

	// the replies leave through the mesh tun by a route the reconciler installs for the leaf's prefixes, as babel would select it
	// the route to the leaf's prefixes is also the reply route the egress segment needs for an inner source before it egresses anything
	// handed counts the packets the mesh tried to send the leaf
	var handed atomic.Int64
	leaf := netstack.NewPeer("example/leaf", func(count int) (netstack.BatchSealer, error) {
		handed.Add(int64(count))
		return nil, errors.New("the leaf is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(leaf.Close)
	for _, prefix := range labLeafPrefixes() {
		node.Mesh.Routes.Set(netip.Prefix{}, prefix, leaf)
	}

	before := node.Mesh.SegmentCounters()
	steer(udpPacket(labHeadend, labFar6.Addr(), labLeafPort, labPort, []byte("before the first pass")))
	if got := node.Mesh.SegmentCounters(); got.NotReady != before.NotReady+1 || got.Egressed != before.Egressed {
		t.Errorf("an egress result before the translator's first pass counted %+v, want one more not ready", got)
	}

	var routes *kernel.Reconciler
	var border *egress.BorderFilter
	if err := exit.Do(func() (err error) {
		if border, err = egress.NewBorderFilter(*cfg.Cap.Border, node.BorderRuntime()); err != nil {
			return err
		}
		routes, err = kernel.New(*cfg.Cap.Table, node.KernelRuntime(), node.Mesh.Routes)
		return err
	}); err != nil {
		t.Fatalf("build the border and the reconciler: %v", err)
	}
	translator := labTranslator(t, exit, node, bus)
	node.SetBorder(border)
	runs.Go(func() {
		if err := routes.Run(ctx); err != nil {
			t.Errorf("the reconciler: %v", err)
		}
	})
	runs.Go(func() {
		if err := translator.Run(ctx); err != nil {
			t.Errorf("the translator: %v", err)
		}
	})
	runs.Go(func() {
		if err := border.Run(ctx); err != nil {
			t.Errorf("the border: %v", err)
		}
	})
	// the leaf's prefixes are the members the lookups read from, so a pass skipping them has not read the path at all
	serving := func() bool {
		stats := translator.Stats()
		return stats.Ready4 && stats.Ready6 && stats.Skipped == "" && labOriginated(node, labDefaults[4]) && labOriginated(node, labDefaults[6]) && sidOriginated(node, labSID.String())
	}
	waitFor(t, convergeBudget, "both families ready by their lookups, the defaults and the SID's /128 originated and the mesh table covering the leaves", func() bool {
		return serving() && labMeshRoute(t, exit, labLeafPrefixes()[0]) && labMeshRoute(t, exit, labLeafPrefixes()[1])
	})

	t.Run("the exit's links", func(t *testing.T) {
		var names []string
		if err := exit.Do(func() error {
			links, err := net.Interfaces()
			for _, link := range links {
				names = append(names, link.Name)
			}
			return err
		}); err != nil {
			t.Fatalf("list the exit's links: %v", err)
		}
		slices.Sort(names)
		if want := []string{labTUN, "labx", "lo"}; !slices.Equal(names, want) {
			t.Errorf("the exit holds the links %v, want %v, the tun, the uplink and the loopback alone", names, want)
		}
	})

	var listeners [2]*net.UDPConn
	if err := far.Do(func() error {
		for i, address := range []netip.Addr{labFar4.Addr(), labFar6.Addr()} {
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, labPort)))
			if err != nil {
				return err
			}
			listeners[i] = conn
		}
		return nil
	}); err != nil {
		t.Fatalf("listen on the far host: %v", err)
	}
	for _, conn := range listeners {
		t.Cleanup(func() { _ = conn.Close() })
	}
	var capture int
	if err := exit.Do(func() (err error) {
		capture, err = openCapture(node.Mesh.Name, labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture the mesh tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })
	var uplink int
	if err := far.Do(func() (err error) {
		uplink, err = openCapture("labf", labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture the far host's end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(uplink) })

	type labArm struct {
		name            string
		family          int
		leaf, far, exit netip.Addr
		listener        *net.UDPConn
	}
	arms := []labArm{
		{"IPv4", 4, labLeaf4, labFar4.Addr(), labExit4.Addr(), listeners[0]},
		{"IPv6", 6, labHeadend, labFar6.Addr(), labExit6.Addr(), listeners[1]},
	}
	// send hands the exit a leaf's packet as the leaf's session delivers it, for the default the exit advertises
	send := func(inner []byte) { node.Mesh.DeliverInbound(inner, 0) }
	egressed := func() uint64 { return node.Mesh.SegmentCounters().Egressed }
	delivered := func() uint64 { return node.Mesh.TransitCounters().Delivered }
	// carry hands the exit a leaf's packet for the far host through hand until the far host reads it, which must be from the exit's uplink address and counted
	carry := func(t *testing.T, hand func([]byte), counted func() uint64, leafAddr, farAddr, exitAddr netip.Addr, listener *net.UDPConn, payload string) netip.AddrPort {
		t.Helper()
		before := counted()
		from := labReceive(t, listener, []byte(payload), func() { hand(udpPacket(leafAddr, farAddr, labLeafPort, labPort, []byte(payload))) })
		if from.Addr().Unmap() != exitAddr {
			t.Errorf("the far host read %q from %s, want the exit's uplink address %s", payload, from, exitAddr)
		}
		if counted() <= before {
			t.Errorf("the far host read %q and the exit counted nothing for it", payload)
		}
		return from
	}
	// replies counts the replies the capture read crossing the tun, which the mesh reads off it and hands the leaf's peer later
	var replies int64
	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			for _, mode := range []struct {
				name    string
				hand    func([]byte)
				counted func() uint64
			}{{"steered", steer, egressed}, {"sent", send, delivered}} {
				from := carry(t, mode.hand, mode.counted, arm.leaf, arm.far, arm.exit, arm.listener, mode.name+" "+arm.name)
				reply := []byte("reply to " + mode.name + " " + arm.name)
				labCaptureReply(t, capture, arm.leaf, reply, func() {
					if _, err := arm.listener.WriteToUDPAddrPort(reply, from); err != nil {
						t.Fatalf("reply from the far host: %v", err)
					}
				})
				// a reply sent again before the capture read the first crossed the tun too
				replies += 1 + int64(labCount(capture, labReplyTo(arm.leaf, reply)))
			}
		})
	}

	t.Run("an inner packet for the leaf", func(t *testing.T) {
		waitFor(t, convergeBudget, "the replies the capture read handed to the leaf's peer", func() bool { return handed.Load() >= replies })
		for i, arm := range arms {
			destination := labLeafPrefixes()[1-i].Addr().Next().Next()
			payload := []byte("for the leaf over " + arm.name)
			before, handedBefore := node.Mesh.SegmentCounters(), handed.Load()
			steer(udpPacket(arm.leaf, destination, labLeafPort, labPort, payload))
			got := node.Mesh.SegmentCounters()
			if got.Refused != before.Refused+1 || got.Dropped != before.Dropped+1 || got.Egressed != before.Egressed || got.Forwarded != before.Forwarded {
				t.Errorf("an %s inner packet for the leaf's %s counted %+v after %+v, want one more refused and dropped and nothing egressed or forwarded", arm.name, destination, got, before)
			}
			if labCaptured(uplink, func(packet []byte) bool {
				_, _, carried, ok := labUDPOf(packet)
				return ok && bytes.Equal(carried, payload)
			}) {
				t.Errorf("the far host's link carried the %s inner packet for the leaf", arm.name)
			}
			if got := handed.Load(); got != handedBefore {
				t.Errorf("the mesh tried to send the leaf %d packets around the %s inner packet for it, want none", got-handedBefore, arm.name)
			}
		}
	})

	// the lookups read each default at its read address, 128.0.0.0 and 8000::, from the read address of the leaf's prefix of its family
	back := map[int]netip.Prefix{4: netip.MustParsePrefix("128.0.0.0/1"), 6: netip.MustParsePrefix("8000::/1")}
	member := map[int]netip.Prefix{4: netip.MustParsePrefix("198.18.104.128/32"), 6: netip.MustParsePrefix("3fff:a:8000::/128")}
	inNetlink := func(f func(netnstest.Netlink) error) func() error {
		return func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			return f(netlink)
		}
	}
	// held makes change in the exit's namespace and waits for arm's family not ready by a reason holding reason, with its default and the SID's /128 retracted
	// then hands the exit a packet of the family in each mode, which the far host must not read, undoes the change and waits for both families served again
	// a hold that fails is undone all the same, so the arms after it start from an exit serving both families
	held := func(t *testing.T, arm labArm, reason string, change, undo func() error) {
		t.Helper()
		undone := false
		t.Cleanup(func() {
			if !undone {
				_ = exit.Do(undo)
			}
		})
		if err := exit.Do(change); err != nil {
			t.Fatalf("hold %s: %v", arm.name, err)
		}
		waitFor(t, convergeBudget, arm.name+" not ready by "+reason+", its default and the SID's /128 retracted", func() bool {
			stats := translator.Stats()
			ready := map[int]bool{4: stats.Ready4, 6: stats.Ready6}[arm.family]
			return !ready && strings.Contains(stats.Unready, reason) && !labOriginated(node, labDefaults[arm.family]) && !sidOriginated(node, labSID.String())
		})
		payload := []byte("held " + arm.name)
		steer(udpPacket(arm.leaf, arm.far, labLeafPort, labPort, payload))
		send(udpPacket(arm.leaf, arm.far, labLeafPort, labPort, payload))
		labQuietFor(t, arm.listener, payload)
		undone = true
		if err := exit.Do(undo); err != nil {
			t.Fatalf("undo the hold of %s: %v", arm.name, err)
		}
		waitFor(t, convergeBudget, "both families served again once the hold of "+arm.name+" went", serving)
	}
	for _, arm := range arms {
		t.Run(arm.name+" lookup sent back into the tun", func(t *testing.T) {
			held(t, arm, "leaves by "+labTUN+" again",
				inNetlink(func(netlink netnstest.Netlink) error {
					return labRouteDevice(netlink, unix.RTM_NEWROUTE, labTUN, back[arm.family])
				}),
				inNetlink(func(netlink netnstest.Netlink) error {
					return labRouteDevice(netlink, unix.RTM_DELROUTE, labTUN, back[arm.family])
				}))
		})
		// the reverse path check of an IPv4 forward lookup reads the member's route arriving on the uplink, as the reply lookup does
		// so with reverse path filtering on the tun the forward lookup fails first, and off it the reply lookup is the one to say so
		type filtered struct{ filter, reason string }
		filters := []filtered{{"", "leaves by labx rather than " + labTUN}}
		if arm.family == 4 {
			filters = []filtered{{"0", "leaves by labx rather than " + labTUN}, {"1", "with reverse path filtering at 1 on " + labTUN}}
		}
		for _, f := range filters {
			filter, reason := f.filter, f.reason
			name := arm.name + " reply sent out of the uplink"
			if filter != "" {
				name += " with rp_filter " + filter
			}
			t.Run(name, func(t *testing.T) {
				rule := func(kind uint16) func() error {
					return inNetlink(func(netlink netnstest.Netlink) error {
						return labRuleToMain(netlink, kind, "labx", member[arm.family], labAheadPriority)
					})
				}
				saved := map[string][]byte{}
				held(t, arm, reason,
					func() error {
						for _, device := range []string{"all", labTUN} {
							if filter == "" {
								break
							}
							path := "/proc/sys/net/ipv4/conf/" + device + "/rp_filter"
							was, err := os.ReadFile(path)
							if err != nil {
								return err
							}
							saved[path] = was
							if err := os.WriteFile(path, []byte(filter+"\n"), 0o644); err != nil {
								return err
							}
						}
						return rule(unix.RTM_NEWRULE)()
					},
					func() error {
						err := rule(unix.RTM_DELRULE)()
						for path, was := range saved {
							err = errors.Join(err, os.WriteFile(path, was, 0o644))
						}
						return err
					})
			})
		}
	}
	t.Run("IPv4 forwarding off on the tun", func(t *testing.T) {
		path := "/proc/sys/net/ipv4/conf/" + labTUN + "/forwarding"
		held(t, arms[0], "with net.ipv4.conf."+labTUN+".forwarding at 0",
			func() error { return os.WriteFile(path, []byte("0\n"), 0o644) },
			func() error { return os.WriteFile(path, []byte("1\n"), 0o644) })
	})

	t.Run("no IPv6 prefix of the leaf's inside the overlay", func(t *testing.T) {
		inside := labLeafPrefixes()[0]
		// a network of the leaf's outside the overlay, whose hosts the mesh routes a reply to and the lookups never read from
		outside := netip.MustParsePrefix("2001:db8:a::/48")
		node.Mesh.Routes.Remove(netip.Prefix{}, inside)
		node.Mesh.Routes.Set(netip.Prefix{}, outside, leaf)
		waitFor(t, convergeBudget, "the IPv6 lookups skipped and said so, both families ready", func() bool {
			stats := translator.Stats()
			return stats.Ready4 && stats.Ready6 && stats.Skipped == labSkipped6 && slices.Contains(skips(bus), labSkipped6)
		})
		carry(t, send, delivered, outside.Addr().Next(), labFar6.Addr(), labExit6.Addr(), listeners[1], "sent from outside the overlay with the IPv6 lookups skipped")
		node.Mesh.Routes.Remove(netip.Prefix{}, outside)
		node.Mesh.Routes.Set(netip.Prefix{}, inside, leaf)
		waitFor(t, convergeBudget, "the IPv6 lookups read again", serving)
	})

	t.Run("a source outside the allow list", func(t *testing.T) {
		before := node.Mesh.SegmentCounters()
		payload := []byte("from outside the list")
		steer(udpPacket(labOutside, labFar4.Addr(), labLeafPort, labPort, payload))
		if got := node.Mesh.SegmentCounters(); got.Refused != before.Refused+1 || got.Egressed != before.Egressed {
			t.Errorf("a source outside the list counted %+v, want one more refused", got)
		}
		labQuietFor(t, listeners[0], payload)
	})

	t.Run("another writer deleting the ip table", func(t *testing.T) {
		mark := len(readiness(bus))
		if err := exit.Do(func() error { return labDeleteTable(unix.NFPROTO_IPV4, egress.TableName) }); err != nil {
			t.Fatalf("delete the ip table: %v", err)
		}
		waitFor(t, convergeBudget, "the translator to report the egress segments not ready and then ready again", func() bool {
			moved := readiness(bus)[mark:]
			down := slices.Index(moved, "false false")
			return down >= 0 && slices.Contains(moved[down:], "true true")
		})
		carry(t, steer, egressed, labLeaf4, labFar4.Addr(), labExit4.Addr(), listeners[0], "steered after the table came back")
	})

	t.Run("a packet from the far host to the SID", func(t *testing.T) {
		spec := "drop ipv6 destination " + labSID.String()
		dropped := borderDropped(t, exit, border, spec)
		before := node.Mesh.SegmentCounters()
		if err := far.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			uplink, err := net.InterfaceByName("labf")
			if err != nil {
				return err
			}
			if err := labRouteVia(netlink, uplink.Index, netip.PrefixFrom(labSID, 128), labExit6.Addr()); err != nil {
				return err
			}
			conn, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(labSID, labPort)))
			if err != nil {
				return err
			}
			defer conn.Close()
			for range 3 {
				if _, err := conn.Write([]byte("injected from beyond the uplink")); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("send to the SID from the far host: %v", err)
		}
		time.Sleep(labQuiet)
		if got := node.Mesh.SegmentCounters(); got != before {
			t.Errorf("packets sent to the SID from beyond the uplink moved the counters from %+v to %+v", before, got)
		}
		if got := borderDropped(t, exit, border, spec); got < dropped+3 {
			t.Errorf("the border counted %d packets to the SID from beyond the uplink after %d, want three more", got, dropped)
		}
	})

	stop()
	if err := exit.Do(func() error {
		if _, err := net.InterfaceByName(labTUN); err == nil {
			return fmt.Errorf("%s outlived the node", labTUN)
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
		for _, family := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
			if err := labDeleteTable(family, egress.TableName); !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("deleting the translator's table of family %d once it stopped answered %v, want it gone", family, err)
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// the mesh takes the readiness before the announcement is rebuilt, so the
// SID's /128 follows the word just given and never the one before it, the
// mesh's word read by what it egresses into a real tun
func TestTUNSetEgressReadyMovesTheMeshBeforeTheAnnouncement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(labSID.String(), labLeaves...)) })
	carried := meshCarrying(t, c)
	speakerRecording(t, c, bus)
	var rebuiltWith [2]bool
	c.SetEgressAnnounce(func() []netip.Prefix {
		rebuiltWith = carried()
		return nil
	})
	for _, step := range []struct {
		v4, v6, serves bool
	}{
		{true, true, true},
		{false, true, false},
		{false, false, false},
		{true, true, true},
		{true, false, true},
	} {
		c.SetEgressReady(step.v4, step.v6, step.serves)
		if got := carried(); got != [2]bool{step.v4, step.v6} {
			t.Errorf("the mesh carries %v after SetEgressReady(%v, %v, %v)", got, step.v4, step.v6, step.serves)
		}
		if rebuiltWith != [2]bool{step.v4, step.v6} {
			t.Errorf("SetEgressReady(%v, %v, %v) rebuilt the announcement while the mesh carried %v", step.v4, step.v6, step.serves, rebuiltWith)
		}
		if got := sidOriginated(c, labSID.String()); got != step.serves {
			t.Errorf("after SetEgressReady(%v, %v, %v) the SID's /128 is originated %v", step.v4, step.v6, step.serves, got)
		}
	}
}

func labLeafPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(labLeaves))
	for _, prefix := range labLeaves {
		out = append(out, netip.MustParsePrefix(prefix))
	}
	return out
}

// readiness is every egress.ready recorded on bus, as its ipv4 and ipv6 values
func readiness(bus *events.Bus) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
		out = append(out, event.Attrs["ipv4"]+" "+event.Attrs["ipv6"])
	}
	return out
}

// skips is every egress.ready recorded on bus, as what it says the lookups skipped
func skips(bus *events.Bus) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
		out = append(out, event.Attrs["skipped"])
	}
	return out
}

// labOriginated reports the speaker originating prefix with no source prefix
func labOriginated(c *Client, prefix netip.Prefix) bool {
	return slices.ContainsFunc(c.speaker.Originated(), func(route babel.OriginatedRoute) bool {
		return route.Destination == prefix && !route.Source.IsValid()
	})
}

// labRouteDevice adds or deletes, as kind says, the route to through the link name in the main table of the calling thread's namespace, with no gateway
func labRouteDevice(netlink netnstest.Netlink, kind uint16, name string, to netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	family, scope := byte(unix.AF_INET6), byte(unix.RT_SCOPE_UNIVERSE)
	if to.Addr().Is4() {
		family, scope = unix.AF_INET, unix.RT_SCOPE_LINK
	}
	header := []byte{family, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, scope, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()), netnstest.Attr(unix.RTA_OIF, netnstest.U32(uint32(link.Index))))
	var flags uint16
	if kind == unix.RTM_NEWROUTE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	if err := netlink.Request(kind, flags, body); err != nil {
		return fmt.Errorf("route %s through %s: %w", to, name, err)
	}
	return nil
}

// labRuleToMain adds or deletes, as kind says, the rule sending a packet arriving on iif for to to the main table at priority, in the calling thread's namespace
func labRuleToMain(netlink netnstest.Netlink, kind uint16, iif string, to netip.Prefix, priority uint32) error {
	family := byte(unix.AF_INET6)
	if to.Addr().Is4() {
		family = unix.AF_INET
	}
	// struct fib_rule_hdr of include/uapi/linux/fib_rules.h
	header := []byte{family, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	body := slices.Concat(header, netnstest.Attr(unix.FRA_IIFNAME, netnstest.CString(iif)), netnstest.Attr(unix.FRA_DST, to.Addr().AsSlice()), netnstest.Attr(unix.FRA_PRIORITY, netnstest.U32(priority)))
	var flags uint16
	if kind == unix.RTM_NEWRULE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	if err := netlink.Request(kind, flags, body); err != nil {
		return fmt.Errorf("rule for %s arriving on %s: %w", to, iif, err)
	}
	return nil
}

// labConfig is the reload fixture's node made an exit with the egress segment,
// cap.egress and a cap.table holding the to and from rules for the leaves into
// the mesh table
func labConfig(t *testing.T) *config.Config {
	t.Helper()
	fixture, _ := reloadFixture(t)
	cfg := *fixture.config()
	cfg.Link.TUN = labTUN
	egressNode(&cfg, egressSegment(labSID.String(), labLeaves...))
	// a deleted table is noticed at the next sweep
	cfg.Cap.Egress.Sweep = schema.Duration(time.Second)
	cfg.Cap.Table = &kernel.Table{ID: kernel.DefaultTable, Rules: []kernel.Rule{
		{To: schema.MustPrefix(labLeaves[0]), Table: kernel.DefaultTable, Priority: 100},
		{To: schema.MustPrefix(labLeaves[1]), Table: kernel.DefaultTable, Priority: 100},
		{From: schema.MustPrefix(labLeaves[0]), Table: kernel.DefaultTable, Priority: 150},
		{From: schema.MustPrefix(labLeaves[1]), Table: kernel.DefaultTable, Priority: 150},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the exit's configuration is refused: %v", err)
	}
	return &cfg
}

// labUplink makes the veth pair from the exit's namespace to the far host's,
// addresses both ends and turns forwarding on at the exit before any device
// of the node exists, so the mesh tun takes it from conf.default. Where
// master is not empty, a VRF of that name bound to the mesh table is made
// first and the exit's end joins it before it is addressed. A kernel with no
// VRF support skips the test, as the reconciler's own VRF test does.
func labUplink(t *testing.T, exit, far *netnstest.Thread, master string) {
	t.Helper()
	var unsupported error
	if err := exit.Do(func() error {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
				return err
			}
		}
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		var enslave []byte
		if master != "" {
			vrf := slices.Concat(netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("vrf")), netnstest.Attr(unix.IFLA_INFO_DATA, netnstest.Attr(unix.IFLA_VRF_TABLE, netnstest.U32(kernel.DefaultTable))))
			if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
				slices.Concat(netnstest.IfInfo(0, unix.IFF_UP), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(master)), netnstest.Attr(unix.IFLA_LINKINFO, vrf))); err != nil {
				unsupported = err
				return nil
			}
			link, err := net.InterfaceByName(master)
			if err != nil {
				return err
			}
			enslave = netnstest.Attr(unix.IFLA_MASTER, netnstest.U32(uint32(link.Index)))
		}
		other, err := unix.Open(far.Path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(other)
		peer := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("labf")), netnstest.Attr(unix.IFLA_NET_NS_FD, netnstest.U32(uint32(other))))
		kind := slices.Concat(netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("veth")), netnstest.Attr(unix.IFLA_INFO_DATA, netnstest.Attr(netnstest.VethPeer, peer)))
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
			slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("labx")), enslave, netnstest.Attr(unix.IFLA_LINKINFO, kind))); err != nil {
			return fmt.Errorf("make the veth pair: %w", err)
		}
		if master != "" {
			if held, err := labMaster("labx"); err != nil || held != master {
				return fmt.Errorf("the uplink is enslaved to %q (%v), want %s", held, err, master)
			}
		}
		return labAddress(netlink, "labx", labExit4, labExit6)
	}); err != nil {
		t.Fatalf("make the exit's end of the uplink: %v", err)
	}
	if unsupported != nil {
		t.Skipf("no vrf support in this kernel: %v", unsupported)
	}
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		return labAddress(netlink, "labf", labFar4, labFar6)
	}); err != nil {
		t.Fatalf("address the far host's end of the uplink: %v", err)
	}
}

// labMaster names the device name is enslaved to in the calling thread's
// namespace, empty for none, out of a dump of every link
func labMaster(name string) (string, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return "", err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return "", err
	}
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWLINK || len(message.Data) < syscall.SizeofIfInfomsg ||
			int(int32(binary.NativeEndian.Uint32(message.Data[4:]))) != link.Index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return "", err
		}
		for _, attr := range attrs {
			if attr.Attr.Type == syscall.IFLA_MASTER && len(attr.Value) == 4 {
				master, err := net.InterfaceByIndex(int(binary.NativeEndian.Uint32(attr.Value)))
				if err != nil {
					return "", err
				}
				return master.Name, nil
			}
		}
		return "", nil
	}
	return "", fmt.Errorf("the link dump holds no %s", name)
}

func labAddress(netlink netnstest.Netlink, name string, addresses ...netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if err := netlink.AddAddress(link.Index, address); err != nil {
			return fmt.Errorf("add %s to %s: %w", address, name, err)
		}
	}
	return nil
}

// labRouteVia routes to through gateway on link index in the main table, in
// the family of to
func labRouteVia(netlink netnstest.Netlink, index int, to netip.Prefix, gateway netip.Addr) error {
	family := byte(unix.AF_INET6)
	if to.Addr().Is4() {
		family = unix.AF_INET
	}
	header := []byte{family, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()), netnstest.Attr(unix.RTA_GATEWAY, gateway.AsSlice()), netnstest.Attr(unix.RTA_OIF, netnstest.U32(uint32(index))))
	return netlink.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// labReceive calls send until listener reads payload, and returns where it came from
func labReceive(t *testing.T, listener *net.UDPConn, payload []byte, send func()) netip.AddrPort {
	t.Helper()
	buf := make([]byte, 1<<16)
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		send()
		if err := listener.SetReadDeadline(time.Now().Add(labRetry)); err != nil {
			t.Fatal(err)
		}
		for {
			n, from, err := listener.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if bytes.Equal(buf[:n], payload) {
				return from
			}
		}
	}
	t.Fatalf("the far host read no %q within %s", payload, convergeBudget)
	return netip.AddrPort{}
}

// labQuietFor fails the test if listener reads payload within labQuiet
func labQuietFor(t *testing.T, listener *net.UDPConn, payload []byte) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(labQuiet)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, from, err := listener.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if bytes.Equal(buf[:n], payload) {
			t.Errorf("the far host read %q from %s", payload, from)
		}
	}
}

// labCaptureReply calls send until the capture reads a UDP packet to leaf's labLeafPort carrying payload
func labCaptureReply(t *testing.T, capture int, leaf netip.Addr, payload []byte, send func()) {
	t.Helper()
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		send()
		if labCaptured(capture, labReplyTo(leaf, payload)) {
			return
		}
	}
	t.Fatalf("no reply to %s crossed the mesh tun within %s", leaf, convergeBudget)
}

// labCaptured reads the capture until a read times out, and reports whether
// it read a packet match takes
func labCaptured(capture int, match func(packet []byte) bool) bool {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false
		}
		if match(buf[:n]) {
			return true
		}
	}
}

// labCount reads the capture until a read times out, and counts the packets match takes
func labCount(capture int, match func(packet []byte) bool) int {
	buf := make([]byte, 1<<16)
	count := 0
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return count
		}
		if match(buf[:n]) {
			count++
		}
	}
}

// labReplyTo takes a UDP packet to leaf's labLeafPort carrying payload
func labReplyTo(leaf netip.Addr, payload []byte) func([]byte) bool {
	return func(packet []byte) bool {
		to, port, got, ok := labUDPOf(packet)
		return ok && to == leaf && port == labLeafPort && bytes.Equal(got, payload)
	}
}

// labIPv6To takes an IPv6 packet to destination holding payload
func labIPv6To(destination netip.Addr, payload []byte) func([]byte) bool {
	return func(packet []byte) bool {
		return len(packet) > 40 && packet[0]>>4 == 6 && netip.AddrFrom16([16]byte(packet[24:40])) == destination && bytes.Contains(packet, payload)
	}
}

// labUDPOf reads the destination, its port and the payload of the UDP packet raw
func labUDPOf(raw []byte) (netip.Addr, uint16, []byte, bool) {
	var to netip.Addr
	var offset int
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4 && raw[9] == unix.IPPROTO_UDP:
		to, offset = netip.AddrFrom4([4]byte(raw[16:20])), int(raw[0]&0x0f)*4
	case len(raw) >= 40 && raw[0]>>4 == 6 && raw[6] == unix.IPPROTO_UDP:
		to, offset = netip.AddrFrom16([16]byte(raw[24:40])), 40
	default:
		return netip.Addr{}, 0, nil, false
	}
	if len(raw) < offset+8 {
		return netip.Addr{}, 0, nil, false
	}
	return to, binary.BigEndian.Uint16(raw[offset+2:]), raw[offset+8:], true
}

// labMeshRoute reports a route to prefix in the mesh table of the exit's namespace
func labMeshRoute(t testing.TB, exit *netnstest.Thread, prefix netip.Prefix) bool {
	t.Helper()
	var routes []kernelRoute
	if err := exit.Do(func() (err error) {
		routes, err = dumpRoutes()
		return err
	}); err != nil {
		t.Fatalf("list the routes: %v", err)
	}
	return slices.ContainsFunc(routes, func(route kernelRoute) bool {
		return route.table == kernel.DefaultTable && route.destination == prefix
	})
}

// labDeleteTable deletes the nftables table name of family as another writer would, in one batch from a socket of its own
func labDeleteTable(family uint8, name string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return netnstest.Acknowledged(fd, slices.Concat(
		netnstest.Message(unix.NFNL_MSG_BATCH_BEGIN, 0, labNfgen(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES)),
		netnstest.Message(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE, unix.NLM_F_ACK,
			slices.Concat(labNfgen(family, 0), netnstest.Attr(unix.NFTA_TABLE_NAME, netnstest.CString(name)))),
		netnstest.Message(unix.NFNL_MSG_BATCH_END, 0, labNfgen(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES))))
}

func labNfgen(family uint8, resource uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte{family, unix.NFNETLINK_V0}, resource)
}
