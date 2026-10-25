// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// rulesTUN is the leaf's mesh tun, and rulesUplink and rulesFar the two ends of its uplink
	rulesTUN    = "rul0"
	rulesUplink = "rulx"
	rulesFar    = "rulf"
	// rulesOther is the link another program routes over from its own table, rulesOtherTable, through its own rule at rulesOtherPriority, as Tailscale's 52 at 5270
	rulesOther         = "rult"
	rulesOtherTable    = 52
	rulesOtherPriority = 5270
	// rulesPortBase is the port the first probe binds, each probe after it taking the next
	rulesPortBase = 42000
	// rulesDiscard is the port every probe is sent to
	rulesDiscard = 9
	// rulesSettle is how long an arm waits for the reconciler's pass, which takes about a second
	rulesSettle = 10 * time.Second
)

// rulesVerdict is where the kernel sent a probe's first packet
type rulesVerdict string

const (
	rulesIntoTun   rulesVerdict = "into the tun"
	rulesOutUplink rulesVerdict = "out of the uplink"
	rulesIntoOther rulesVerdict = "into the other program's link"
	rulesRefused   rulesVerdict = "refused by its route"
	rulesNowhere   rulesVerdict = "nowhere"
	rulesSeveral   rulesVerdict = "out of more than one link"
)

// rulesSocket is how a probe's socket is opened
type rulesSocket int

const (
	rulesUnbound rulesSocket = iota
	rulesFromOverlay
	rulesFromUplink
	rulesOnUplink
	rulesMarked
	rulesMarkedFromOverlay
)

func (s rulesSocket) String() string {
	return [...]string{
		"unbound", "bound to the overlay address", "bound to the uplink's address", "bound to the uplink's device",
		"carrying the underlay's mark", "carrying the mark and bound to the overlay address",
	}[s]
}

// rulesHost is the leaf's addresses in one family: its own inside the overlay, its uplink's, and the far host's two
var rulesHost = map[int]struct{ own, uplink, gateway, lan netip.Prefix }{
	4: {netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("198.51.100.10/24"), netip.MustParsePrefix("198.51.100.1/24"), netip.MustParsePrefix("198.51.100.20/24")},
	6: {netip.MustParsePrefix("3fff::1/128"), netip.MustParsePrefix("2001:db8:a::10/64"), netip.MustParsePrefix("2001:db8:a::1/64"), netip.MustParsePrefix("2001:db8:a::20/64")},
}

// rulesOverlay is the leaf's cap.border overlay
var rulesOverlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}

// rulesProbe is one socket's first packet to destination, and where it has to go
type rulesProbe struct {
	destination netip.Addr
	socket      rulesSocket
	want        rulesVerdict
}

// rulesRow is a probe of destination from each socket but the one bound to the uplink's device, wanting in turn
func rulesRow(destination string, unbound, overlay, uplink, marked, markedOverlay rulesVerdict) []rulesProbe {
	to := netip.MustParseAddr(destination)
	return []rulesProbe{
		{to, rulesUnbound, unbound}, {to, rulesFromOverlay, overlay}, {to, rulesFromUplink, uplink},
		{to, rulesMarked, marked}, {to, rulesMarkedFromOverlay, markedOverlay},
	}
}

// rulesOut is rulesRow for a destination every socket reaches out of the uplink, the one bound to the uplink's device among them
func rulesOut(destination string) []rulesProbe {
	up := rulesOutUplink
	return append(rulesRow(destination, up, up, up, up, up), rulesProbe{netip.MustParseAddr(destination), rulesOnUplink, up})
}

// rulesOnDevice is the socket bound to the uplink's device sent to a held IPv4 and a held IPv6 destination, which the holds do not refuse
// IPv4 meets the hold, and a lookup that fails for a socket bound to a device takes the destination as on that device's link
// route.c's on-link assumption, so the packet waits on a neighbor nothing answers
// and IPv6 takes only routes through the bound device, passes the hold over and leaves by main's default, out of the uplink
func rulesOnDevice(v4, v6 string) []rulesProbe {
	return []rulesProbe{{netip.MustParseAddr(v4), rulesOnUplink, rulesNowhere}, {netip.MustParseAddr(v6), rulesOnUplink, rulesOutUplink}}
}

// rulesForward is a packet a peer's session delivers, which the mesh writes into the tun for the host to forward
type rulesForward struct {
	source, destination netip.Addr
	want                rulesVerdict
}

// rulesArm is one state of the mesh's table, the routes and rules the reconciler makes of it, and the probes that read them
type rulesArm struct {
	name string
	// entries is the mesh's table beside this node's own addresses
	entries map[string]*netstack.Peer
	// announced holds the prefixes cap.route announces, and a node announcing a default is an exit
	announced []netip.Prefix
	// table is every route the reconciler installs beside the overlay's holds, as its kind and prefix
	table []string
	// own is every prefix the rule at 5430 selects a source from beside the tun's addresses
	own []string
	// other is the prefixes another program routes over its link from its table, through its rule, none without its rule
	other    []netip.Prefix
	probes   []rulesProbe
	forwards []rulesForward
}

// rulesArms are the lab's arms, a peer at learned standing for every route a neighbor offers
func rulesArms(learned *netstack.Peer) []rulesArm {
	tun, up, refused, other := rulesIntoTun, rulesOutUplink, rulesRefused, rulesIntoOther
	peers := map[string]*netstack.Peer{"192.0.2.5/32": learned, "3fff::5/128": learned}
	with := func(more map[string]*netstack.Peer) map[string]*netstack.Peer {
		out := maps.Clone(peers)
		for prefix, value := range more {
			out[prefix] = value
		}
		return out
	}
	peerRoutes := []string{"unicast 192.0.2.5/32", "unicast 3fff::5/128"}
	reachPeers := slices.Concat(rulesRow("192.0.2.5", tun, tun, tun, up, up), rulesRow("3fff::5", tun, tun, tun, up, up))
	unrouted := slices.Concat(rulesRow("192.0.2.77", refused, refused, refused, up, up), rulesRow("3fff::77", refused, refused, refused, up, up))
	lan := slices.Concat(rulesOut("198.51.100.20"), rulesOut("2001:db8:a::20"))
	return []rulesArm{{
		// 5110 sends an overlay destination to the mesh and its hold answers one no peer holds, 5420 the mesh's subnets,
		// and 5430 a source of this node's own to the default the mesh learned, which 5420 skips for every other source
		name: "a leaf holding a learned default",
		entries: with(map[string]*netstack.Peer{
			"203.0.113.128/25": learned, "2001:db8:300::/64": learned, "0.0.0.0/0": learned, "::/0": learned,
		}),
		table: slices.Concat(peerRoutes, []string{"unicast 203.0.113.128/25", "unicast 2001:db8:300::/64", "unicast 0.0.0.0/0", "unicast ::/0"}),
		probes: slices.Concat(reachPeers, unrouted, lan,
			rulesRow("203.0.113.9", up, tun, up, up, up), rulesRow("2001:db8:c::9", up, tun, up, up, up),
			[]rulesProbe{{netip.MustParseAddr("203.0.113.9"), rulesOnUplink, up}, {netip.MustParseAddr("2001:db8:c::9"), rulesOnUplink, up}},
			rulesRow("203.0.113.130", tun, tun, tun, up, up), rulesRow("2001:db8:300::4", tun, tun, tun, up, up),
			rulesOnDevice("192.0.2.77", "3fff::77")),
	}, {
		// the mirror installs no hold of a default, so every source leaves by the uplink, and a held subnet is refused
		// but to a socket carrying the underlay's mark, which skips the holds, and to the socket bound to the uplink's device, the declared limit
		name: "the default and a subnet retracted",
		entries: with(map[string]*netstack.Peer{
			"203.0.113.128/25": netstack.Unreachable, "2001:db8:300::/64": netstack.Unreachable,
			"0.0.0.0/0": netstack.Unreachable, "::/0": netstack.Unreachable,
		}),
		table: slices.Concat(peerRoutes, []string{"unreachable 203.0.113.128/25", "unreachable 2001:db8:300::/64"}),
		probes: slices.Concat(reachPeers, rulesOut("203.0.113.9"), rulesOut("2001:db8:c::9"),
			rulesRow("203.0.113.130", refused, refused, refused, up, up), rulesRow("2001:db8:300::4", refused, refused, refused, up, up),
			rulesOnDevice("203.0.113.130", "2001:db8:300::4")),
	}, {
		// halves of a default count as one by their length, so 5420 skips them, at suppress_prefixlength 7 and 15 rather than 1
		name: "half defaults learned",
		entries: with(map[string]*netstack.Peer{
			"0.0.0.0/1": learned, "128.0.0.0/1": learned, "::/1": learned, "8000::/1": learned,
		}),
		table: slices.Concat(peerRoutes, []string{"unicast 0.0.0.0/1", "unicast 128.0.0.0/1", "unicast ::/1", "unicast 8000::/1"}),
		probes: slices.Concat(reachPeers,
			rulesRow("203.0.113.9", up, tun, up, up, up), rulesRow("2001:db8:c::9", up, tun, up, up, up),
			[]rulesProbe{{netip.MustParseAddr("203.0.113.9"), rulesOnUplink, up}, {netip.MustParseAddr("2001:db8:c::9"), rulesOnUplink, up}}),
	}, {
		// a split internet counts as a default by its length too, while the mesh's subnet beside it carries every source of an unmarked socket not bound to the uplink's device
		name: "a split internet learned",
		entries: with(map[string]*netstack.Peer{
			"0.0.0.0/2": learned, "64.0.0.0/2": learned, "128.0.0.0/2": learned, "192.0.0.0/2": learned, "2000::/3": learned,
			"203.0.113.128/25": learned, "2001:db8:300::/64": learned,
		}),
		table: slices.Concat(peerRoutes, []string{
			"unicast 0.0.0.0/2", "unicast 64.0.0.0/2", "unicast 128.0.0.0/2", "unicast 192.0.0.0/2", "unicast 2000::/3",
			"unicast 203.0.113.128/25", "unicast 2001:db8:300::/64",
		}),
		probes: slices.Concat(reachPeers, unrouted, lan,
			rulesRow("203.0.113.9", up, tun, up, up, up), rulesRow("2001:db8:c::9", up, tun, up, up, up),
			rulesRow("203.0.113.130", tun, tun, tun, up, up), rulesRow("2001:db8:300::4", tun, tun, tun, up, up)),
	}, {
		// the split's holds count as it did, so none is installed and nothing of the host's is cut off
		name: "the split internet retracted",
		entries: with(map[string]*netstack.Peer{
			"0.0.0.0/2": netstack.Unreachable, "64.0.0.0/2": netstack.Unreachable, "128.0.0.0/2": netstack.Unreachable,
			"192.0.0.0/2": netstack.Unreachable, "2000::/3": netstack.Unreachable,
			"203.0.113.128/25": learned, "2001:db8:300::/64": learned,
		}),
		table: slices.Concat(peerRoutes, []string{"unicast 203.0.113.128/25", "unicast 2001:db8:300::/64"}),
		probes: slices.Concat(reachPeers, rulesOut("203.0.113.9"), rulesOut("2001:db8:c::9"),
			rulesRow("203.0.113.130", tun, tun, tun, up, up), rulesRow("2001:db8:300::4", tun, tun, tun, up, up)),
	}, {
		// a route at the floor is longer than 5420's suppress length, so 5420 carries every source of an unmarked socket not bound to the uplink's device to it
		name:    "a route at the floor learned",
		entries: with(map[string]*netstack.Peer{"203.0.0.0/8": learned, "2001::/16": learned}),
		table:   slices.Concat(peerRoutes, []string{"unicast 203.0.0.0/8", "unicast 2001::/16"}),
		probes: slices.Concat(reachPeers, lan,
			rulesRow("203.0.113.9", tun, tun, tun, up, up), rulesRow("2001:db8:c::9", tun, tun, tun, up, up),
			[]rulesProbe{{netip.MustParseAddr("203.0.113.9"), rulesOnUplink, up}, {netip.MustParseAddr("2001:db8:c::9"), rulesOnUplink, up}}),
	}, {
		// this node's own prefix inside the overlay is held, so neither a forwarded packet nor a socket of the host's takes main to it, but one carrying the underlay's mark, and over IPv6 one bound to the uplink's device
		name:    "this node's own prefix inside the overlay",
		entries: with(map[string]*netstack.Peer{"192.0.2.16/28": netstack.Local, "3fff:0:0:1::/64": netstack.Local}),
		table:   slices.Concat(peerRoutes, []string{"unreachable 192.0.2.16/28", "unreachable 3fff:0:0:1::/64"}),
		own:     []string{"192.0.2.16/28", "3fff:0:0:1::/64"},
		probes: slices.Concat(reachPeers,
			rulesRow("192.0.2.20", refused, refused, refused, up, up), rulesRow("3fff:0:0:1::20", refused, refused, refused, up, up)),
		forwards: []rulesForward{
			{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("192.0.2.20"), rulesNowhere},
			{netip.MustParseAddr("3fff::5"), netip.MustParseAddr("3fff:0:0:1::20"), rulesNowhere},
		},
	}, {
		// another program's rule at 5270 sits between the blocks: the overlay reaches the mesh at 5110 ahead of its table,
		// whose routes take every other probe of the arm, and the underlay's mark skips the first block to 5190 and so still meets it
		name:    "beside another program's table at 5270",
		entries: maps.Clone(peers),
		table:   peerRoutes,
		other: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("203.0.113.192/26"),
			netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("2001:db8:e::/48"),
		},
		probes: slices.Concat(
			rulesRow("192.0.2.5", tun, tun, tun, other, other), rulesRow("3fff::5", tun, tun, tun, other, other),
			rulesRow("192.0.2.77", refused, refused, refused, other, other), rulesRow("3fff::77", refused, refused, refused, other, other),
			rulesRow("203.0.113.200", other, other, other, other, other), rulesRow("2001:db8:e::9", other, other, other, other, other)),
	}, {
		// an exit installs none of another exit's halves, so its own traffic leaves by its uplink whatever its source,
		// and its LAN outside the overlay is a throw, which hands a forwarded packet to main's default
		name: "an exit with another exit's halves",
		entries: with(map[string]*netstack.Peer{
			"0.0.0.0/0": netstack.Local, "::/0": netstack.Local,
			"0.0.0.0/1": learned, "128.0.0.0/1": learned, "::/1": learned, "8000::/1": learned,
			"203.0.113.0/25": netstack.Local, "2001:db8:c::/48": netstack.Local,
		}),
		announced: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		table:     slices.Concat(peerRoutes, []string{"throw 203.0.113.0/25", "throw 2001:db8:c::/48"}),
		own:       []string{"203.0.113.0/25", "2001:db8:c::/48"},
		probes:    slices.Concat(reachPeers, rulesOut("203.0.113.200"), rulesOut("2001:db8:d::9")),
		forwards: []rulesForward{
			{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.9"), up},
			{netip.MustParseAddr("3fff::5"), netip.MustParseAddr("2001:db8:c::9"), up},
		},
	}}
}

// a leaf in a namespace of its own holds its tun, an uplink to a far host and the loopback, and runs the reconciler main builds over the mesh's table
// for each arm the reconciler installs the mirror's routes and the rules of mode off it derives
// and each probe, unbound, bound to the overlay address, bound to the uplink's address or device, carrying the underlay's mark, or that and bound to the overlay address,
// over UDP, TCP and echo in both families, leaves into the tun, out of the uplink or into another program's link, or is refused by its route or sent nowhere, where the arm says
// while no hold refuses the socket bound to the uplink's device, the declared limit of mode off
// and a packet a peer delivers to this node's own prefix is forwarded out of the uplink outside the overlay and held inside it
// and a clean stop leaves no rule or route of the reconciler's protocol
func TestTUNDerivedRulesSendEachSocketWhereModeOffSays(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	cfg := rulesConfig(t)
	var node *Client
	if err := leaf.Do(func() (err error) {
		node, err = New(cfg, events.New())
		return err
	}); err != nil {
		t.Fatalf("start the leaf: %v", err)
	}
	learned := netstack.NewPeer("example/peer", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the peer is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(learned.Close)
	for _, family := range rulesHost {
		node.Mesh.Routes.Set(netip.Prefix{}, family.own, netstack.Assigned)
	}
	var routes *kernel.Reconciler
	if err := leaf.Do(func() (err error) {
		rt := node.KernelRuntime()
		// a session counts as live throughout, so the gate is open and a route that counts as a default, unless it is a hold or this node is an exit, is the mirror's to install
		rt.Sessions = func() int { return 1 }
		routes, err = kernel.New(*cfg.Cap.Table, rt, node.Mesh.Routes)
		return err
	}); err != nil {
		t.Fatalf("build the reconciler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	stop := sync.OnceFunc(func() {
		cancel()
		runs.Wait()
		node.Close()
	})
	t.Cleanup(stop)
	runs.Go(func() {
		if err := routes.Run(ctx); err != nil {
			t.Errorf("the reconciler: %v", err)
		}
	})
	var tunCapture, farCapture, otherCapture int
	if err := errors.Join(
		leaf.Do(func() (err error) { tunCapture, err = openCapture(rulesTUN, labRetry); return err }),
		leaf.Do(func() (err error) { otherCapture, err = openCapture(rulesOther, labRetry); return err }),
		far.Do(func() (err error) { farCapture, err = openCapture(rulesFar, labRetry); return err }),
	); err != nil {
		t.Fatalf("capture the tun, the other program's link and the far end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(tunCapture); _ = unix.Close(farCapture); _ = unix.Close(otherCapture) })

	probe := 0
	for _, arm := range rulesArms(learned) {
		t.Run(arm.name, func(t *testing.T) {
			for prefix, value := range arm.entries {
				node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
			}
			t.Cleanup(func() {
				for prefix := range arm.entries {
					node.Mesh.Routes.Remove(netip.Prefix{}, netip.MustParsePrefix(prefix))
				}
			})
			if len(arm.other) > 0 {
				if err := leaf.Do(func() error { return rulesOtherProgram(unix.RTM_NEWRULE, unix.RTM_NEWROUTE, arm.other) }); err != nil {
					t.Fatalf("write the other program's rules and routes: %v", err)
				}
				t.Cleanup(func() {
					if err := leaf.Do(func() error { return rulesOtherProgram(unix.RTM_DELRULE, unix.RTM_DELROUTE, arm.other) }); err != nil {
						t.Errorf("delete the other program's rules and routes: %v", err)
					}
				})
			}
			if err := routes.SetTable(*cfg.Cap.Table, cfg.Overlay(), arm.announced); err != nil {
				t.Fatalf("hand the reconciler the announcements %v: %v", arm.announced, err)
			}
			var held string
			waitFor(t, rulesSettle, "the reconciler to install the arm's routes and rules", func() bool {
				var ok bool
				ok, held = rulesConverged(t, leaf, arm)
				return ok
			})
			t.Logf("the kernel holds %s", held)

			type sent struct {
				probe    rulesProbe
				protocol string
				number   int
				refused  bool
			}
			var all []sent
			var fds []int
			if err := leaf.Do(func() error {
				for _, p := range arm.probes {
					for _, protocol := range []string{"udp", "tcp", "echo"} {
						probe++
						fd, refused, err := rulesSend(p, protocol, probe)
						if err != nil {
							return fmt.Errorf("%s %s to %s: %w", p.socket, protocol, p.destination, err)
						}
						if fd >= 0 {
							fds = append(fds, fd)
						}
						all = append(all, sent{p, protocol, probe, refused})
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("send the probes: %v", err)
			}
			type forwarded struct {
				forward rulesForward
				number  int
			}
			var injected []forwarded
			for _, f := range arm.forwards {
				probe++
				node.Mesh.DeliverInbound(udpPacket(f.source, f.destination, uint16(rulesPortBase+probe), rulesDiscard, []byte(fmt.Sprintf("forwarded %d", probe))), 0)
				injected = append(injected, forwarded{f, probe})
			}
			intoTun, outUplink, intoOther := rulesDrain(tunCapture), rulesDrain(farCapture), rulesDrain(otherCapture)
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			for _, s := range all {
				key := rulesKey{s.protocol, s.number}
				var seen []rulesVerdict
				var source netip.Addr
				for verdict, capture := range map[rulesVerdict]map[rulesKey]netip.Addr{rulesIntoTun: intoTun, rulesOutUplink: outUplink, rulesIntoOther: intoOther} {
					if from, ok := capture[key]; ok {
						seen, source = append(seen, verdict), from
					}
				}
				got := rulesNowhere
				switch {
				case s.refused:
					got = rulesRefused
				case len(seen) == 1:
					got = seen[0]
				case len(seen) > 1:
					got = rulesSeveral
				}
				if got != s.probe.want {
					t.Errorf("%s from a socket %s to %s went %s from %s, want %s", s.protocol, s.probe.socket, s.probe.destination, got, source, s.probe.want)
				}
			}
			for _, f := range injected {
				got := rulesNowhere
				if source, ok := outUplink[rulesKey{"udp", f.number}]; ok && source == f.forward.source {
					got = rulesOutUplink
				}
				if got != f.forward.want {
					t.Errorf("a packet a peer delivered from %s to %s was forwarded %s, want %s", f.forward.source, f.forward.destination, got, f.forward.want)
				}
			}
		})
	}

	t.Run("a clean stop", func(t *testing.T) {
		stop()
		var rules []kernelRule
		var left []kernelRoute
		if err := leaf.Do(func() (err error) {
			if rules, err = dumpRules(); err != nil {
				return err
			}
			left, err = dumpRoutes()
			return err
		}); err != nil {
			t.Fatalf("read the leaf back: %v", err)
		}
		proto := uint8(kernel.DefaultProtocol)
		for _, rule := range rules {
			if rule.protocol == proto {
				t.Errorf("the stop left the rule %s", rule)
			}
		}
		for _, route := range left {
			if route.protocol == proto {
				t.Errorf("the stop left the route %s", route)
			}
		}
	})
}

// rulesConfig is the reload fixture's node with the tun rulesTUN, a cap.table assigning the leaf's own addresses, and cap.border's overlay
func rulesConfig(t *testing.T) *config.Config {
	t.Helper()
	fixture, _ := reloadFixture(t)
	cfg := *fixture.config()
	cfg.Link.TUN = rulesTUN
	cfg.Cap.Table = &kernel.Table{ID: kernel.DefaultTable, Addresses: []schema.Prefix{schema.PrefixFrom(rulesHost[4].own), schema.PrefixFrom(rulesHost[6].own)}}
	cfg.Cap.Border = &egress.Border{Overlay: rulesOverlay}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the leaf's configuration is refused: %v", err)
	}
	return &cfg
}

// rulesUplinkPair makes the veth pair from the leaf's namespace to the far host's, the leaf's defaults through the far host, and forwarding on at the leaf
// with reverse path filtering off before any device exists, so the kernel drops no forwarded packet for its source
func rulesUplinkPair(t *testing.T, leaf, far *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		for path, value := range map[string]string{
			"/proc/sys/net/ipv4/ip_forward":             "1",
			"/proc/sys/net/ipv6/conf/all/forwarding":    "1",
			"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
			"/proc/sys/net/ipv4/conf/default/rp_filter": "0",
		} {
			if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
				return err
			}
		}
		other, err := unix.Open(far.Path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(other)
		peer := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(rulesFar)), netnstest.Attr(unix.IFLA_NET_NS_FD, netnstest.U32(uint32(other))))
		kind := slices.Concat(netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("veth")), netnstest.Attr(unix.IFLA_INFO_DATA, netnstest.Attr(netnstest.VethPeer, peer)))
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
			slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(rulesUplink)), netnstest.Attr(unix.IFLA_LINKINFO, kind))); err != nil {
			return fmt.Errorf("make the veth pair: %w", err)
		}
		if err := netlink.AddAddresses(rulesUplink, rulesHost[4].uplink, rulesHost[6].uplink); err != nil {
			return err
		}
		dummy := netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("dummy"))
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
			slices.Concat(netnstest.IfInfo(0, unix.IFF_UP), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(rulesOther)), netnstest.Attr(unix.IFLA_LINKINFO, dummy))); err != nil {
			return fmt.Errorf("make the other program's link: %w", err)
		}
		uplink, err := net.InterfaceByName(rulesUplink)
		if err != nil {
			return err
		}
		for _, family := range []int{4, 6} {
			every := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			if family == 4 {
				every = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			if err := netlink.RouteVia(uplink.Index, every, rulesHost[family].gateway.Addr()); err != nil {
				return fmt.Errorf("route %s through the far host: %w", every, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("make the leaf's end of the uplink: %v", err)
	}
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		return netlink.AddAddresses(rulesFar, rulesHost[4].gateway, rulesHost[4].lan, rulesHost[6].gateway, rulesHost[6].lan)
	}); err != nil {
		t.Fatalf("address the far host's end of the uplink: %v", err)
	}
}

// rulesOtherProgram adds or deletes, as ruleKind and routeKind say, another program's rule at rulesOtherPriority looking up
// rulesOtherTable in both families, and its routes to prefixes over its link in that table, in the calling thread's namespace
func rulesOtherProgram(ruleKind, routeKind uint16, prefixes []netip.Prefix) error {
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	link, err := net.InterfaceByName(rulesOther)
	if err != nil {
		return err
	}
	var flags uint16
	if ruleKind == unix.RTM_NEWRULE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		// struct fib_rule_hdr of include/uapi/linux/fib_rules.h, with no selector
		header := []byte{family, 0, 0, 0, rulesOtherTable, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
		if err := netlink.Request(ruleKind, flags, slices.Concat(header, netnstest.Attr(unix.FRA_PRIORITY, netnstest.U32(rulesOtherPriority)))); err != nil {
			return fmt.Errorf("the rule at %d: %w", rulesOtherPriority, err)
		}
	}
	for _, prefix := range prefixes {
		family, scope := byte(unix.AF_INET6), byte(unix.RT_SCOPE_UNIVERSE)
		if prefix.Addr().Is4() {
			family, scope = unix.AF_INET, unix.RT_SCOPE_LINK
		}
		header := []byte{family, byte(prefix.Bits()), 0, 0, rulesOtherTable, unix.RTPROT_BOOT, scope, unix.RTN_UNICAST, 0, 0, 0, 0}
		body := slices.Concat(header, netnstest.Attr(unix.RTA_DST, prefix.Addr().AsSlice()), netnstest.Attr(unix.RTA_OIF, netnstest.U32(uint32(link.Index))))
		if err := netlink.Request(routeKind, flags, body); err != nil {
			return fmt.Errorf("the route to %s: %w", prefix, err)
		}
	}
	return nil
}

// rulesConverged reports whether the leaf's kernel holds exactly the routes of arm in the mesh's table, the overlay's holds among them,
// and the rules at 5430 for exactly this node's own prefixes, and what it holds
func rulesConverged(t *testing.T, leaf *netnstest.Thread, arm rulesArm) (bool, string) {
	t.Helper()
	var routes []kernelRoute
	var rules []kernelRule
	if err := leaf.Do(func() (err error) {
		if routes, err = dumpRoutes(); err != nil {
			return err
		}
		rules, err = dumpRules()
		return err
	}); err != nil {
		t.Fatalf("read the leaf's kernel: %v", err)
	}
	kinds := map[uint8]string{unix.RTN_UNICAST: "unicast", unix.RTN_UNREACHABLE: "unreachable", unix.RTN_THROW: "throw"}
	var table []string
	for _, route := range routes {
		if route.table == kernel.DefaultTable && route.protocol == kernel.DefaultProtocol {
			kind, ok := kinds[route.kind]
			if !ok {
				kind = fmt.Sprintf("type %d", route.kind)
			}
			table = append(table, kind+" "+route.destination.String())
		}
	}
	want := slices.Clone(arm.table)
	for _, prefix := range rulesOverlay {
		want = append(want, "unreachable "+prefix.String())
	}
	var own []string
	for _, rule := range rules {
		if rule.protocol == kernel.DefaultProtocol && rule.priority == 5430 {
			own = append(own, rule.source.String())
		}
	}
	wantOwn := append(slices.Clone(arm.own), rulesHost[4].own.String(), rulesHost[6].own.String())
	sort.Strings(table)
	sort.Strings(want)
	sort.Strings(own)
	sort.Strings(wantOwn)
	held := fmt.Sprintf("the routes [%s] and the rules at 5430 from [%s]", strings.Join(table, ", "), strings.Join(own, ", "))
	return slices.Equal(table, want) && slices.Equal(own, wantOwn), held
}

// rulesSend opens the socket p names in the calling thread's namespace and sends its first packet of protocol to p's destination
// numbered n by its source port, or by its echo identifier, and answers the socket, still open, and whether its route refused it
func rulesSend(p rulesProbe, protocol string, n int) (int, bool, error) {
	family, own, uplink := unix.AF_INET6, rulesHost[6].own.Addr(), rulesHost[6].uplink.Addr()
	unspecified := netip.IPv6Unspecified()
	if p.destination.Is4() {
		family, own, uplink, unspecified = unix.AF_INET, rulesHost[4].own.Addr(), rulesHost[4].uplink.Addr(), netip.IPv4Unspecified()
	}
	kind, number := unix.SOCK_DGRAM, 0
	switch protocol {
	case "tcp":
		kind = unix.SOCK_STREAM | unix.SOCK_NONBLOCK
	case "echo":
		kind, number = unix.SOCK_RAW, unix.IPPROTO_ICMP
		if family == unix.AF_INET6 {
			number = unix.IPPROTO_ICMPV6
		}
	}
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, number)
	if err != nil {
		return -1, false, err
	}
	fail := func(err error) (int, bool, error) {
		_ = unix.Close(fd)
		return -1, false, err
	}
	refusal := func(err error) bool { return errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENETUNREACH) }
	bind := unspecified
	switch p.socket {
	case rulesFromOverlay, rulesMarkedFromOverlay:
		bind = own
	case rulesFromUplink:
		bind = uplink
	case rulesOnUplink:
		if err := unix.BindToDevice(fd, rulesUplink); err != nil {
			return fail(err)
		}
	}
	if p.socket == rulesMarked || p.socket == rulesMarkedFromOverlay {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(schema.UnderlayMark)); err != nil {
			return fail(err)
		}
	}
	port, peerPort := rulesPortBase+n, rulesDiscard
	if protocol == "echo" {
		port, peerPort = 0, 0
	}
	if port != 0 || bind != unspecified {
		if err := unix.Bind(fd, rulesSockaddr(bind, port)); err != nil {
			return fail(fmt.Errorf("bind %s port %d: %w", bind, port, err))
		}
	}
	switch err := unix.Connect(fd, rulesSockaddr(p.destination, peerPort)); {
	case refusal(err):
		_ = unix.Close(fd)
		return -1, true, nil
	case protocol == "tcp" && errors.Is(err, unix.EINPROGRESS):
		return fd, false, nil
	case err != nil:
		return fail(fmt.Errorf("connect: %w", err))
	}
	payload := []byte(fmt.Sprintf("probe %d", n))
	if protocol == "echo" {
		payload = rulesEcho(family == unix.AF_INET, n, payload)
	}
	if _, err := unix.Write(fd, payload); refusal(err) {
		_ = unix.Close(fd)
		return -1, true, nil
	} else if err != nil {
		return fail(fmt.Errorf("send: %w", err))
	}
	return fd, false, nil
}

// rulesEcho is an echo request numbered n carrying payload, over IPv4 with its checksum, which the kernel writes for ICMPv6
func rulesEcho(v4 bool, n int, payload []byte) []byte {
	message := make([]byte, 8, 8+len(payload))
	message[0] = 128
	if v4 {
		message[0] = 8
	}
	binary.BigEndian.PutUint16(message[4:], uint16(n))
	binary.BigEndian.PutUint16(message[6:], 1)
	message = append(message, payload...)
	if v4 {
		binary.BigEndian.PutUint16(message[2:], ^uint16(packet.Sum(0, message)))
	}
	return message
}

func rulesSockaddr(address netip.Addr, port int) unix.Sockaddr {
	if address.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: address.As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: address.As16()}
}

// rulesKey names a probe's packet by its protocol and its number
type rulesKey struct {
	protocol string
	number   int
}

// rulesDrain reads the capture until a read waits out its timeout, and answers the source of each probe's packet it read
func rulesDrain(capture int) map[rulesKey]netip.Addr {
	out := make(map[rulesKey]netip.Addr)
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return out
		}
		if key, source, ok := rulesKeyOf(buf[:n]); ok {
			out[key] = source
		}
	}
}

// rulesKeyOf reads a probe's key and source from raw, an IP packet with no extension header
func rulesKeyOf(raw []byte) (rulesKey, netip.Addr, bool) {
	var source netip.Addr
	var protocol byte
	var l4 []byte
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		source, protocol, l4 = netip.AddrFrom4([4]byte(raw[12:16])), raw[9], raw[int(raw[0]&0x0f)*4:]
	case len(raw) >= 40 && raw[0]>>4 == 6:
		source, protocol, l4 = netip.AddrFrom16([16]byte(raw[8:24])), raw[6], raw[40:]
	default:
		return rulesKey{}, netip.Addr{}, false
	}
	if len(l4) < 8 {
		return rulesKey{}, netip.Addr{}, false
	}
	switch {
	case protocol == unix.IPPROTO_UDP || protocol == unix.IPPROTO_TCP:
		port := int(binary.BigEndian.Uint16(l4))
		if port <= rulesPortBase {
			return rulesKey{}, netip.Addr{}, false
		}
		name := "udp"
		if protocol == unix.IPPROTO_TCP {
			name = "tcp"
		}
		return rulesKey{name, port - rulesPortBase}, source, true
	case protocol == unix.IPPROTO_ICMP && l4[0] == 8, protocol == unix.IPPROTO_ICMPV6 && l4[0] == 128:
		return rulesKey{"echo", int(binary.BigEndian.Uint16(l4[4:]))}, source, true
	}
	return rulesKey{}, netip.Addr{}, false
}
