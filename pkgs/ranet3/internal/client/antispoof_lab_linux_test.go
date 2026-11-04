// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/schema"
)

// antispoofLab is a leaf with its uplink to far and a second link to other,
// both outside the mesh, its node and its antispoof filter running in the
// leaf's namespace, and the leaf's socket on carvePort
type antispoofLab struct {
	leaf, far, other *netnstest.Thread
	d                *exitDaemon
	border           *kernelexit.BorderFilter
	receiver         *net.UDPConn
}

// antispoofMesh is a mesh prefix of each exemption the lab writes, which the
// mesh's table routes to a peer
var antispoofMesh = []netip.Prefix{netip.MustParsePrefix("192.0.2.70/32"), netip.MustParsePrefix("192.0.2.130/32"), netip.MustParsePrefix("3fff::5/128")}

// startAntispoofLab starts the lab's node with antispoof as its cap.antispoof,
// the mesh's table routing antispoofMesh to a peer, and the filter over it
func startAntispoofLab(t *testing.T, antispoof *egress.Antispoof) *antispoofLab {
	t.Helper()
	lab := &antispoofLab{leaf: netnstest.StartThread(t), far: netnstest.StartThread(t), other: netnstest.StartThread(t)}
	rulesUplinkPair(t, lab.leaf, lab.far)
	carveOtherLink(t, lab.leaf, lab.other)
	lab.d = startExitDaemon(t, lab.leaf)
	lab.exempt(t, antispoof)
	for _, prefix := range antispoofMesh {
		lab.d.node.Mesh.Routes.Set(netip.Prefix{}, prefix, lab.d.learned)
	}
	if err := lab.leaf.Do(func() (err error) {
		lab.border, err = kernelexit.NewBorderFilter(lab.d.node.config().Border(), lab.d.node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = lab.border.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if err := lab.leaf.Do(func() (err error) {
		lab.receiver, err = net.ListenUDP("udp", &net.UDPAddr{Port: carvePort})
		return err
	}); err != nil {
		t.Fatalf("listen on the leaf: %v", err)
	}
	t.Cleanup(func() { _ = lab.receiver.Close() })
	lab.reachable(t)
	return lab
}

// antispoofProbe is the payload of a datagram reachable sends, and
// antispoofProbeWait how long it waits for one before sending the next
const (
	antispoofProbe     = "reachable"
	antispoofProbeWait = 100 * time.Millisecond
)

// reachable waits for a datagram from far's and other's own IPv6 addresses,
// outside the overlay, to reach the leaf's socket by each link, so no address
// still in duplicate address detection drops one of the lab's
func (lab *antispoofLab) reachable(t *testing.T) {
	t.Helper()
	for _, link := range []struct {
		thread   *netnstest.Thread
		from, to netip.Addr
	}{
		{lab.far, rulesHost[6].gateway.Addr(), rulesHost[6].uplink.Addr()},
		{lab.other, carveOther[6].far.Addr(), carveOther[6].leaf.Addr()},
	} {
		waitFor(t, convergeBudget, "the leaf's IPv6 address by each link to take a datagram", func() bool {
			if err := link.thread.Do(func() error { return carveSend(link.from, link.to, antispoofProbe) }); err != nil {
				t.Fatalf("send a probe from %s: %v", link.from, err)
			}
			buf := make([]byte, 64)
			if err := lab.receiver.SetReadDeadline(time.Now().Add(antispoofProbeWait)); err != nil {
				t.Fatal(err)
			}
			for {
				n, _, err := lab.receiver.ReadFromUDPAddrPort(buf)
				if err != nil {
					return false
				}
				if string(buf[:n]) == antispoofProbe {
					return true
				}
			}
		})
	}
}

// exempt stores antispoof as the node's cap.antispoof and hands the filter
// the configuration it carves from, where it runs
func (lab *antispoofLab) exempt(t *testing.T, antispoof *egress.Antispoof) {
	t.Helper()
	cfg := *lab.d.node.config()
	cfg.Cap.Antispoof = antispoof
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the lab's exemptions are refused: %v", err)
	}
	lab.d.node.cfg.Store(&cfg)
	if lab.border == nil {
		return
	}
	if err := lab.border.SetConfig(*cfg.Border()); err != nil {
		t.Fatalf("hand the filter the exemptions: %v", err)
	}
}

// send sends one datagram to the leaf from each source, from far by the uplink
// and from other by the second link, each named by its link and source
func (lab *antispoofLab) send(t *testing.T, fromFar, fromOther []string) {
	t.Helper()
	for _, link := range []struct {
		thread  *netnstest.Thread
		name    string
		sources []string
		to      map[bool]netip.Addr
	}{
		{lab.far, rulesUplink, fromFar, map[bool]netip.Addr{false: rulesHost[4].uplink.Addr(), true: rulesHost[6].uplink.Addr()}},
		{lab.other, "carx", fromOther, map[bool]netip.Addr{false: carveOther[4].leaf.Addr(), true: carveOther[6].leaf.Addr()}},
	} {
		if err := link.thread.Do(func() error {
			for _, raw := range link.sources {
				source := netip.MustParseAddr(raw)
				if err := carveSend(source, link.to[source.Is6()], link.name+" "+raw); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("send to the leaf by %s: %v", link.name, err)
		}
	}
}

// delivered is every datagram the leaf's socket takes within labQuiet but a
// late probe of reachable's, sorted
func (lab *antispoofLab) delivered(t *testing.T) []string {
	t.Helper()
	var out []string
	buf := make([]byte, 256)
	if err := lab.receiver.SetReadDeadline(time.Now().Add(labQuiet)); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := lab.receiver.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		if string(buf[:n]) != antispoofProbe {
			out = append(out, string(buf[:n]))
		}
	}
	slices.Sort(out)
	return out
}

// carved is the filter's carved sets as the last pass asked for them, for a
// failure to name
func (lab *antispoofLab) carved() string {
	var debug egress.BorderDebug
	_ = lab.leaf.Do(func() error { debug = lab.border.Debug(); return nil })
	var out []string
	for _, set := range debug.Sets {
		if strings.HasPrefix(set.Name, "carved") {
			out = append(out, fmt.Sprintf("%s %v", set.Name, set.Elements))
		}
	}
	return strings.Join(out, ", ")
}

// holds waits for the filter's chain to hold spec, ready
func (lab *antispoofLab) holds(t *testing.T, spec string) {
	t.Helper()
	waitFor(t, convergeBudget, "the antispoof filter to hold "+spec, func() bool {
		var debug egress.BorderDebug
		_ = lab.leaf.Do(func() error { debug = lab.border.Debug(); return nil })
		for _, chain := range debug.Chains {
			if slices.ContainsFunc(chain.Rules, func(rule egress.BorderReading) bool { return rule.Spec == spec && rule.Held }) {
				return debug.Ready
			}
		}
		return false
	})
}

// a leaf with no cap.antispoof drops every overlay source from both links, and
// one exempting a prefix from every interface outside the mesh, one from its
// uplink and one from the interfaces whose names start with car takes each
// from the links its entry names alone: the shared one from both, the
// uplink's from the uplink and not the second link, and the wildcard's from
// the second link, carx, and not the uplink. A mesh prefix inside an exemption
// is dropped as carved from each link, and the overlay outside every exemption
// is dropped from each.
func TestTUNAntispoofExemptsFromTheInterfacesItNames(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := startAntispoofLab(t, nil)
	lab.holds(t, "drop ipv4 source 192.0.2.0/24")
	overlay4, overlay6 := borderDropped(t, lab.leaf, lab.border, "drop ipv4 source 192.0.2.0/24"), borderDropped(t, lab.leaf, lab.border, "drop ipv6 source 3fff::/20")
	lab.send(t, []string{"192.0.2.65", "3fff:0:1::5"}, []string{"192.0.2.129", "3fff::99"})
	if got := lab.delivered(t); len(got) != 0 {
		t.Errorf("with no cap.antispoof the leaf's socket took %q, want nothing", got)
	}
	waitFor(t, convergeBudget, "the overlay's drops to count both links' datagrams", func() bool {
		return borderDropped(t, lab.leaf, lab.border, "drop ipv4 source 192.0.2.0/24") >= overlay4+2 && borderDropped(t, lab.leaf, lab.border, "drop ipv6 source 3fff::/20") >= overlay6+2
	})

	lab.exempt(t, &egress.Antispoof{
		Exempt: []schema.Prefix{schema.MustPrefix("192.0.2.64/26")},
		Interface: map[string]egress.AntispoofInterface{
			rulesUplink: {Exempt: []schema.Prefix{schema.MustPrefix("3fff:0:1::/48")}},
			"car*":      {Exempt: []schema.Prefix{schema.MustPrefix("192.0.2.128/26")}},
		},
	})
	lab.holds(t, "accept exempt via car* source 192.0.2.128/26")
	carved := borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4")
	lab.send(t,
		[]string{"192.0.2.65", "3fff:0:1::5", "192.0.2.129", "192.0.2.70", "192.0.2.10"},
		[]string{"192.0.2.65", "192.0.2.129", "3fff:0:1::5", "192.0.2.130", "3fff::99"})
	want := []string{"carx 192.0.2.129", "carx 192.0.2.65", rulesUplink + " 192.0.2.65", rulesUplink + " 3fff:0:1::5"}
	slices.Sort(want)
	if got := lab.delivered(t); !slices.Equal(got, want) {
		t.Errorf("the leaf's socket took %q, want %q, with %s", got, want, lab.carved())
	}
	waitFor(t, convergeBudget, "the carved drop to count the mesh's prefixes inside an exemption from each link", func() bool {
		return borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4") >= carved+2
	})
}

// conflicts is each antispoof.conflict the leaf's node recorded, as the prefix
// another node holds, the part of the exemption carved, the exemption, its
// interface and the peer the prefix is routed via
func (lab *antispoofLab) conflicts() []string {
	var out []string
	for _, event := range lab.d.node.events.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0) {
		a := event.Attrs
		out = append(out, fmt.Sprintf("%s carved %s of %s via %s routed via %s", a["prefix"], a["carved"], a["exemption"], a["interface"], a["routed_via"]))
	}
	return out
}

// passes is how many antispoof.pass events the leaf's node recorded
func (lab *antispoofLab) passes() int {
	return len(lab.d.node.events.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pass" }, 0))
}

// pass hands the filter the configuration it holds, which moves nothing, and
// waits for the pass that wakes, which a pass that writes nothing records no
// event for
func (lab *antispoofLab) pass(t *testing.T) {
	t.Helper()
	at := lab.border.Stats().At
	if err := lab.border.SetConfig(lab.border.Capability()); err != nil {
		t.Fatalf("wake the antispoof filter: %v", err)
	}
	waitFor(t, convergeBudget, "the antispoof filter to run another pass", func() bool { return lab.border.Stats().At.After(at) })
}

// a gateway announcing 192.0.2.0/25 by cap.route, its site behind carx and
// exempt under that interface's name, passes the site's sources from carx and
// drops the same source from its uplink. It drops its own node address, which
// cap.table assigns inside the range, and another node's prefix inside the
// range, reporting that prefix once by an event naming the peer it is routed
// via. A more specific prefix of another node coming later is carved at the
// next pass.
func TestTUNAntispoofGatewayExemptsItsSiteAndNoOtherNode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := startAntispoofLab(t, nil)
	cfg := *lab.d.node.config()
	cfg.Cap.Route = &babel.Routes{Announce: []schema.Announce{{Prefix: schema.MustPrefix("192.0.2.0/25")}}}
	lab.d.node.cfg.Store(&cfg)
	lab.exempt(t, &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"carx": {Exempt: []schema.Prefix{schema.MustPrefix("192.0.2.0/25")}}}})
	lab.holds(t, "accept exempt via carx source 192.0.2.0/25")
	carved, overlay := borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4"), borderDropped(t, lab.leaf, lab.border, "drop ipv4 source 192.0.2.0/24")
	lab.send(t, []string{"192.0.2.65"}, []string{"192.0.2.65", "192.0.2.100", "192.0.2.1", "192.0.2.70"})
	want := []string{"carx 192.0.2.100", "carx 192.0.2.65"}
	if got := lab.delivered(t); !slices.Equal(got, want) {
		t.Errorf("the leaf's socket took %q, want %q, with %s", got, want, lab.carved())
	}
	waitFor(t, convergeBudget, "the carved drop to count the node's own address and the other node's prefix, and the overlay's the uplink's source", func() bool {
		return borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4") >= carved+2 && borderDropped(t, lab.leaf, lab.border, "drop ipv4 source 192.0.2.0/24") >= overlay+1
	})
	// a conflict reported on every pass records one event per pass
	lab.pass(t)
	reported := "192.0.2.70/32 carved 192.0.2.70/32 of 192.0.2.0/25 via carx routed via " + lab.d.learned.ID
	if got := lab.conflicts(); !slices.Equal(got, []string{reported}) {
		t.Errorf("the node recorded the conflicts %q, want %q once", got, reported)
	}

	passes := lab.passes()
	lab.d.node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("192.0.2.96/28"), lab.d.learned)
	waitFor(t, convergeBudget, "a pass writing the other node's more specific prefix", func() bool { return lab.passes() > passes })
	carved = borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4")
	lab.send(t, nil, []string{"192.0.2.100", "192.0.2.65"})
	if got := lab.delivered(t); !slices.Equal(got, []string{"carx 192.0.2.65"}) {
		t.Errorf("the leaf's socket took %q, want %q, with %s", got, []string{"carx 192.0.2.65"}, lab.carved())
	}
	waitFor(t, convergeBudget, "the carved drop to count the later prefix's source", func() bool {
		return borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4") >= carved+1
	})
	later := "192.0.2.96/28 carved 192.0.2.96/28 of 192.0.2.0/25 via carx routed via " + lab.d.learned.ID
	if got := lab.conflicts(); !slices.Contains(got, later) {
		t.Errorf("the node recorded the conflicts %q, want %q among them", got, later)
	}
}

// exemptions covering the overlay pass every overlay source the mesh's table
// holds no prefix for, from every interface outside the mesh, while a mesh
// prefix is still dropped as carved
func TestTUNAntispoofExemptingTheOverlayKeepsTheCarvedDrops(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := startAntispoofLab(t, &egress.Antispoof{Exempt: rulesOverlay})
	lab.holds(t, "accept exempt source 3fff::/20")
	carved4, carved6 := borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4"), borderDropped(t, lab.leaf, lab.border, "drop ipv6 source @carved6")
	lab.send(t,
		[]string{"192.0.2.10", "3fff::99", "192.0.2.70", "3fff::5"},
		[]string{"192.0.2.200", "3fff:0:9::1", "192.0.2.130"})
	want := []string{"carx 192.0.2.200", "carx 3fff:0:9::1", rulesUplink + " 192.0.2.10", rulesUplink + " 3fff::99"}
	slices.Sort(want)
	if got := lab.delivered(t); !slices.Equal(got, want) {
		t.Errorf("the leaf's socket took %q, want %q, with %s", got, want, lab.carved())
	}
	waitFor(t, convergeBudget, "the carved drops to count the mesh's prefixes", func() bool {
		return borderDropped(t, lab.leaf, lab.border, "drop ipv4 source @carved4") >= carved4+2 &&
			borderDropped(t, lab.leaf, lab.border, "drop ipv6 source @carved6") >= carved6+1
	})
}
