// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

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
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

const (
	// labTUN is the exit's mesh tun, and labEgress the egress device named after it
	labTUN    = "lab0"
	labEgress = "lab0e"
	// labPort is the far host's listening port, and labLeafPort the port the leaf sends from
	labPort     = 9000
	labLeafPort = 40000
	// labRetry is how long one read waits before a packet is sent again, and labQuiet how long a packet that must not arrive is waited for
	labRetry = 250 * time.Millisecond
	labQuiet = time.Second
	// labIIFPriority is the priority of the egress device's rule, between the to rules at 100 and the from rule at 150
	labIIFPriority = 120
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
)

// An exit node in a namespace of its own, started through New with the
// reconciler and the translator main builds, carries a synthetic leaf's
// steered packets out of a veth uplink to a far host in another namespace.
func TestTUNEgressSegmentCarriesSteeredTrafficOutOfTheUplink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	exit, far := startNamespaceThread(t), startNamespaceThread(t)
	labUplink(t, exit, far)
	cfg := labConfig(t)
	bus := events.New()
	var node *Client
	if err := exit.do(func() (err error) {
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

	before := node.Mesh.SegmentCounters()
	steer(udpPacket(labHeadend, labFar6.Addr(), labLeafPort, labPort, []byte("before the first pass")))
	if got := node.Mesh.SegmentCounters(); got.NotReady != before.NotReady+1 || got.Egressed != before.Egressed {
		t.Errorf("an egress result before the translator's first pass counted %+v, want one more not ready", got)
	}

	// the replies leave through the mesh tun by a route the reconciler installs for the leaf's prefixes, as babel would select it
	// and the mesh carries a route covering the far host too, which the from rules would send a steered packet into without the egress device's rule
	leaf := netstack.NewPeer("example/leaf", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the leaf is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(leaf.Close)
	for _, prefix := range append([]netip.Prefix{labFar4.Masked(), labFar6.Masked()}, labLeafPrefixes()...) {
		node.Mesh.Routes.Set(netip.Prefix{}, prefix, leaf)
	}
	var routes *kernel.Reconciler
	var translator *egress.Translator
	inExit := func(f func()) { _ = exit.do(func() error { f(); return nil }) }
	if err := exit.do(func() (err error) {
		if routes, err = kernel.New(*cfg.Cap.Table, node.KernelRuntime(), node.Mesh.Routes); err != nil {
			return err
		}
		reader := node.EgressDeviceReader()
		// the sysctls are read in the exit's namespace, which the translator's own goroutine is not in
		translator, err = egress.New(*cfg.Egress(), egress.Runtime{
			Interface:     node.Mesh.Name,
			MeshAddresses: MeshAddresses(cfg),
			Forwarding:    func() (v4, v6 bool) { inExit(func() { v4, v6 = Forwarding() }); return v4, v6 },
			Announce:      func([]netip.Prefix) { node.Republish() },
			Events:        bus,
			Egress:        node.EgressDevice(),
			Device:        func() (v4, v6 error) { inExit(func() { v4, v6 = reader() }); return v4, v6 },
			Ready:         node.SetEgressReady,
		})
		return err
	}); err != nil {
		t.Fatalf("build the reconciler and the translator: %v", err)
	}
	node.SetEgressAnnounce(translator.Announce)
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
	waitFor(t, convergeBudget, "the egress device ready for both families, its rule installed and the mesh table covering the far host", func() bool {
		stats := translator.Stats()
		return stats.Ready4 && stats.Ready6 && labRuleHeld(t, exit, unix.AF_INET) && labRuleHeld(t, exit, unix.AF_INET6) &&
			labMeshRoute(t, exit, labFar4.Masked()) && labMeshRoute(t, exit, labFar6.Masked())
	})

	var listeners [2]*net.UDPConn
	if err := far.do(func() error {
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
	if err := exit.do(func() (err error) {
		capture, err = openCapture(node.Mesh.Name, labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture the mesh tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })

	arms := []struct {
		name            string
		leaf, far, exit netip.Addr
		listener        *net.UDPConn
	}{
		{"IPv4", labLeaf4, labFar4.Addr(), labExit4.Addr(), listeners[0]},
		{"IPv6", labHeadend, labFar6.Addr(), labExit6.Addr(), listeners[1]},
	}
	carry := func(t *testing.T, leafAddr, farAddr, exitAddr netip.Addr, listener *net.UDPConn, payload string) netip.AddrPort {
		t.Helper()
		egressed := node.Mesh.SegmentCounters().Egressed
		from := labReceive(t, listener, []byte(payload), func() { steer(udpPacket(leafAddr, farAddr, labLeafPort, labPort, []byte(payload))) })
		if from.Addr().Unmap() != exitAddr {
			t.Errorf("the far host read the steered packet from %s, want the exit's uplink address %s", from, exitAddr)
		}
		if node.Mesh.SegmentCounters().Egressed <= egressed {
			t.Error("the steered packet reached the far host and no egress was counted")
		}
		return from
	}
	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			from := carry(t, arm.leaf, arm.far, arm.exit, arm.listener, "steered "+arm.name)
			reply := []byte("reply " + arm.name)
			labCaptureReply(t, capture, arm.leaf, reply, func() {
				if _, err := arm.listener.WriteToUDPAddrPort(reply, from); err != nil {
					t.Fatalf("reply from the far host: %v", err)
				}
			})
		})
	}

	t.Run("a source outside the allow list", func(t *testing.T) {
		before := node.Mesh.SegmentCounters()
		payload := []byte("from outside the list")
		steer(udpPacket(labOutside, labFar4.Addr(), labLeafPort, labPort, payload))
		if got := node.Mesh.SegmentCounters(); got.Refused != before.Refused+1 || got.Egressed != before.Egressed {
			t.Errorf("a source outside the list counted %+v, want one more refused", got)
		}
		labQuietFor(t, listeners[0], payload)
	})

	t.Run("another writer deleting the egress device's rule", func(t *testing.T) {
		for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
			if err := exit.do(func() error { return labDeleteRule(family) }); err != nil {
				t.Fatalf("delete the egress device's rule: %v", err)
			}
		}
		waitFor(t, convergeBudget, "the reconciler to put the egress device's rule back", func() bool {
			return labRuleHeld(t, exit, unix.AF_INET) && labRuleHeld(t, exit, unix.AF_INET6)
		})
	})

	t.Run("another writer deleting the ip table", func(t *testing.T) {
		mark := len(readiness(bus))
		if err := exit.do(func() error { return labDeleteTable(unix.NFPROTO_IPV4, egress.TableName) }); err != nil {
			t.Fatalf("delete the ip table: %v", err)
		}
		waitFor(t, convergeBudget, "the translator to report the device not ready and then ready again", func() bool {
			moved := readiness(bus)[mark:]
			down := slices.Index(moved, "false false")
			return down >= 0 && slices.Contains(moved[down:], "true true")
		})
		carry(t, labLeaf4, labFar4.Addr(), labExit4.Addr(), listeners[0], "steered after the table came back")
	})

	// IPv6 coming back on has the kernel send its MLD reports out of the device, which the drain reads and leaves uncounted
	t.Run("another writer turning IPv6 off on the egress device", func(t *testing.T) {
		path := "/proc/sys/net/ipv6/conf/" + labEgress + "/disable_ipv6"
		if err := exit.do(func() error { return os.WriteFile(path, []byte("1\n"), 0o644) }); err != nil {
			t.Fatalf("turn IPv6 off on the egress device: %v", err)
		}
		waitFor(t, convergeBudget, "a pass to put the egress device's disable_ipv6 back to 0", func() bool {
			var body []byte
			if err := exit.do(func() (err error) { body, err = os.ReadFile(path); return err }); err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			return strings.TrimSpace(string(body)) == "0"
		})
		carry(t, labHeadend, labFar6.Addr(), labExit6.Addr(), listeners[1], "steered after IPv6 came back on")
		if drained := node.Mesh.SegmentCounters().Drained; drained != 0 {
			t.Errorf("drained reads %d after disable_ipv6 was put back, want 0", drained)
		}
	})

	t.Run("a packet from the far host to the SID", func(t *testing.T) {
		before := node.Mesh.SegmentCounters()
		if err := far.do(func() error {
			netlink, err := openNetlinkRoute()
			if err != nil {
				return err
			}
			defer netlink.close()
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
	})

	t.Run("the egress device deleted under the mesh", func(t *testing.T) {
		waitFor(t, convergeBudget, "the SID's /128 originated", func() bool { return sidOriginated(node, labSID.String()) })
		if err := exit.do(func() error {
			link, err := net.InterfaceByName(labEgress)
			if err != nil {
				return err
			}
			netlink, err := openNetlinkRoute()
			if err != nil {
				return err
			}
			defer netlink.close()
			return netlink.request(unix.RTM_DELLINK, 0, ifinfo(link.Index, 0))
		}); err != nil {
			t.Fatalf("delete the egress device: %v", err)
		}
		waitFor(t, convergeBudget, "both families not ready and the SID's /128 withdrawn", func() bool {
			stats := translator.Stats()
			return !stats.Ready4 && !stats.Ready6 && !sidOriginated(node, labSID.String())
		})
		if got := translator.Stats().Unready; !strings.Contains(got, "the egress device is gone") {
			t.Errorf("the translator reports the reason %q, want the device gone", got)
		}
		before := node.Mesh.SegmentCounters()
		steer(udpPacket(labHeadend, labFar6.Addr(), labLeafPort, labPort, []byte("after the device went")))
		if got := node.Mesh.SegmentCounters(); got.NotReady != before.NotReady+1 {
			t.Errorf("an egress result after the device went counted %+v, want one more not ready", got)
		}
	})

	stop()
	var actions []string
	for _, event := range recorded(bus, "egress.device") {
		actions = append(actions, event.Attrs["name"]+" "+event.Attrs["action"])
	}
	if want := []string{labEgress + " created", labEgress + " withdrawn"}; !slices.Equal(actions, want) {
		t.Errorf("the egress device was recorded as %q, want %q", actions, want)
	}
	if err := exit.do(func() error {
		for _, name := range []string{labEgress, labTUN} {
			if _, err := net.InterfaceByName(name); err == nil {
				return fmt.Errorf("%s outlived the node", name)
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
// mesh's word read by what it writes into a real egress device
func TestTUNSetEgressReadyMovesTheMeshBeforeTheAnnouncement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(labSID.String(), labLeaves...)) })
	segments, steering, err := c.config().Segments().Tables()
	if err != nil {
		t.Fatal(err)
	}
	if err := startNamespaceThread(t).do(func() error {
		mesh, err := netstack.NewNamed(0, labTUN, nil)
		if err != nil {
			return err
		}
		device, err := netstack.NewEgressDevice(labEgress, netstack.DefaultMTU)
		if err != nil {
			mesh.Close()
			return err
		}
		mesh.SetSegments(segments)
		mesh.SetSteering(steering)
		mesh.SetEgress(device)
		c.Mesh = mesh
		return nil
	}); err != nil {
		t.Fatalf("open the mesh and its egress device: %v", err)
	}
	t.Cleanup(c.Mesh.Close)
	speakerRecording(t, c, bus)
	carried := func() (families [2]bool) {
		for i, inner := range [][]byte{
			udpPacket(labLeaf4, labFar4.Addr(), labLeafPort, labPort, []byte("steered IPv4")),
			udpPacket(labHeadend, labFar6.Addr(), labLeafPort, labPort, []byte("steered IPv6")),
		} {
			outer, err := srv6.Encapsulate(inner, labHeadend, []netip.Addr{labSID})
			if err != nil {
				t.Fatalf("encapsulate toward %s: %v", labSID, err)
			}
			egressed := c.Mesh.SegmentCounters().Egressed
			c.Mesh.DeliverInbound(outer, 0)
			families[i] = c.Mesh.SegmentCounters().Egressed > egressed
		}
		return families
	}
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

// labConfig is the reload fixture's node made an exit with the egress segment,
// cap.egress and a cap.table holding the to rules, the egress device's rule
// and from rules for the leaves into the mesh table
func labConfig(t *testing.T) *config.Config {
	t.Helper()
	fixture, _ := reloadFixture(t)
	cfg := *fixture.config()
	cfg.Link.TUN = labTUN
	egressNode(&cfg, egressSegment(labSID.String(), labLeaves...))
	// a deleted device is noticed at the next sweep
	cfg.Cap.Egress.Sweep = schema.Duration(time.Second)
	cfg.Cap.Table = &kernel.Table{ID: kernel.DefaultTable, Rules: []kernel.Rule{
		{To: schema.MustPrefix(labLeaves[0]), Table: kernel.DefaultTable, Priority: 100},
		{To: schema.MustPrefix(labLeaves[1]), Table: kernel.DefaultTable, Priority: 100},
		{IIF: labEgress, Table: schema.TableMain, Priority: labIIFPriority, Family: kernel.FamilyBoth},
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
// of the node exists, so the egress device takes it from conf.default
func labUplink(t *testing.T, exit, far *namespaceThread) {
	t.Helper()
	if err := exit.do(func() error {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
				return err
			}
		}
		other, err := unix.Open(far.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(other)
		peer := slices.Concat(ifinfo(0, 0), rtattr(unix.IFLA_IFNAME, cstring("labf")), rtattr(unix.IFLA_NET_NS_FD, u32(uint32(other))))
		kind := slices.Concat(rtattr(unix.IFLA_INFO_KIND, cstring("veth")), rtattr(unix.IFLA_INFO_DATA, rtattr(vethPeer, peer)))
		netlink, err := openNetlinkRoute()
		if err != nil {
			return err
		}
		defer netlink.close()
		if err := netlink.request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
			slices.Concat(ifinfo(0, 0), rtattr(unix.IFLA_IFNAME, cstring("labx")), rtattr(unix.IFLA_LINKINFO, kind))); err != nil {
			return fmt.Errorf("make the veth pair: %w", err)
		}
		return labAddress(netlink, "labx", labExit4, labExit6)
	}); err != nil {
		t.Fatalf("make the exit's end of the uplink: %v", err)
	}
	if err := far.do(func() error {
		netlink, err := openNetlinkRoute()
		if err != nil {
			return err
		}
		defer netlink.close()
		return labAddress(netlink, "labf", labFar4, labFar6)
	}); err != nil {
		t.Fatalf("address the far host's end of the uplink: %v", err)
	}
}

func labAddress(netlink netlinkRoute, name string, addresses ...netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if err := netlink.addAddress(link.Index, address); err != nil {
			return fmt.Errorf("add %s to %s: %w", address, name, err)
		}
	}
	return nil
}

func labRouteVia(netlink netlinkRoute, index int, to netip.Prefix, gateway netip.Addr) error {
	header := []byte{unix.AF_INET6, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, rtattr(unix.RTA_DST, to.Addr().AsSlice()), rtattr(unix.RTA_GATEWAY, gateway.AsSlice()), rtattr(unix.RTA_OIF, u32(uint32(index))))
	return netlink.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
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
	buf := make([]byte, 1<<16)
	for deadline := time.Now().Add(convergeBudget); time.Now().Before(deadline); {
		send()
		for {
			n, _, err := unix.Recvfrom(capture, buf, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				break
			}
			if to, port, got, ok := labUDPOf(buf[:n]); ok && to == leaf && port == labLeafPort && bytes.Equal(got, payload) {
				return
			}
		}
	}
	t.Fatalf("no reply to %s crossed the mesh tun within %s", leaf, convergeBudget)
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

// labRuleHeader is a fib_rule_hdr of family sending to the main table
func labRuleHeader(family uint8) []byte {
	return []byte{family, 0, 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
}

// labDeleteRule deletes the egress device's rule of family as another writer would, in the calling thread's namespace
func labDeleteRule(family uint8) error {
	netlink, err := openNetlinkRoute()
	if err != nil {
		return err
	}
	defer netlink.close()
	return netlink.request(unix.RTM_DELRULE, 0, slices.Concat(labRuleHeader(family),
		rtattr(unix.FRA_IIFNAME, cstring(labEgress)), rtattr(unix.FRA_PRIORITY, u32(labIIFPriority))))
}

// labRuleHeld reports a rule of family in the exit's namespace sending what arrives on the egress device to the main table at its priority
func labRuleHeld(t testing.TB, exit *namespaceThread, family uint8) bool {
	t.Helper()
	var rules []kernelRule
	if err := exit.do(func() (err error) {
		rules, err = dumpRules()
		return err
	}); err != nil {
		t.Fatalf("list the rules: %v", err)
	}
	return slices.Contains(rules, kernelRule{family: family, iif: labEgress, table: unix.RT_TABLE_MAIN, priority: labIIFPriority, protocol: kernel.DefaultProtocol})
}

// labMeshRoute reports a route to prefix in the mesh table of the exit's namespace
func labMeshRoute(t testing.TB, exit *namespaceThread, prefix netip.Prefix) bool {
	t.Helper()
	var routes []kernelRoute
	if err := exit.do(func() (err error) {
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
	return acknowledged(fd, slices.Concat(
		netlinkMessage(unix.NFNL_MSG_BATCH_BEGIN, 0, labNfgen(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES)),
		netlinkMessage(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE, unix.NLM_F_ACK,
			slices.Concat(labNfgen(family, 0), rtattr(unix.NFTA_TABLE_NAME, cstring(name)))),
		netlinkMessage(unix.NFNL_MSG_BATCH_END, 0, labNfgen(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES))))
}

func labNfgen(family uint8, resource uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte{family, unix.NFNETLINK_V0}, resource)
}
