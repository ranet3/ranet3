// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
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

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

var (
	// labForged4 and labForged6 are the far host's addresses inside the overlay, which no packet from beyond the uplink may carry into the mesh
	labForged4 = netip.MustParsePrefix("198.18.104.200/32")
	labForged6 = netip.MustParsePrefix("3fff:a::200/128")
)

// labVRF is the master the VRF arm enslaves the mesh tun and the exit's end of the uplink to
const labVRF = "labv"

// borderLab is the border's lab: the exit's node, its reconciler and its
// border built as main builds them, a far host beyond the uplink, and a
// capture of the mesh tun
type borderLab struct {
	exit, far *namespaceThread
	node      *Client
	border    *egress.BorderFilter
	capture   int
	listeners [2]*net.UDPConn
	// stopBorder withdraws the border alone, and stop the border, the reconciler and the node
	stopBorder, stop func()
}

// The border in two namespaces. The exit runs a node
// started through New with cap.table, cap.border and an egress segment, with
// the reconciler and the border built as main builds them, and an uplink of a
// veth pair to a far host in a namespace of its own.
//   - a packet from the far host with a source outside the overlay, to a
//     mesh destination, crosses the mesh tun, so the path exists
//   - the same from a source inside the overlay never does, and the border
//     counts it
//   - a type 4 routing header, alone or behind one of type 0 or 2, never
//     crosses the tun and is counted, as is a packet to the local SID
//   - a packet from beyond the uplink to another node's SID, with no routing
//     header and an outer source outside the overlay, crosses the tun, and
//     the SID's owner refuses and counts it, delivering one from inside
//   - a packet the mesh writes into the tun with a mesh source reaches the far
//     host, so the tun is inside
//   - with the border withdrawn and forwarding off, the packet of the first
//     arm no longer crosses the tun, so the host forwards nothing from its
//     links into the mesh without forwarding
//   - with the tun and the uplink in a VRF, the first and fourth arms again,
//     so a packet meeting prerouting a second time as the master passes
//   - shutdown leaves no inet table of the border
//
// The egress device's place inside is the egress lab's steered packet, which
// runs with the border built.
func TestTUNBorderDropsAForgedSourceAtTheUplink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	t.Run("in the host's own tables", func(t *testing.T) {
		lab := startBorderLab(t, "")
		for _, arm := range []struct {
			family     string
			from, leaf netip.Addr
		}{{"IPv4", labFar4.Addr(), labLeaf4}, {"IPv6", labFar6.Addr(), labHeadend}} {
			t.Run("a source outside the overlay over "+arm.family, func(t *testing.T) {
				payload := []byte("from outside the overlay over " + arm.family)
				labCaptureReply(t, lab.capture, arm.leaf, payload, lab.sender(t, arm.from, arm.leaf, payload))
			})
		}
		for _, arm := range []struct {
			family     string
			from, leaf netip.Addr
			spec       string
		}{
			{"IPv4", labForged4.Addr(), labLeaf4, "drop ipv4 source 198.18.0.0/15"},
			{"IPv6", labForged6.Addr(), labHeadend, "drop ipv6 source 3fff::/20"},
		} {
			t.Run("a source inside the overlay over "+arm.family, func(t *testing.T) {
				payload := []byte("forged inside the overlay over " + arm.family)
				before := lab.dropped(t, arm.spec)
				lab.quiet(t, payload, labReplyTo(arm.leaf, payload), lab.sender(t, arm.from, arm.leaf, payload))
				lab.counts(t, arm.spec, before)
			})
		}
		// an address of the leaf's mesh prefix, which a packet the border passes reaches through the tun
		beyond := netip.MustParseAddr("3fff:a::d4")
		for _, arm := range []struct {
			name    string
			routing []uint8
		}{
			{"a type 4 routing header", []uint8{4}},
			{"a type 4 routing header behind a type 0", []uint8{0, 4}},
			{"a type 4 routing header behind a type 2", []uint8{2, 4}},
		} {
			t.Run(arm.name, func(t *testing.T) {
				const spec = "drop ipv6 routing header"
				payload := []byte(arm.name + " from beyond the uplink")
				before := lab.dropped(t, spec)
				lab.quiet(t, payload, labIPv6To(beyond, payload), func() { lab.raw(t, beyond, labOuter(labFar6.Addr(), beyond, arm.routing, payload)) })
				lab.counts(t, spec, before)
			})
		}
		t.Run("a packet to the local SID", func(t *testing.T) {
			spec := "drop ipv6 destination " + labSID.String()
			before := lab.dropped(t, spec)
			lab.routeFar(t, netip.PrefixFrom(labSID, 128), labExit6.Addr())
			lab.sender(t, labFar6.Addr(), labSID, []byte("to the SID from beyond the uplink"))()
			lab.counts(t, spec, before)
		})
		t.Run("another node's SID from outside the overlay", func(t *testing.T) {
			// an address of the leaf's mesh prefix, standing for an End.DT46 SID of the leaf's
			other := netip.MustParseAddr("3fff:a::d46")
			// outer is a packet from source to other with no routing header, carrying an IPv4 packet with a mesh source
			outer := func(source netip.Addr, payload []byte) []byte { return labOuter(source, other, nil, payload) }
			// it carries no mesh source, no routing header and none of this node's SIDs, so the border passes it into the mesh
			crossing := []byte("to another node's SID from beyond the uplink")
			crossed := false
			for deadline := time.Now().Add(convergeBudget); !crossed && time.Now().Before(deadline); {
				lab.raw(t, other, outer(labFar6.Addr(), crossing))
				crossed = labCaptured(lab.capture, labIPv6To(other, crossing))
			}
			if !crossed {
				t.Fatalf("the packet to %s never crossed the mesh tun", other)
			}

			// the SID's owner, here this node with the SID in the table it builds, refuses it, counts it and delivers nothing
			cfg := *lab.node.config()
			segment := *cfg.Cap.Segment
			segment.Local = append(slices.Clone(segment.Local), srv6.Segment{SID: schema.AddrFrom(other), Behavior: srv6.BehaviorEndDT46})
			cfg.Cap.Segment = &segment
			table, _, err := cfg.SegmentTables()
			if err != nil {
				t.Fatalf("build the owner's table: %v", err)
			}
			held := lab.node.Mesh.Segments()
			lab.node.Mesh.SetSegments(table)
			defer lab.node.Mesh.SetSegments(held)
			// the inner packet's destination is an address of the owner's host, as one cap.table assigns, so its mesh writes it to the tun
			// and the reconciler writes nothing for it into the kernel
			owned := netip.PrefixFrom(labExit4.Addr(), 32)
			lab.node.Mesh.Routes.Set(netip.Prefix{}, owned, netstack.Assigned)
			defer lab.node.Mesh.Routes.Remove(netip.Prefix{}, owned)
			var listener *net.UDPConn
			if err := lab.exit.do(func() (err error) {
				listener, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(labExit4.Addr(), labPort)))
				return err
			}); err != nil {
				t.Fatalf("listen at the owner: %v", err)
			}
			defer listener.Close()
			refused := lab.node.Mesh.SegmentCounters().Refused
			forged := []byte("forged through another node's SID")
			lab.node.Mesh.DeliverInbound(outer(labFar6.Addr(), forged), 0)
			labQuietFor(t, listener, forged)
			if got := lab.node.Mesh.SegmentCounters().Refused; got != refused+1 {
				t.Errorf("the owner counted %d refusals past %d, want one", got-refused, refused)
			}
			inside := []byte("through another node's SID from inside the overlay")
			if from := labReceive(t, listener, inside, func() { lab.node.Mesh.DeliverInbound(outer(labHeadend, inside), 0) }); from.Addr() != labLeaf4 {
				t.Errorf("from inside the overlay the owner's socket read %s, want %s", from, labLeaf4)
			}
		})
		lab.written(t)

		t.Run("forwarding off with the border withdrawn", func(t *testing.T) {
			lab.stopBorder()
			lab.withoutTable(t)
			if err := lab.exit.do(func() error {
				for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
					if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("turn forwarding off at the exit: %v", err)
			}
			for _, arm := range []struct{ from, leaf netip.Addr }{{labFar4.Addr(), labLeaf4}, {labFar6.Addr(), labHeadend}} {
				payload := []byte("with forwarding off from " + arm.from.String())
				lab.quiet(t, payload, labReplyTo(arm.leaf, payload), lab.sender(t, arm.from, arm.leaf, payload))
			}
		})
		lab.stop()
		lab.withoutTable(t)
	})

	t.Run("in a vrf", func(t *testing.T) {
		lab := startBorderLab(t, labVRF)
		if !slices.Contains(lab.border.Inside(), labVRF) {
			t.Fatalf("the border accepts %v, without the vrf master %s", lab.border.Inside(), labVRF)
		}
		for _, arm := range []struct{ from, leaf netip.Addr }{{labFar4.Addr(), labLeaf4}, {labFar6.Addr(), labHeadend}} {
			payload := []byte("from outside the overlay through the vrf from " + arm.from.String())
			labCaptureReply(t, lab.capture, arm.leaf, payload, lab.sender(t, arm.from, arm.leaf, payload))
		}
		lab.written(t)
		lab.stop()
		lab.withoutTable(t)
	})
}

// an exit whose border's chain is not read back writes neither family into a
// real egress device, whatever the translator holds, and with the chain read
// back it writes each family the translator holds
func TestTUNEgressCarriesNothingWhileTheBorderIsNotReady(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(labSID.String(), labLeaves...)) })
	carried := meshCarrying(t, c)
	speakerRecording(t, c, bus)
	for _, step := range []struct{ v4, v6, border bool }{
		{true, true, false},
		{true, true, true},
		{true, true, false},
		{true, false, true},
		{false, true, true},
		{false, true, false},
	} {
		c.SetEgressReady(step.v4, step.v6, step.v4 || step.v6)
		c.SetBorderReady(step.border)
		if got, want := carried(), [2]bool{step.v4 && step.border, step.v6 && step.border}; got != want {
			t.Errorf("with the translator holding %v %v and the border ready %v the mesh carries %v, want %v", step.v4, step.v6, step.border, got, want)
		}
	}
}

// meshCarrying gives c a mesh on a tun in a namespace of its own, holding the
// tables of its cap.segment and writing into a real egress device, and returns
// the families of a steered packet to labSID the mesh writes into the device
func meshCarrying(t *testing.T, c *Client) func() [2]bool {
	t.Helper()
	segments, steering, err := c.config().SegmentTables()
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
	return func() (families [2]bool) {
		t.Helper()
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
}

// startBorderLab makes the two namespaces and their uplink, the exit's tun
// and the uplink's end enslaved to master where it is not empty, and starts
// the exit's node, reconciler and border with the leaves' routes in the mesh
func startBorderLab(t *testing.T, master string) *borderLab {
	t.Helper()
	lab := &borderLab{exit: startNamespaceThread(t), far: startNamespaceThread(t)}
	labUplink(t, lab.exit, lab.far, master)
	cfg := labConfig(t)
	if master != "" {
		cfg.Cap.Table.VRF = &kernel.VRF{Name: master}
	}
	bus := events.New()
	if err := lab.exit.do(func() (err error) {
		lab.node, err = New(cfg, bus)
		return err
	}); err != nil {
		t.Fatalf("start the exit: %v", err)
	}
	leaf := netstack.NewPeer("example/leaf", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the leaf is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(leaf.Close)
	for _, prefix := range labLeafPrefixes() {
		lab.node.Mesh.Routes.Set(netip.Prefix{}, prefix, leaf)
	}
	var routes *kernel.Reconciler
	if err := lab.exit.do(func() (err error) {
		if routes, err = kernel.New(*cfg.Cap.Table, lab.node.KernelRuntime(), lab.node.Mesh.Routes); err != nil {
			return err
		}
		lab.border, err = egress.NewBorderFilter(*cfg.Cap.Border, lab.node.BorderRuntime())
		return err
	}); err != nil {
		lab.node.Close()
		t.Fatalf("build the reconciler and the border: %v", err)
	}
	lab.node.SetBorder(lab.border)
	borderCtx, cancelBorder := context.WithCancel(context.Background())
	borderDone := make(chan struct{})
	go func() {
		defer close(borderDone)
		if err := lab.border.Run(borderCtx); err != nil {
			t.Errorf("the border: %v", err)
		}
	}()
	lab.stopBorder = sync.OnceFunc(func() {
		cancelBorder()
		<-borderDone
	})
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	runs.Go(func() {
		if err := routes.Run(ctx); err != nil {
			t.Errorf("the reconciler: %v", err)
		}
	})
	// as main stops them: the reconciler, then the border
	lab.stop = sync.OnceFunc(func() {
		cancel()
		runs.Wait()
		lab.stopBorder()
		lab.node.Close()
	})
	t.Cleanup(lab.stop)
	waitFor(t, convergeBudget, "the mesh table covering the leaves", func() bool {
		return labMeshRoute(t, lab.exit, labLeafPrefixes()[0]) && labMeshRoute(t, lab.exit, labLeafPrefixes()[1])
	})

	if err := lab.far.do(func() error {
		netlink, err := openNetlinkRoute()
		if err != nil {
			return err
		}
		defer netlink.close()
		if err := labAddress(netlink, "labf", labForged4, labForged6); err != nil {
			return err
		}
		uplink, err := net.InterfaceByName("labf")
		if err != nil {
			return err
		}
		for _, leaves := range []struct {
			to      netip.Prefix
			gateway netip.Addr
		}{{labLeafPrefixes()[1], labExit4.Addr()}, {labLeafPrefixes()[0], labExit6.Addr()}} {
			if err := labRouteVia(netlink, uplink.Index, leaves.to, leaves.gateway); err != nil {
				return fmt.Errorf("route %s through the exit: %w", leaves.to, err)
			}
		}
		for i, address := range []netip.Addr{labFar4.Addr(), labFar6.Addr()} {
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, labPort)))
			if err != nil {
				return err
			}
			lab.listeners[i] = conn
		}
		return nil
	}); err != nil {
		t.Fatalf("set up the far host: %v", err)
	}
	for _, conn := range lab.listeners {
		t.Cleanup(func() { _ = conn.Close() })
	}
	if err := lab.exit.do(func() (err error) {
		lab.capture, err = openCapture(lab.node.Mesh.Name, labRetry)
		return err
	}); err != nil {
		t.Fatalf("capture the mesh tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(lab.capture) })
	return lab
}

// written sends a packet of each family from a leaf's address through the
// mesh into the tun, as a session would deliver it, and reads it at the far
// host: the border accepts the tun, and in a VRF the master
// the mesh writes a packet to the tun only for a destination it holds as this node's
// so the far host's addresses are held as addresses cap.table assigns, which the reconciler leaves out of the kernel
func (lab *borderLab) written(t *testing.T) {
	t.Helper()
	for _, far := range []netip.Addr{labFar4.Addr(), labFar6.Addr()} {
		host := netip.PrefixFrom(far, far.BitLen())
		lab.node.Mesh.Routes.Set(netip.Prefix{}, host, netstack.Assigned)
		t.Cleanup(func() { lab.node.Mesh.Routes.Remove(netip.Prefix{}, host) })
	}
	for i, arm := range []struct{ leaf, far netip.Addr }{{labLeaf4, labFar4.Addr()}, {labHeadend, labFar6.Addr()}} {
		t.Run("a mesh source written into the tun from "+arm.leaf.String(), func(t *testing.T) {
			payload := []byte("written into the tun from " + arm.leaf.String())
			labReceive(t, lab.listeners[i], payload, func() { lab.node.Mesh.DeliverInbound(udpPacket(arm.leaf, arm.far, labLeafPort, labPort, payload), 0) })
		})
	}
}

// sender is a UDP socket of the far host's from source to the leaf's port at
// leaf, and a send of payload on it
func (lab *borderLab) sender(t *testing.T, source, leaf netip.Addr, payload []byte) func() {
	t.Helper()
	var conn *net.UDPConn
	if err := lab.far.do(func() (err error) {
		conn, err = net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(leaf, labLeafPort)))
		return err
	}); err != nil {
		t.Fatalf("open a socket of the far host from %s: %v", source, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return func() {
		// a send the kernel refuses is a packet that never left, which the caller's capture reads as such
		_, _ = conn.Write(payload)
	}
}

// raw sends packet, an IPv6 packet with its own header, from the far host to destination
func (lab *borderLab) raw(t *testing.T, destination netip.Addr, packet []byte) {
	t.Helper()
	if err := lab.far.do(func() error {
		// IPPROTO_RAW over IPv6 takes the header from the packet
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, packet, 0, &unix.SockaddrInet6{Addr: destination.As16()})
	}); err != nil {
		t.Fatalf("send a raw packet to %s from the far host: %v", destination, err)
	}
}

// routeFar routes to through gateway at the far host
func (lab *borderLab) routeFar(t *testing.T, to netip.Prefix, gateway netip.Addr) {
	t.Helper()
	if err := lab.far.do(func() error {
		netlink, err := openNetlinkRoute()
		if err != nil {
			return err
		}
		defer netlink.close()
		uplink, err := net.InterfaceByName("labf")
		if err != nil {
			return err
		}
		return labRouteVia(netlink, uplink.Index, to, gateway)
	}); err != nil {
		t.Fatalf("route %s through %s at the far host: %v", to, gateway, err)
	}
}

// dropped is the packets the border's rule spec has counted, read now in the exit's namespace
func (lab *borderLab) dropped(t *testing.T, spec string) uint64 {
	t.Helper()
	return borderDropped(t, lab.exit, lab.border, spec)
}

// borderDropped is the packets border's rule spec has counted, read now in
// the exit's namespace, where the debug read opens its socket
func borderDropped(t *testing.T, exit *namespaceThread, border *egress.BorderFilter, spec string) uint64 {
	t.Helper()
	var debug egress.BorderDebug
	_ = exit.do(func() error {
		debug = border.Debug()
		return nil
	})
	if debug.Err != "" {
		t.Fatalf("read the border's chain: %s", debug.Err)
	}
	index := slices.IndexFunc(debug.Rules, func(rule egress.BorderReading) bool { return rule.Spec == spec })
	if index < 0 || !debug.Rules[index].Held {
		t.Fatalf("the border's chain holds no %q in %+v", spec, debug.Rules)
	}
	return debug.Rules[index].Packets
}

// counts waits for the border's rule spec to count a packet past before
func (lab *borderLab) counts(t *testing.T, spec string, before uint64) {
	t.Helper()
	waitFor(t, convergeBudget, "the border to count a packet on "+spec, func() bool { return lab.dropped(t, spec) > before })
}

// quiet sends once and fails the test if the capture reads a packet match
// takes within labQuiet
func (lab *borderLab) quiet(t *testing.T, payload []byte, match func([]byte) bool, send func()) {
	t.Helper()
	send()
	for range labQuiet / labRetry {
		if labCaptured(lab.capture, match) {
			t.Errorf("%q crossed the mesh tun", payload)
			return
		}
	}
}

// labOuter is an IPv6 packet from source to destination carrying a routing
// header of each type in routing, in order, each naming destination with no
// segments left, then an IPv4 UDP packet from a leaf carrying payload
func labOuter(source, destination netip.Addr, routing []uint8, payload []byte) []byte {
	body := udpPacket(labLeaf4, labExit4.Addr(), labLeafPort, labPort, payload)
	next := uint8(srv6.NextHeaderIPv4)
	for _, kind := range slices.Backward(routing) {
		// one address, so a header length of 2 in units of 8 bytes past the first 8
		header := make([]byte, 24, 24+len(body))
		header[0], header[1], header[2] = next, 2, kind
		copy(header[8:], destination.AsSlice())
		body, next = append(header, body...), unix.IPPROTO_ROUTING
	}
	header := make([]byte, 40, 40+len(body))
	header[0], header[4], header[5], header[6], header[7] = 0x60, byte(len(body)>>8), byte(len(body)), next, 64
	copy(header[8:], source.AsSlice())
	copy(header[24:], destination.AsSlice())
	return append(header, body...)
}

// withoutTable fails the test if the exit holds an nftables table of the
// binary's name in a family the binary writes
func (lab *borderLab) withoutTable(t *testing.T) {
	t.Helper()
	if err := lab.exit.do(func() error {
		for _, family := range []uint8{unix.NFPROTO_INET, unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
			if err := labDeleteTable(family, egress.TableName); !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("deleting the exit's table of family %d answered %v, want it gone", family, err)
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}
