// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// This file runs one configuration file all the way to a running daemon and
// asks what reached the kernel. Everything else in this package builds a
// Client by hand and drives one mechanism, so fifteen call sites wiring the
// darwin underlay together could each be deleted with the whole suite green:
// every mechanism was tested and nothing tested that a file turns them on.
//
// Nothing here needs privilege or a second machine. internal/kernel names the
// machine it reads and writes, see kernel.Host, and recordedKernel is a
// routing table this test writes and reads back. The one thing still left
// with the running kernel is the transport's own UDP sockets, whose datagrams
// name the interface the recorded routes select, which is why the uplink below
// is lo0's index.

// meshDeviceIndex is the tun this node carries the overlay on. No socket is
// bound to it, so it names a device that need not exist.
const meshDeviceIndex = 424

// otherProgramIndex is a device another program routes out of, a VPN's tun.
const otherProgramIndex = 425

// What the mesh announces to this node, what this node announces back, and
// where the machine under it reaches the world. capturingPrefix takes the
// machine and ordinaryPrefix does not, which is the distinction the whole
// capture gate rests on.
var (
	capturingPrefix = netip.MustParsePrefix("::/0")
	// halfCapture takes the machine too and holds ::, so under cap.exit it
	// goes in as the members it contains, the first seven of ipv6Cover
	halfCapture    = netip.MustParsePrefix("::/1")
	ordinaryPrefix = netip.MustParsePrefix("2001:db8:2::/64")
	// ipv6Cover holds the members cap.exit installs capturingPrefix as
	ipv6Cover = []netip.Prefix{
		netip.MustParsePrefix("100::/8"), netip.MustParsePrefix("200::/7"),
		netip.MustParsePrefix("400::/6"), netip.MustParsePrefix("800::/5"),
		netip.MustParsePrefix("1000::/4"), netip.MustParsePrefix("2000::/3"),
		netip.MustParsePrefix("4000::/2"), netip.MustParsePrefix("8000::/1"),
	}
	// witnessPrefix is announced beside a route the daemon should hold back,
	// so that its arrival says a pass has run over both (see daemon.heldBack).
	witnessPrefix = netip.MustParsePrefix("2001:db8:3::/64")
	// laterWitness is the witness of a second held-back route in one test
	laterWitness = netip.MustParsePrefix("2001:db8:4::/64")
	// announcedAddress is the prefix this node originates, which
	// assign_announced puts on the mesh device.
	announcedAddress = netip.MustParsePrefix("2001:db8:1::1/128")
	// announcedAddress4 is the IPv4 one, so the mesh device holds an overlay
	// address of each family and cap.exit covers both
	announcedAddress4 = netip.MustParsePrefix("203.0.113.1/32")
	// hostGateways are the next hops the recorded host reaches the world
	// through, one per family.
	hostGateway4 = netip.MustParseAddr("192.0.2.1")
	hostGateway6 = netip.MustParseAddr("2001:db8:ff::1")
	// peerEndpoint is where the trust document says this node's peer answers,
	// which is an address the transport has to keep reaching past the mesh.
	peerEndpoint = netip.MustParseAddr("198.51.100.7")
)

// daemon is one node built the way the command builds one, on a recorded
// machine.
type daemon struct {
	node   *Client
	routes *kernel.Reconciler
	host   *recordedKernel
	// uplink is the interface the recorded host's own traffic leaves by.
	uplink int
	// stop ends the reconcile loop and waits for it to withdraw, the way the
	// command waits for it before closing the node.
	stop func()
	// file is the configuration file the node was loaded from
	file *daemonFile
}

// recordedHost is the machine a daemon in this file starts on: one uplink
// carrying the host's own default of both families, and a mesh device. A test
// that wants a different machine changes it before handing it to startDaemon.
func recordedHost(t *testing.T) *recordedKernel {
	t.Helper()
	uplink := loopbackIndex(t)
	host := newRecordedKernel(uplink, meshDeviceIndex)
	host.v4 = kernel.RouteAnswer{Index: uplink, Gateway: hostGateway4}
	host.v6 = kernel.RouteAnswer{Index: uplink, Gateway: hostGateway6}
	// The host's own two defaults, the routes none of this may ever touch.
	host.hold(recordedRoute{destination: netip.MustParsePrefix("0.0.0.0/0"), index: uplink, gateway: hostGateway4})
	host.hold(recordedRoute{destination: capturingPrefix, index: uplink, gateway: hostGateway6})
	return host
}

// startDaemon builds one node and its reconciler, under cap.exit where exit
// is true, retrying the port
func startDaemon(t *testing.T, exit bool, host *recordedKernel) *daemon {
	t.Helper()
	var d *daemon
	retryPort(t, "bind", func() (err error) {
		file := newDaemonFile(t)
		if d, err = tryDaemon(t, file.load(t, exit), host); d != nil {
			d.file = file
		}
		return err
	})
	return d
}

// tryDaemon builds the node a loaded configuration describes around a mesh
// with no TUN, and builds the route reconciler out of what the node says about
// itself. The last step is the one under test, as main takes it but for the
// live sends (standInRuntime).
//
// Only the port it could not take comes back as an error. Anything else is
// this test being wrong about the tree and ends it.
func tryDaemon(t *testing.T, cfg *config.Config, host *recordedKernel) (*daemon, error) {
	t.Helper()
	privateKey := daemonIdentity(t, cfg)
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		t.Fatal(err)
	}
	mesh := netstack.NewRoutesOnly()
	// The device the mesh actually got, which the file cannot say and which
	// the reconciler is handed rather than told.
	mesh.Name = "mesh0"
	t.Cleanup(mesh.Close)

	node, err := newClient(cfg, privateKey, reg, mesh, host, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(node.Close)
	// A session counts as live only when the set says so, and standing up two
	// real SAs measures something else.
	node.sessions.active = func(*ike.Session) bool { return true }

	routes, err := kernel.New(*cfg.ReconcilerTable(), standInRuntime(node), mesh.Routes)
	if err != nil {
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
	node.SetReconciler(ReconcilerOf(routes))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = routes.Run(ctx)
	}()
	stop := sync.OnceFunc(func() { cancel(); <-done })
	t.Cleanup(stop)
	return &daemon{node: node, routes: routes, host: host, uplink: host.uplink, stop: stop}, nil
}

// standInRuntime is node's KernelRuntime with no live sends, since a session
// these tests adopt stands in for one and carries no mux to read its
// destination from
func standInRuntime(node *Client) kernel.Runtime {
	rt := node.KernelRuntime()
	rt.Sends = func() []kernel.Send { return nil }
	return rt
}

// announce puts a prefix in the mesh's forwarding table, which is where the
// reconciler reads what to install from, and wakes the reconcile loop.
func (d *daemon) announce(prefix netip.Prefix) {
	d.node.Mesh.Routes.Set(netip.Prefix{}, prefix, &netstack.Peer{ID: "peer"})
}

// live adopts one session that has proved its peer is there, the one thing
// that opens the capture gate.
func (d *daemon) live(t *testing.T) {
	t.Helper()
	if _, adopted := d.node.sessions.adoptPreferred("example/gateway:1@0", &ike.Session{}, true, nil); !adopted {
		t.Fatal("the session was not adopted")
	}
	d.announce(ordinaryPrefix)
}

// coverInstalled counts the IPv6 cover members the tun holds unscoped, and
// the ones it holds scoped.
func (k *recordedKernel) coverInstalled() (plain, scoped int) {
	for _, member := range ipv6Cover {
		p, s := k.installed(member)
		if p {
			plain++
		}
		if s {
			scoped++
		}
	}
	return plain, scoped
}

// waitFor polls until the condition holds, because a reconcile pass is a
// goroutine rather than a call. The budget is generous: a failure here is a
// route that never arrives, not one that arrives late.
func waitForKernel(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

// heldBack announces prefix together with a witness the daemon has no reason
// to hold back, waits for the witness to arrive, and then reports whether
// prefix is in the kernel. The witness turns a wait into an assertion: its
// arrival proves a pass ran over a set carrying both, so an absent prefix is
// one the reconciler decided against rather than one that had not reached it
// yet.
func (d *daemon) heldBack(t *testing.T, prefix, witness netip.Prefix) bool {
	t.Helper()
	d.announce(prefix)
	d.announce(witness)
	waitForKernel(t, "a pass over an announcement carrying both has run", func() bool {
		plain, scoped := d.host.installed(witness)
		return plain || scoped
	})
	plain, scoped := d.host.installed(prefix)
	return !plain && !scoped
}

// A configuration that writes cap.exit produces a daemon whose reconciler
// holds an announced default out of the kernel until a session is live and
// then installs it unscoped as the zero-free cover, installs every other route
// holding a zero address as the members it contains, and writes nothing
// outside the tun. Every one of those is a different call site, and each of
// them was removable.
//
// The assertions are about routes and sockets rather than about which
// functions ran, so a rearrangement that keeps the behavior keeps the test.
func TestExitModeInstallsACaptureOnlyOnceASessionIsLive(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))

	// An ordinary prefix installs at once: the gate holds back what would
	// carry this machine's own traffic and nothing else.
	d.announce(ordinaryPrefix)
	waitForKernel(t, "the ordinary prefix reaches the kernel", func() bool {
		plain, _ := d.host.installed(ordinaryPrefix)
		return plain
	})

	// And the address the file announces is assigned to the device the mesh
	// got, which is the only thing cap.route's announcements do to the kernel.
	waitForKernel(t, "the announced address is assigned to the mesh device", func() bool {
		return slices.Contains(d.host.addresses(meshDeviceIndex), announcedAddress)
	})

	// The default the mesh is announcing is not installed, because no session
	// has proved a peer is there. A node coming up beside a stale
	// announcement must not take it.
	if got := d.node.LiveSessions(); got != 0 {
		t.Fatalf("a node with no session counts %d live, so this measures nothing", got)
	}
	if !d.heldBack(t, capturingPrefix, witnessPrefix) {
		t.Fatal("the mesh took this machine's own traffic before a session was live")
	}
	if plain, scoped := d.host.coverInstalled(); plain+scoped != 0 {
		t.Fatal("the cover took this machine's own traffic before a session was live")
	}

	// One live session opens it.
	d.live(t)
	if got := d.node.LiveSessions(); got != 1 {
		t.Fatalf("a node under cap.exit with one live session counts %d", got)
	}
	waitForKernel(t, "the announced default reaches the kernel as its cover", func() bool {
		plain, _ := d.host.coverInstalled()
		return plain == len(ipv6Cover)
	})

	// Unscoped: a route scoped to the tun is reached by nothing that did not
	// name the tun, so this Mac would hold a mesh address and still not use a
	// mesh exit. The default itself stays out of the kernel.
	if _, scoped := d.host.coverInstalled(); scoped != 0 {
		t.Error("cover members were scoped to the tun under cap.exit")
	}
	if plain, scoped := d.host.installed(capturingPrefix); plain || scoped {
		t.Error("the announced default went into the kernel itself rather than as its cover")
	}

	// A capture beside the default that holds :: goes in as the members it
	// contains, which the default's cover already holds, and never whole.
	if !d.heldBack(t, halfCapture, laterWitness) {
		t.Error("the half capture went into the kernel whole rather than as its members")
	}
	if plain, scoped := d.host.coverInstalled(); plain != len(ipv6Cover) || scoped != 0 {
		t.Errorf("beside the half capture the cover is %d members unscoped and %d scoped, want %d and none", plain, scoped, len(ipv6Cover))
	}
	// Nothing of this daemon's is written outside the tun, and the host's own
	// unscoped defaults are untouched, always. Tailscale
	// shipped the opposite as #21395.
	for _, write := range d.host.writes() {
		if write.index != meshDeviceIndex {
			t.Errorf("the daemon wrote %+v, which is not on its own tun", write)
		}
	}
}

// The same file without cap.exit produces a daemon that writes nothing on the
// uplink and scopes its announced default to the tun so that no ordinary
// socket follows it.
func TestConfigurationWithoutTheModeScopesItsCaptureToTheTun(t *testing.T) {
	d := startDaemon(t, false, recordedHost(t))

	d.live(t)
	d.announce(capturingPrefix)
	waitForKernel(t, "the announced default reaches the kernel", func() bool {
		_, scoped := d.host.installed(capturingPrefix)
		return scoped
	})
	if plain, _ := d.host.installed(capturingPrefix); plain {
		t.Error("the announced default is reachable from every socket on this machine")
	}
	for _, write := range d.host.writes() {
		if write.index != meshDeviceIndex {
			t.Errorf("the daemon wrote %+v, which is not on its own tun", write)
		}
	}
}

// A reload adding cap.exit moves the announced default, scoped to the tun
// before it, into its cover with no restart, and a reload removing it moves
// the default back and the cover out.
func TestReloadAddingTheModeMovesTheDefaultIntoTheCoverAndBack(t *testing.T) {
	d := startDaemon(t, false, recordedHost(t))
	d.live(t)
	d.announce(capturingPrefix)
	scopedAlone := func() bool {
		plain, scoped := d.host.installed(capturingPrefix)
		members, scopedMembers := d.host.coverInstalled()
		return scoped && !plain && members+scopedMembers == 0
	}
	waitForKernel(t, "the announced default reaches the kernel scoped to the tun", scopedAlone)

	d.file.write(t, true)
	if err := d.node.ReloadFrom(d.file.path); err != nil {
		t.Fatalf("a reload adding cap.exit was refused: %v", err)
	}
	waitForKernel(t, "the announced default moves into its cover", func() bool {
		plain, scoped := d.host.installed(capturingPrefix)
		members, scopedMembers := d.host.coverInstalled()
		return !plain && !scoped && members == len(ipv6Cover) && scopedMembers == 0
	})

	d.file.write(t, false)
	if err := d.node.ReloadFrom(d.file.path); err != nil {
		t.Fatalf("a reload removing cap.exit was refused: %v", err)
	}
	waitForKernel(t, "the announced default moves back out of its cover", scopedAlone)
	for _, write := range d.host.writes() {
		if write.index != meshDeviceIndex {
			t.Errorf("the daemon wrote %+v, which is not on its own tun", write)
		}
	}
}

// unnamedQuiet is how long the listener behind lo0 hears nothing before a test takes it that no datagram left unnamed
const unnamedQuiet = 200 * time.Millisecond

// A daemon names each underlay datagram's interface from the selection it
// opens over the host's own routes. The recorded host sends the loopback by a
// device the running machine lacks, so the datagram naming it is refused with
// the ENXIO udp_check_pktinfo in bsd/netinet/udp_usrreq.c answers, and the
// listener behind lo0, which a datagram naming no interface reaches, hears
// nothing.
func TestDaemonNamesEachUnderlayDatagramsInterfaceFromTheHostsRoutes(t *testing.T) {
	host := recordedHost(t)
	host.hold(recordedRoute{destination: netip.MustParsePrefix("127.0.0.0/8"), index: otherProgramIndex})
	d := startDaemon(t, false, host)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	at := listener.LocalAddr().(*net.UDPAddr)
	mux, err := d.node.hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mux.Close() })
	if err := mux.SendIKE([]byte("named")); !errors.Is(err, unix.ENXIO) {
		t.Errorf("a datagram to %s, which the host's routes send by interface %d, answered %v, want ENXIO", at, otherProgramIndex, err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(unnamedQuiet)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, _, err := listener.ReadFromUDP(buf); err == nil {
		t.Errorf("the listener behind lo0 read %q, a datagram that named no interface", buf[:n])
	}
	// the rules view reads the route the same selection takes
	if d.node.underlayRoutes == nil {
		t.Fatal("the daemon hands its rules view no selection")
	}
	if prefix, _, ok := d.node.underlayRoutes.Route(netip.MustParseAddr("127.0.0.1")); !ok || prefix != netip.MustParsePrefix("127.0.0.0/8") {
		t.Errorf("the rules view reads 127.0.0.1 by %s, %v, want 127.0.0.0/8", prefix, ok)
	}
}

// A cover goes in whatever the host's own routes hold: a family the host has
// no default of its own in gets its cover as the other family does, and a
// route holding 0.0.0.0 goes in as the members it contains.
func TestCoverGoesInForAFamilyTheHostHasNoDefaultIn(t *testing.T) {
	host := recordedHost(t)
	// The host reaches IPv6 nowhere.
	host.v6 = kernel.RouteAnswer{}
	d := startDaemon(t, true, host)

	d.live(t)
	// 1.0.0.0/8 to 64.0.0.0/2
	v4capture := netip.MustParsePrefix("0.0.0.0/1")
	d.announce(v4capture)
	waitForKernel(t, "the IPv4 capture reaches the kernel as its members", func() bool {
		plain, _ := d.host.installed(netip.MustParsePrefix("64.0.0.0/2"))
		return plain
	})
	if plain, scoped := d.host.installed(v4capture); plain || scoped {
		t.Errorf("%s went into the kernel whole", v4capture)
	}

	d.announce(capturingPrefix)
	waitForKernel(t, "the IPv6 default reaches the kernel as its cover", func() bool {
		plain, _ := d.host.coverInstalled()
		return plain == len(ipv6Cover)
	})
	if plain, scoped := d.host.installed(capturingPrefix); plain || scoped {
		t.Errorf("%s went into the kernel whole", capturingPrefix)
	}
}

// A prefix covering a peer's own endpoint is scoped to the tun even under
// cap.exit: unscoped and longer than the host's own route to the peer, it
// would leave the datagrams naming the selection's interface no route there.
// It is scoped for that reason alone: it does not count as a default, and the
// capture gate does not cover it.
func TestPrefixCoveringAPeerEndpointIsScopedInTheMode(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))
	d.live(t)

	covering := netip.MustParsePrefix("198.51.100.0/24")
	if !covering.Contains(peerEndpoint) {
		t.Fatalf("%s does not hold the peer endpoint %s, so this measures nothing", covering, peerEndpoint)
	}
	d.announce(covering)
	waitForKernel(t, "the prefix covering the peer endpoint reaches the kernel", func() bool {
		plain, scoped := d.host.installed(covering)
		return plain || scoped
	})
	plain, scoped := d.host.installed(covering)
	if plain || !scoped {
		t.Error("a prefix holding this node's own peer endpoint went in unscoped")
	}
}

// Shutdown takes down what this node opened: the reconciler withdraws the
// cover, and closing the node closes the selection's route watcher. A route
// socket or a watcher left open is one per start, for the life of the process.
func TestShutdownLeavesTheMachineAsItFoundIt(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))
	d.live(t)
	d.announce(capturingPrefix)
	waitForKernel(t, "the cover reaches the kernel", func() bool {
		plain, _ := d.host.coverInstalled()
		return plain == len(ipv6Cover)
	})

	d.stop()
	if plain, scoped := d.host.coverInstalled(); plain+scoped != 0 {
		t.Fatal("the reconciler left the cover carrying this machine's traffic in the kernel")
	}
	d.node.Close()
	if sockets, watchers := d.host.stillOpen(); sockets != 0 || watchers != 0 {
		t.Errorf("shutdown left %d route sockets and %d route watchers open", sockets, watchers)
	}
	for _, write := range d.host.writes() {
		if write.index != meshDeviceIndex {
			t.Errorf("the daemon wrote %+v, which is not on its own tun", write)
		}
	}
}

// a start that fails after the transport opened its selection leaves the machine as it found it
// another socket holds the port, which is how a second node on one port fails once the first half of its start has run
// the selection's route watcher is closed, and nothing was written
func TestFailedStartLeavesTheMachineAsItFoundIt(t *testing.T) {
	host := recordedHost(t)

	// the port is chosen by binding zero and giving it back, so another process can take it before this one holds it again
	var cfg *config.Config
	var held net.PacketConn
	retryPort(t, "hold", func() (err error) {
		cfg = newDaemonFile(t).load(t, true)
		held, err = net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", cfg.Link.Port))
		return err
	})
	t.Cleanup(func() { _ = held.Close() })

	_, err := tryDaemon(t, cfg, host)
	if err == nil {
		t.Fatal("a node started on a port another socket holds, so this measures nothing")
	}
	// the hub refused the port after the selection opened, which is the state this leaves behind
	if writes := host.writes(); len(writes) != 0 {
		t.Errorf("the failed start wrote %+v", writes)
	}
	if sockets, watchers := host.stillOpen(); sockets != 0 || watchers != 0 {
		t.Errorf("the failed start left %d route sockets and %d route watchers open", sockets, watchers)
	}
}

// a start whose first read of the host's links fails, after the selection and
// the shared watcher opened, leaves the machine as it found it: the watcher is
// closed once, and nothing was written
func TestFailedNetworkReadLeavesTheMachineAsItFoundIt(t *testing.T) {
	host := recordedHost(t)
	host.linksErr = errors.New("the links cannot be read")
	_, err := tryDaemon(t, newDaemonFile(t).load(t, false), host)
	if !errors.Is(err, host.linksErr) {
		t.Fatalf("a node whose links cannot be read started with %v, want the read's error", err)
	}
	if writes := host.writes(); len(writes) != 0 {
		t.Errorf("the failed start wrote %+v", writes)
	}
	if sockets, watchers := host.stillOpen(); sockets != 0 || watchers != 0 {
		t.Errorf("the failed start left %d route sockets and %d route watchers open", sockets, watchers)
	}
	if opened, closes := host.everyInterface(); opened != 1 || closes != 1 {
		t.Errorf("the failed start opened %d watchers of every interface and closed them %d times, want one closed once", opened, closes)
	}
}

// a start whose first dump of the host's table fails, after the shared watcher
// opened and before the selection did, leaves the machine as it found it: the
// watcher is closed once, and nothing was written
func TestFailedTableDumpLeavesTheMachineAsItFoundIt(t *testing.T) {
	host := recordedHost(t)
	host.dumpErr = errors.New("the table cannot be dumped")
	_, err := tryDaemon(t, newDaemonFile(t).load(t, false), host)
	if !errors.Is(err, host.dumpErr) {
		t.Fatalf("a node whose table cannot be dumped started with %v, want the dump's error", err)
	}
	if writes := host.writes(); len(writes) != 0 {
		t.Errorf("the failed start wrote %+v", writes)
	}
	if sockets, watchers := host.stillOpen(); sockets != 0 || watchers != 0 {
		t.Errorf("the failed start left %d route sockets and %d route watchers open", sockets, watchers)
	}
	if opened, closes := host.everyInterface(); opened != 1 || closes != 1 {
		t.Errorf("the failed start opened %d watchers of every interface and closed them %d times, want one closed once", opened, closes)
	}
}

// the underlay's selection and the network watch follow one watcher of every
// interface, which the node's constructor opens beside the reconciler's own and
// its Close closes once
// a wake reaches both, and once either has closed its reader a wake still
// reaches the other and the watcher stays open
func TestOneWatcherServesTheSelectionAndTheNetworkWatch(t *testing.T) {
	for _, closing := range []string{"the network watch", "the selection"} {
		t.Run(closing+" closes first", func(t *testing.T) {
			host := recordedHost(t)
			d := startDaemon(t, false, host)
			waitForKernel(t, "the reconciler opens its own watcher", func() bool { return host.watchCalls() >= 2 })
			if opened, _ := host.everyInterface(); opened != 1 || host.watchCalls() != 2 {
				t.Fatalf("the node opened %d watchers, %d of them of every interface, want the reconciler's and one for the selection and the network watch",
					host.watchCalls(), opened)
			}
			selects := func(destination netip.Prefix, address netip.Addr) func() bool {
				return func() bool {
					got, _, ok := d.node.underlayRoutes.Route(address)
					return ok && got == destination
				}
			}
			reads := func(address netip.Addr) func() bool {
				return func() bool { return slices.Contains(d.node.networkState().IPv4.Addresses, address) }
			}

			first, firstTarget, firstAddress := netip.MustParsePrefix("203.0.113.0/25"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("192.0.2.77")
			host.hold(recordedRoute{destination: first, index: d.uplink})
			if err := host.Assign(true, "uplink0", netip.PrefixFrom(firstAddress, 24)); err != nil {
				t.Fatal(err)
			}
			host.fire()
			waitForKernel(t, "the selection reads the route the wake reported", selects(first, firstTarget))
			waitForKernel(t, "the network watch reads the address the wake reported", reads(firstAddress))

			second, secondTarget, secondAddress := netip.MustParsePrefix("203.0.113.128/25"), netip.MustParseAddr("203.0.113.130"), netip.MustParseAddr("192.0.2.78")
			host.hold(recordedRoute{destination: second, index: d.uplink})
			if err := host.Assign(true, "uplink0", netip.PrefixFrom(secondAddress, 24)); err != nil {
				t.Fatal(err)
			}
			if closing == "the network watch" {
				if err := d.node.network.Close(); err != nil {
					t.Fatal(err)
				}
				host.fire()
				waitForKernel(t, "the selection reads a route reported after the network watch closed", selects(second, secondTarget))
			} else {
				selection, ok := d.node.underlayRoutes.(interface{ Close() error })
				if !ok {
					t.Fatalf("the selection %T has no Close", d.node.underlayRoutes)
				}
				if err := selection.Close(); err != nil {
					t.Fatal(err)
				}
				host.fire()
				waitForKernel(t, "the network watch reads an address reported after the selection closed", reads(secondAddress))
			}
			if _, closes := host.everyInterface(); closes != 0 {
				t.Errorf("closing %s closed the watcher the other follows %d times", closing, closes)
			}

			d.stop()
			d.node.Close()
			if opened, closes := host.everyInterface(); opened != 1 || closes != 1 {
				t.Errorf("the node opened %d watchers of every interface and closed them %d times, want one closed once", opened, closes)
			}
		})
	}
}

// debug netmon carries the links of the recorded host as the network watch
// reads them, the uplink with its addresses of each family and the mesh's
// device left out
func TestNetmonCarriesTheHostsLinks(t *testing.T) {
	host := recordedHost(t)
	host.assigned[host.uplink] = []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("2001:db8:5::10/64")}
	host.assigned[meshDeviceIndex] = []netip.Prefix{announcedAddress4}
	d := startDaemon(t, false, host)
	info := d.node.DebugNetmon()
	want := map[string][]control.NetmonLink{
		string(kernel.FamilyIPv4): {{Name: "uplink0", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}}},
		string(kernel.FamilyIPv6): {{Name: "uplink0", Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:5::10/64")}}},
	}
	if !info.Watching || len(info.Families) != len(want) {
		t.Fatalf("debug netmon reads %+v, want both families watched", info)
	}
	for _, family := range info.Families {
		if !slices.EqualFunc(family.Links, want[family.Family], func(a, b control.NetmonLink) bool {
			return a.Name == b.Name && slices.Equal(a.Prefixes, b.Prefixes) && slices.Equal(a.Peers, b.Peers)
		}) {
			t.Errorf("debug netmon carries the %s links %+v, want %+v", family.Family, family.Links, want[family.Family])
		}
	}
}

// daemonFile is one node's configuration file, with the key and the trust
// document it names
type daemonFile struct {
	path, keyPath, trustPath string
	port                     uint16
}

// newDaemonFile writes the key and the trust document of one node, on a port
// of this run's own, because the hub binds it for real and two of these tests
// in flight at once would otherwise collide.
func newDaemonFile(t *testing.T) *daemonFile {
	t.Helper()
	dir := t.TempDir()
	f := &daemonFile{path: filepath.Join(dir, "config.yaml"), keyPath: filepath.Join(dir, "key.pem"),
		trustPath: filepath.Join(dir, "registry.json"), port: freeUDPPort(t)}
	writeDaemonIdentity(t, f.keyPath, f.trustPath, f.port)
	return f
}

// write writes the file, with cap.exit in mode 2 where exit is true
func (f *daemonFile) write(t *testing.T, exit bool) {
	t.Helper()
	mode := ""
	if exit {
		mode = "  exit: {}\n"
	}
	body := fmt.Sprintf(`node: example/laptop
overlay:
  - "2001:db8:1::/48"
  - "203.0.113.0/24"
auth:
  key: %s
  trust: %s
link:
  port: %d
  endpoints:
    - serial: "0"
      family: ip4
dial:
  to:
    - example/gateway:1
cap:
%s  route:
    announce:
      - %q
      - %q
  table:
    assign_announced: true
    reconcile: 50ms
    capture_grace: 1s
`, f.keyPath, f.trustPath, f.port, mode, announcedAddress.String(), announcedAddress4.String())
	if err := os.WriteFile(f.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// load writes the file and reads it back through the loader the daemon uses,
// so the capability defaults and the refusals are the ones a deployment gets.
func (f *daemonFile) load(t *testing.T, exit bool) *config.Config {
	t.Helper()
	f.write(t, exit)
	cfg, err := config.Load(f.path)
	if err != nil {
		t.Fatalf("the configuration this test writes does not load: %v", err)
	}
	if cfg.Cap.Table == nil {
		t.Fatal("the configuration carries no cap.table, so there is no reconciler to build")
	}
	return cfg
}

// writeDaemonIdentity writes the key and the trust document the file names.
// The peer's endpoint carries an address, because the transport has to keep
// reaching it past whatever the mesh announces and the reconciler reads that
// set once a pass. Nothing dials it: these tests never call Run, so no dialer
// is ever started and nothing here reaches the network.
func writeDaemonIdentity(t *testing.T, keyPath, trustPath string, port uint16) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := peerEndpoint.String()
	reg := registry.Registry{{
		Organization: "example",
		PublicKey:    string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Nodes: []registry.Node{
			{CommonName: "laptop", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: port}}},
			{CommonName: "gateway", Endpoints: []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Address: &endpoint, Port: port}}},
		},
	}}
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// daemonIdentity reads back the key the file names, the way client.New does.
func daemonIdentity(t *testing.T, cfg *config.Config) ed25519.PrivateKey {
	t.Helper()
	privateKey, err := registry.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}
