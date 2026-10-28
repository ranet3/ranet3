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
	// halfCapture takes the machine too and holds ::, so under
	// link.underlay.bind it goes in as the members it contains, the first
	// seven of ipv6Cover
	halfCapture    = netip.MustParsePrefix("::/1")
	ordinaryPrefix = netip.MustParsePrefix("2001:db8:2::/64")
	// ipv6Cover holds the members link.underlay.bind installs capturingPrefix as
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

// startDaemon builds one node and its reconciler, retrying the port
func startDaemon(t *testing.T, bind bool, host *recordedKernel) *daemon {
	t.Helper()
	var d *daemon
	retryPort(t, "bind", func() (err error) {
		d, err = tryDaemon(t, loadDaemonConfig(t, bind), host)
		return err
	})
	return d
}

// tryDaemon builds the node a loaded configuration describes around a mesh
// with no TUN, and builds the route reconciler out of what the node says about
// itself. The last step is the one under test: main does exactly this and
// nothing more.
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

	routes, err := kernel.New(*cfg.Cap.Table, node.KernelRuntime(), mesh.Routes)
	if err != nil {
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
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

// A configuration that sets link.underlay.bind produces a daemon whose
// reconciler holds an announced default out of the kernel until a session is
// live and then installs it unscoped as the zero-free cover, installs every
// other route holding a zero address as the members it contains, and writes
// nothing outside the tun. Every one of those is a different call site, and
// each of them was removable.
//
// The assertions are about routes and sockets rather than about which
// functions ran, so a rearrangement that keeps the behavior keeps the test.
func TestBindConfigurationInstallsACaptureOnlyOnceASessionIsLive(t *testing.T) {
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
		t.Fatalf("a node under link.underlay.bind with one live session counts %d", got)
	}
	waitForKernel(t, "the announced default reaches the kernel as its cover", func() bool {
		plain, _ := d.host.coverInstalled()
		return plain == len(ipv6Cover)
	})

	// Unscoped: a route scoped to the tun is reached by nothing that did not
	// name the tun, so this Mac would hold a mesh address and still not use a
	// mesh exit. The default itself stays out of the kernel.
	if _, scoped := d.host.coverInstalled(); scoped != 0 {
		t.Error("cover members were scoped to the tun under link.underlay.bind")
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

// The same file without link.underlay.bind produces a daemon that writes
// nothing on the uplink and scopes its announced default to the tun so that
// no ordinary socket follows it.
func TestConfigurationWithoutBindScopesItsCaptureToTheTun(t *testing.T) {
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
// link.underlay.bind: unscoped and longer than the host's own route to the
// peer, it would leave the datagrams naming the selection's interface no route
// there. It is scoped for that reason alone: it does not count as a default,
// and the capture gate does not cover it.
func TestPrefixCoveringAPeerEndpointIsScopedEvenUnderBind(t *testing.T) {
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
		cfg = loadDaemonConfig(t, true)
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

// loadDaemonConfig writes one node's file and reads it back through the loader
// the daemon uses, so the capability defaults and the refusals are the ones a
// deployment gets.
func loadDaemonConfig(t *testing.T, bind bool) *config.Config {
	t.Helper()
	dir := t.TempDir()
	keyPath, trustPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json")
	// A port of this run's own, because the hub below binds it for real and
	// two of these tests in flight at once would otherwise collide.
	port := freeUDPPort(t)
	underlay := ""
	if bind {
		underlay = "  underlay:\n    bind: true\n"
	}
	body := fmt.Sprintf(`node: example/laptop
auth:
  key: %s
  trust: %s
link:
  port: %d
  endpoints:
    - serial: "0"
      family: ip4
%sdial:
  to:
    - example/gateway:1
cap:
  route:
    announce:
      - %q
  table:
    assign_announced: true
    reconcile: 50ms
    capture_grace: 1s
`, keyPath, trustPath, port, underlay, announcedAddress.String())
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDaemonIdentity(t, keyPath, trustPath, port)
	cfg, err := config.Load(path)
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
