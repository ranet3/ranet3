// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// The first two tests here run a darwin node on the recorded machine of daemon_darwin_test.go and need no privilege
// the last two run one on a real utun, as root with RANET3_DARWIN_NETTEST=1, and name documentation prefixes alone

const (
	// quietFor is how long a node starting down is watched for a write to its mesh device, ten of its 50 millisecond reconcile intervals
	quietFor = 500 * time.Millisecond
	// utunBudget bounds every wait on the real kernel
	utunBudget = 10 * time.Second
	// bareBudget bounds the wait for a down to leave the recorded mesh device bare, the budget waitForKernel gives every other wait there
	bareBudget = 5 * time.Second
	// barePoll is how often that wait reads the recorded machine
	barePoll = 5 * time.Millisecond
)

var (
	// utunAddress is the host address the node on a real utun announces and carries on it
	utunAddress = netip.MustParsePrefix("203.0.113.201/32")
	// utunRoute is a prefix the mesh of that node holds unreachable, which its reconciler installs out of the utun as a reject route
	// the kernel refuses a packet for it rather than handing the packet to the mesh, which has no peer behind it
	utunRoute = netip.MustParsePrefix("203.0.113.128/26")
)

// startDownable is startDaemon with a state directory and a node that dials nobody, so up starts no dialer and nothing reaches the network
// the reconciler's stop and table are handed to the node before the reconciler runs, as the daemon hands them over
func startDownable(t *testing.T, host *recordedKernel, stateDir string) *daemon {
	t.Helper()
	redirectUnderlayState(t)
	var d *daemon
	retryPort(t, "bind", func() (err error) {
		d, err = tryDownable(t, host, stateDir)
		return err
	})
	return d
}

func tryDownable(t *testing.T, host *recordedKernel, stateDir string) (*daemon, error) {
	t.Helper()
	cfg := loadDaemonConfig(t, true)
	cfg.Dial = config.Dial{}
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		t.Fatal(err)
	}
	mesh := netstack.NewRoutesOnly()
	mesh.Name = "mesh0"
	t.Cleanup(mesh.Close)
	node, err := newClient(cfg, daemonIdentity(t, cfg), reg, mesh, host, events.New())
	if err != nil {
		return nil, err
	}
	t.Cleanup(node.Close)
	if err := node.SetStateDir(stateDir); err != nil {
		t.Fatal(err)
	}
	routes, err := kernel.New(*cfg.Cap.Table, node.KernelRuntime(), mesh.Routes)
	if err != nil {
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
	node.SetReconcilerEnable(routes.SetEnabled)
	node.SetReconcilerTable(routes.SetTable)
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

// dressed reports whether the mesh device carries the announced address and a route to the ordinary prefix
func (d *daemon) dressed() bool {
	plain, _ := d.host.installed(ordinaryPrefix)
	return plain && slices.Contains(d.host.addresses(meshDeviceIndex), announcedAddress)
}

// waitBare waits for the mesh device to hold no route and no address of this node
// a failure names what the device still holds, since that message is all a run on another machine sends back
func (d *daemon) waitBare(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(bareBudget)
	for {
		routes, addresses := d.host.meshHeld(), d.host.addresses(meshDeviceIndex)
		if len(routes) == 0 && len(addresses) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for down to leave the mesh device bare, and it still holds the routes %+v and the addresses %v", routes, addresses)
		}
		time.Sleep(barePoll)
	}
}

// meshHeld is every route the table holds out of the mesh device
func (k *recordedKernel) meshHeld() []recordedRoute {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []recordedRoute
	for held := range k.held {
		if held.index == k.mesh {
			out = append(out, held)
		}
	}
	return out
}

// down on a darwin node takes its routes and its address off the mesh device and leaves the fallback of the uplink in place
// the fallback serves the transport's socket, which a down keeps open, and up puts the routes and the address back
func TestDownTakesTheMeshDeviceBareAndKeepsTheUnderlayFallback(t *testing.T) {
	d := startDownable(t, recordedHost(t), t.TempDir())
	holdSessions(d.node).adopt(t, d.node, "example/gateway/1@0")
	d.announce(ordinaryPrefix)
	waitForKernel(t, "the ordinary prefix and the announced address are on the mesh device", d.dressed)
	fallback := d.host.scopedDefaults()
	if len(fallback) == 0 {
		t.Fatal("the underlay wrote no fallback, so this measures nothing")
	}

	if _, err := d.node.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.waitBare(t)
	if got := d.host.scopedDefaults(); !slices.Equal(got, fallback) {
		t.Errorf("down left the fallback of the uplink as %+v, want %+v kept for the socket it serves", got, fallback)
	}

	if _, err := d.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForKernel(t, "the ordinary prefix and the announced address are back on the mesh device", d.dressed)
}

// a darwin node whose flag is there when it starts writes nothing to its mesh device, its reconciler stopped before its first pass
// up then installs what the mesh holds, so the quiet before it came from the stop rather than from a pass yet to run
func TestDarwinNodeStartingDownWritesNothingToItsMeshDevice(t *testing.T) {
	dir := t.TempDir()
	if err := writeDownFlag(dir, flaggedAt); err != nil {
		t.Fatal(err)
	}
	d := startDownable(t, recordedHost(t), dir)
	waitForKernel(t, "the reconciler has made its first pass", func() bool { return !d.routes.Stats().At.IsZero() })
	d.announce(ordinaryPrefix)
	time.Sleep(quietFor)
	for _, write := range d.host.writes() {
		if write.index == meshDeviceIndex {
			t.Errorf("the node starting down wrote %+v to its mesh device", write)
		}
	}
	if got := d.host.addresses(meshDeviceIndex); len(got) != 0 {
		t.Errorf("the node starting down put %v on its mesh device", got)
	}

	if _, err := d.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForKernel(t, "up has put the ordinary prefix and the announced address on the mesh device", d.dressed)
}

// requireRealUTUN skips unless the run asked for the real kernel and runs as root, which a utun and its routes need
func requireRealUTUN(t *testing.T) {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to put a node on a real utun")
	}
	if os.Geteuid() != 0 {
		t.Skip("RANET3_DARWIN_NETTEST=1 but this process is not root, and a utun and its routes need root")
	}
}

// utunNode is one node on a real utun with its reconciler, built as the daemon builds one, dialing nobody and dialed by nobody
type utunNode struct {
	node   *Client
	routes *kernel.Reconciler
	// stop ends the reconciler and then the node, the order the daemon's shutdown takes, and waits for both
	stop func()
}

// startUTUN runs a node announcing utunAddress on the next free utun, with the state directory stateDir
// its mesh holds utunRoute before its reconciler runs, so the first pass that installs anything installs that too
// its file turns link.listen on, since the loader refuses a node that neither dials nor answers
func startUTUN(t *testing.T, stateDir string) *utunNode {
	t.Helper()
	redirectUnderlayState(t)
	dir := t.TempDir()
	keyPath, trustPath, path := filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json"), filepath.Join(dir, "config.yaml")
	port := freeUDPPort(t)
	body := fmt.Sprintf(`node:
  org: example
  name: laptop
auth:
  key: %s
  trust: %s
link:
  port: %d
  listen: true
  endpoints:
    - serial: "0"
      family: ip4
cap:
  route:
    announce:
      - %q
  table:
    assign_announced: true
    reconcile: 50ms
`, keyPath, trustPath, port, utunAddress.String())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDaemonIdentity(t, keyPath, trustPath, port)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the configuration this test writes does not load: %v", err)
	}
	node, err := New(cfg, events.New())
	if err != nil {
		t.Fatalf("start a node on a utun: %v", err)
	}
	if err := node.SetStateDir(stateDir); err != nil {
		node.Close()
		t.Fatal(err)
	}
	node.Mesh.Routes.Set(netip.Prefix{}, utunRoute, netstack.Unreachable)
	routes, err := kernel.New(*cfg.Cap.Table, node.KernelRuntime(), node.Mesh.Routes)
	if err != nil {
		node.Close()
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
	node.SetReconcilerEnable(routes.SetEnabled)
	node.SetReconcilerTable(routes.SetTable)
	routesCtx, stopRoutes := context.WithCancel(context.Background())
	meshCtx, stopMesh := context.WithCancel(context.Background())
	withdrawn, left := make(chan error, 1), make(chan error, 1)
	go func() { withdrawn <- routes.Run(routesCtx) }()
	go func() { left <- node.Run(meshCtx) }()
	u := &utunNode{node: node, routes: routes}
	u.stop = sync.OnceFunc(func() {
		stopRoutes()
		select {
		case err := <-withdrawn:
			if err != nil {
				t.Errorf("the reconciler withdrew with %v", err)
			}
		case <-time.After(utunBudget):
			t.Error("the reconciler did not stop")
		}
		stopMesh()
		select {
		case err := <-left:
			if err != nil && !isCanceled(err) {
				t.Errorf("the node stopped with %v", err)
			}
		case <-time.After(utunBudget):
			t.Error("the node did not stop")
		}
	})
	t.Cleanup(u.stop)
	return u
}

// onUTUN reports whether the utun of u carries utunAddress and whether the kernel holds a route to utunRoute out of it
func (u *utunNode) onUTUN(t *testing.T) (address, routed bool) {
	t.Helper()
	link, err := net.InterfaceByName(u.node.Mesh.Name)
	if err != nil {
		t.Fatalf("look up %s: %v", u.node.Mesh.Name, err)
	}
	addresses, err := link.Addrs()
	if err != nil {
		t.Fatalf("list the addresses of %s: %v", link.Name, err)
	}
	for _, carried := range addresses {
		if network, ok := carried.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(network.IP); ok && ip.Unmap() == utunAddress.Addr() {
				address = true
			}
		}
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatalf("dump the routing table: %v", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatalf("parse the routing table: %v", err)
	}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Index != link.Index {
			continue
		}
		if entry, ok := decodeRecorded(rm); ok && entry.destination == utunRoute {
			routed = true
		}
	}
	return address, routed
}

// down on a real utun takes the address and the route off it and keeps the utun, and up puts both back
func TestDownTakesItsAddressAndRouteOffARealUTUN(t *testing.T) {
	requireRealUTUN(t)
	u := startUTUN(t, t.TempDir())
	waitFor(t, utunBudget, "the address and the route on the utun", func() bool {
		address, routed := u.onUTUN(t)
		return address && routed
	})
	if _, err := u.node.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, utunBudget, "the address and the route off the utun", func() bool {
		address, routed := u.onUTUN(t)
		return !address && !routed
	})
	if _, err := net.InterfaceByName(u.node.Mesh.Name); err != nil {
		t.Errorf("down took the utun away: %v", err)
	}
	if _, err := u.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, utunBudget, "the address and the route back on the utun", func() bool {
		address, routed := u.onUTUN(t)
		return address && routed
	})
}

// a node starting down on a real utun leaves it bare through its first pass and after, and up then dresses it
func TestNodeStartingDownLeavesARealUTUNBare(t *testing.T) {
	requireRealUTUN(t)
	dir := t.TempDir()
	if err := writeDownFlag(dir, flaggedAt); err != nil {
		t.Fatal(err)
	}
	u := startUTUN(t, dir)
	waitFor(t, utunBudget, "the first pass of the reconciler", func() bool { return !u.routes.Stats().At.IsZero() })
	time.Sleep(quietFor)
	if address, routed := u.onUTUN(t); address || routed {
		t.Errorf("the node starting down put its address (%v) or its route (%v) on the utun", address, routed)
	}
	if _, err := u.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, utunBudget, "the address and the route on the utun after up", func() bool {
		address, routed := u.onUTUN(t)
		return address && routed
	})
}
