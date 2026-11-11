// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"context"
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

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// The first two tests here run a darwin node on the recorded machine of daemon_darwin_test.go and need no privilege
// the last three run one on a real utun, as root with RANET3_DARWIN_NETTEST=1, and name documentation prefixes alone

const (
	// quietFor is how long a node starting down is watched for a write to its mesh device, ten of its 50 millisecond reconcile intervals
	quietFor = 500 * time.Millisecond
	// utunBudget bounds every wait on the real kernel
	utunBudget = 10 * time.Second
	// utunPoll is how often a wait on the real kernel reads the utun again
	utunPoll = 10 * time.Millisecond
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
	var d *daemon
	retryPort(t, "bind", func() (err error) {
		d, err = tryDownable(t, host, stateDir)
		return err
	})
	return d
}

func tryDownable(t *testing.T, host *recordedKernel, stateDir string) (*daemon, error) {
	t.Helper()
	cfg := newDaemonFile(t).load(t, true)
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
	routes, err := kernel.New(*cfg.ReconcilerTable(), standInRuntime(node), mesh.Routes)
	if err != nil {
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
	node.SetReconciler(Reconciler{Enable: routes.SetEnabled, Table: routes.SetTable})
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

// down on a darwin node takes its routes, the cover among them, and its address off the mesh device, and up puts them back
func TestDownTakesTheMeshDeviceBareWithTheCover(t *testing.T) {
	d := startDownable(t, recordedHost(t), t.TempDir())
	// the session counts as live, which a capture waits for
	d.node.sessions.mu.Lock()
	d.node.sessions.active = func(*ike.Session) bool { return true }
	d.node.sessions.mu.Unlock()
	holdSessions(d.node).adopt(t, d.node, "example/gateway:1@0")
	d.announce(ordinaryPrefix)
	d.announce(capturingPrefix)
	waitForKernel(t, "the ordinary prefix and the announced address are on the mesh device", d.dressed)
	coverWhole := func() bool {
		plain, _ := d.host.coverInstalled()
		return plain == len(ipv6Cover)
	}
	waitForKernel(t, "the announced default is on the mesh device as its cover", coverWhole)

	if _, err := d.node.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.waitBare(t)

	if _, err := d.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForKernel(t, "the ordinary prefix and the announced address are back on the mesh device", d.dressed)
	// down closed the session, and the capture waits for a live one again
	holdSessions(d.node).adopt(t, d.node, "example/gateway:1@0")
	d.announce(capturingPrefix)
	waitForKernel(t, "the cover is back on the mesh device", coverWhole)
	for _, write := range d.host.strayWrites() {
		t.Errorf("the node wrote %+v, which is neither on its own tun nor an overlay hold", write)
	}
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
	dir := t.TempDir()
	keyPath, trustPath, path := filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json"), filepath.Join(dir, "config.yaml")
	port := freeUDPPort(t)
	body := fmt.Sprintf(`node: example/laptop
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
	node.SetReconciler(Reconciler{Enable: routes.SetEnabled, Table: routes.SetTable})
	routesCtx, stopRoutes := context.WithCancel(context.Background())
	meshCtx, stopMesh := context.WithCancel(context.Background())
	withdrawn, left := make(chan error, 1), make(chan struct{})
	go func() { withdrawn <- routes.Run(routesCtx) }()
	go func() { node.Run(meshCtx); close(left) }()
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
		case <-left:
		case <-time.After(utunBudget):
			t.Error("the node did not stop")
		}
	})
	t.Cleanup(u.stop)
	return u
}

// grewWhileListed reports whether a listing of the routing socket failed because its list grew while the kernel filled it
// sysctl_iflist in bsd/net/rtsock.c answers ENOBUFS where the list outgrew the eighth it added to its first pass's size,
// and sysctl answers ENOMEM where the list outgrew the caller's buffer, which Go and x/net try three times before they answer it
func grewWhileListed(err error) bool {
	return errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ENOMEM)
}

// onUTUN reports whether the utun of u carries utunAddress and whether the kernel holds a route to utunRoute out of it
// it answers the error of a listing whose list grew meanwhile, as the reconciler's writes make it, and fails the test on any other
func (u *utunNode) onUTUN(t *testing.T) (address, routed bool, err error) {
	t.Helper()
	link, err := net.InterfaceByName(u.node.Mesh.Name)
	if grewWhileListed(err) {
		return false, false, err
	}
	if err != nil {
		t.Fatalf("look up %s: %v", u.node.Mesh.Name, err)
	}
	addresses, err := link.Addrs()
	if grewWhileListed(err) {
		return false, false, err
	}
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
	if grewWhileListed(err) {
		return false, false, err
	}
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
	return address, routed, nil
}

// wholeUTUN reads the utun of u again past each listing whose list grew, until one reading meets none or deadline passes,
// and answers how many listings grew in this call with either the whole reading and a nil error,
// or, where a listing grew past deadline, no reading and that listing's error
// the lists are the host's, which any process may write meanwhile, and not the utun's alone
func (u *utunNode) wholeUTUN(t *testing.T, deadline time.Time) (address, routed bool, grown int, err error) {
	t.Helper()
	for {
		address, routed, err = u.onUTUN(t)
		if err == nil {
			return address, routed, grown, nil
		}
		grown++
		if time.Now().After(deadline) {
			return false, false, grown, err
		}
		time.Sleep(utunPoll)
	}
}

// waitOnUTUN waits until a whole reading of the utun of u satisfies want
// its timeout names how many listings grew over the wait, the last whole reading where the wait had one,
// and the last grown listing's error where the wait ended on one
func (u *utunNode) waitOnUTUN(t *testing.T, what string, want func(address, routed bool) bool) {
	t.Helper()
	deadline := time.Now().Add(utunBudget)
	grown, last := 0, "no whole reading"
	for {
		address, routed, more, err := u.wholeUTUN(t, deadline)
		grown += more
		if err == nil {
			if want(address, routed) {
				return
			}
			last = fmt.Sprintf("the last whole reading finding the address %v and the route %v", address, routed)
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("timed out waiting for %s, %s, past %d listings the host's lists grew under, the last answering %v", what, last, grown, err)
			}
			t.Fatalf("timed out waiting for %s, %s, past %d listings the host's lists grew under", what, last, grown)
		}
		time.Sleep(utunPoll)
	}
}

// down on a real utun takes the address and the route off it and keeps the utun, and up puts both back
func TestDownTakesItsAddressAndRouteOffARealUTUN(t *testing.T) {
	requireRealUTUN(t)
	u := startUTUN(t, t.TempDir())
	u.waitOnUTUN(t, "the address and the route on the utun", func(address, routed bool) bool { return address && routed })
	if _, err := u.node.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.waitOnUTUN(t, "the address and the route off the utun", func(address, routed bool) bool { return !address && !routed })
	if _, err := net.InterfaceByName(u.node.Mesh.Name); err != nil {
		t.Errorf("down took the utun away: %v", err)
	}
	if _, err := u.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.waitOnUTUN(t, "the address and the route back on the utun", func(address, routed bool) bool { return address && routed })
}

// the mesh of a node New starts on a real utun drops a read from a neighbor toward another node's prefix, counted unowned_source,
// since darwin runs no entry rule to judge it
func TestNodeOnARealUTUNDropsAnUnownedReadTowardAnotherNode(t *testing.T) {
	requireRealUTUN(t)
	u := startUTUN(t, t.TempDir())
	neighbor, far := netip.MustParseAddr("2001:db8:100::30"), netip.MustParseAddr("3fff:20::1")
	peer := netstack.NewPeer("another node", nil, nil, nil)
	t.Cleanup(peer.Close)
	u.node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:20::/32"), peer)
	if e := u.node.Mesh.ExplainRead(udpPacket(neighbor, far, 40000, 9, []byte("neighbor"))); e.Decision != netstack.TraceDrop || e.Reason != "unowned_source" {
		t.Errorf("a read from %s to %s on a node New started is %s %q, want %s %q", neighbor, far, e.Decision, e.Reason, netstack.TraceDrop, "unowned_source")
	}
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
	address, routed, grown, err := u.wholeUTUN(t, time.Now().Add(utunBudget))
	if err != nil {
		t.Fatalf("no reading of the utun the node starting down holds bare came whole within %v, the host's interfaces or routes growing under %d listings, the last answering %v", utunBudget, grown, err)
	}
	if address || routed {
		t.Errorf("the node starting down put its address (%v) or its route (%v) on the utun", address, routed)
	}
	if _, err := u.node.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.waitOnUTUN(t, "the address and the route on the utun after up", func(address, routed bool) bool { return address && routed })
}
