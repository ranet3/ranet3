// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// the tests in this file write into a kernel, two nodes on real tuns
// a node opens its sockets, its tun and its netlink from whatever thread a goroutine runs on, and no one thread can be moved into a namespace for it
// they run instead as root in a network namespace the whole process started in and that held nothing, which unshare -rn starts
// they skip anywhere without root and refuse to start in a namespace that holds anything

const (
	// kernelHello is the Babel hello interval of the two nodes
	kernelHello = 4 * time.Second
	// liveFor is how long a neighbor that stopped sending hellos stays live, three and a half hello intervals
	liveFor = kernelHello * 7 / 2
	// noticedWithin bounds how long the peer of a node going down keeps its kernel route to that node
	// it is a fifth of liveFor, which only the Delete a down sends can meet
	noticedWithin = liveFor / 5
	// fibRuleHeader is the size of struct fib_rule_hdr, which leads every rule message
	fibRuleHeader = 12
)

// kernelMeshPrefix holds the host address of each node, and each node's rule sends it to that node's table
var kernelMeshPrefix = netip.MustParsePrefix("10.77.0.0/24")

var (
	// namespaceOnce claims the namespace for the first test that asks, and its verdict stands for every later one
	namespaceOnce sync.Once
	// namespaceSkip says why the process may not write into its namespace, empty where it may
	namespaceSkip string
	// namespaceErr is a namespace this process could not read or could not bring its loopback up in
	namespaceErr error
)

// kernelNamespace skips the test without root and refuses it in a network namespace that held anything
// the first call reads the namespace and brings its loopback up, which the two nodes reach each other over
func kernelNamespace(t *testing.T) {
	t.Helper()
	namespaceOnce.Do(func() { namespaceSkip, namespaceErr = claimNamespace() })
	if namespaceSkip != "" {
		t.Skip(namespaceSkip)
	}
	if namespaceErr != nil {
		t.Fatal(namespaceErr)
	}
}

// claimNamespace takes the namespace for these tests when every link in it is down without an address and it holds no route
// a loaded tunnel module puts a fallback device in every new namespace, down and without an address, so a link's name proves nothing
func claimNamespace() (string, error) {
	if os.Getuid() != 0 {
		return "writing tuns, routes and rules needs root, as unshare -rn gives in a network namespace of its own", nil
	}
	links, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list the links: %w", err)
	}
	for _, link := range links {
		addresses, err := link.Addrs()
		if err != nil {
			return "", fmt.Errorf("list the addresses of %s: %w", link.Name, err)
		}
		if link.Flags&net.FlagUp != 0 || len(addresses) != 0 {
			return "", fmt.Errorf("refusing to start: %s is up or carries an address, so this network namespace was not made for this process, and unshare -rn makes one that was", link.Name)
		}
	}
	routes, err := dumpRoutes()
	if err != nil {
		return "", err
	}
	if len(routes) != 0 {
		return "", fmt.Errorf("refusing to start: this network namespace holds %d routes, so it was not made for this process, and unshare -rn makes one that was", len(routes))
	}
	return "", bringUp("lo")
}

// kernelRoute is one route a dump of the namespace reads back
type kernelRoute struct {
	destination netip.Prefix
	table       uint32
	protocol    uint8
	// kind is the rtm_type, RTN_UNICAST for a route that carries packets and RTN_UNREACHABLE for the hold a retraction leaves
	kind uint8
	// device is the index of the link the route leaves by, zero for a route leaving by none
	device int
}

func (r kernelRoute) String() string {
	return fmt.Sprintf("%s table %d proto %d type %d dev %d", r.destination, r.table, r.protocol, r.kind, r.device)
}

// dumpRoutes reads every route of every table and family in the namespace
func dumpRoutes() ([]kernelRoute, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("dump the routes: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("parse the route dump: %w", err)
	}
	var routes []kernelRoute
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWROUTE || len(message.Data) < syscall.SizeofRtMsg {
			continue
		}
		route := kernelRoute{table: uint32(message.Data[4]), protocol: message.Data[5], kind: message.Data[7]}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nil, fmt.Errorf("parse a route: %w", err)
		}
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case syscall.RTA_DST:
				if address, ok := netip.AddrFromSlice(attribute.Value); ok {
					route.destination = netip.PrefixFrom(address, int(message.Data[1]))
				}
			case syscall.RTA_TABLE:
				if len(attribute.Value) >= 4 {
					route.table = binary.NativeEndian.Uint32(attribute.Value)
				}
			case syscall.RTA_OIF:
				if len(attribute.Value) >= 4 {
					route.device = int(binary.NativeEndian.Uint32(attribute.Value))
				}
			}
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// kernelRule is one policy rule a dump of the namespace reads back
type kernelRule struct {
	family      uint8
	destination netip.Prefix
	// iif is the name of the link the rule matches arrivals on, empty for a rule matching any
	iif      string
	table    uint32
	priority uint32
	protocol uint8
}

func (r kernelRule) String() string {
	return fmt.Sprintf("family %d to %s iif %q table %d priority %d proto %d", r.family, r.destination, r.iif, r.table, r.priority, r.protocol)
}

// dumpRules reads every policy rule of every family in the namespace
// syscall.ParseNetlinkRouteAttr knows no rule message, so the attributes after struct fib_rule_hdr are walked here
func dumpRules() ([]kernelRule, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETRULE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("dump the rules: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("parse the rule dump: %w", err)
	}
	var rules []kernelRule
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWRULE || len(message.Data) < fibRuleHeader {
			continue
		}
		rule := kernelRule{family: message.Data[0], table: uint32(message.Data[4])}
		for data := message.Data[fibRuleHeader:]; len(data) >= unix.SizeofRtAttr; {
			length := int(binary.NativeEndian.Uint16(data))
			if length < unix.SizeofRtAttr || length > len(data) {
				return nil, errors.New("a rule attribute runs past its message")
			}
			value := data[unix.SizeofRtAttr:length]
			switch binary.NativeEndian.Uint16(data[2:]) &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER) {
			case unix.FRA_DST:
				if address, ok := netip.AddrFromSlice(value); ok {
					rule.destination = netip.PrefixFrom(address, int(message.Data[1]))
				}
			case unix.FRA_IIFNAME:
				rule.iif = strings.TrimRight(string(value), "\x00")
			case unix.FRA_TABLE:
				if len(value) >= 4 {
					rule.table = binary.NativeEndian.Uint32(value)
				}
			case unix.FRA_PRIORITY:
				if len(value) >= 4 {
					rule.priority = binary.NativeEndian.Uint32(value)
				}
			case unix.FRA_PROTOCOL:
				if len(value) >= 1 {
					rule.protocol = value[0]
				}
			}
			data = data[min(len(data), (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1)):]
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// tunAddresses is every address the link named device carries, the link-local ones the kernel gives a tun itself left out
func tunAddresses(device string) ([]netip.Prefix, error) {
	link, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("look up %s: %w", device, err)
	}
	addresses, err := link.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list the addresses of %s: %w", device, err)
	}
	var out []netip.Prefix
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(network.IP)
		if ip = ip.Unmap(); ip.IsLinkLocalUnicast() {
			continue
		}
		bits, _ := network.Mask.Size()
		out = append(out, netip.PrefixFrom(ip, bits))
	}
	return out, nil
}

// kernelNode is one of two nodes on real tuns in the namespace, each with a reconciler of its own
// the two own a table, a protocol and a rule priority apiece, so the protocol alone tells one node's routes and rules from the other's
type kernelNode struct {
	loopbackNode
	tun      string
	table    uint32
	protocol uint8
	priority uint32
	stateDir string
	// retry is the node's dial retry, zero for the default
	retry  time.Duration
	routes *kernel.Reconciler
	// stop ends the reconciler and then the node, the order the daemon's shutdown takes, and waits for both
	stop func()
}

// newKernelMesh writes the files of two nodes that dial and answer each other over the loopback, each on a tun of its own
// each announces a host address and carries it on its tun, and its rule sends kernelMeshPrefix to its table
func newKernelMesh(t *testing.T) (alpha, bravo *kernelNode) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	mesh := meshCounter.Add(1)
	alpha = &kernelNode{
		loopbackNode: loopbackNode{name: fmt.Sprintf("alpha-%d", mesh), port: freeUDPPort(t), prefix: netip.MustParsePrefix("10.77.0.1/32")},
		tun:          "updown0", table: 100, protocol: 200, priority: 1000,
	}
	bravo = &kernelNode{
		loopbackNode: loopbackNode{name: fmt.Sprintf("bravo-%d", mesh), port: freeUDPPort(t), prefix: netip.MustParsePrefix("10.77.0.2/32")},
		tun:          "updown1", table: 101, protocol: 201, priority: 1001,
	}
	nodes := []*kernelNode{alpha, bravo}
	loopback := "127.0.0.1"
	org := registry.Organization{PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Organization: "example"}
	for _, node := range nodes {
		org.Nodes = append(org.Nodes, registry.Node{
			CommonName: node.name,
			Endpoints:  []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Address: &loopback, Port: node.port}},
		})
	}
	raw, err := json.Marshal(registry.Registry{org})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	registryPath, keyPath := filepath.Join(dir, "registry.json"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(registryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, node := range nodes {
		node.configPath = filepath.Join(dir, node.name+".yaml")
		node.stateDir = filepath.Join(dir, node.name)
		writeKernelConfig(t, node, nodes[1-i], keyPath, registryPath)
	}
	return alpha, bravo
}

// writeKernelConfig writes the file of node, which dials peer and reconciles into its own table on its own tun
func writeKernelConfig(t *testing.T, node, peer *kernelNode, keyPath, registryPath string) {
	t.Helper()
	body := fmt.Sprintf(`node: example/%s
auth:
  key: %s
  trust: %s
link:
  port: %d
  tun: %s
  endpoints:
    - serial: "0"
      family: ip4
  listen: true
dial:
  to:
    - example/%s:0
cap:
  babel:
    hello: %s
    update: %s
  route:
    announce:
      - %q
  table:
    id: %d
    proto: %d
    assign_announced: true
    rules:
      - to: %s
        table: %d
        priority: %d
`, node.name, keyPath, registryPath, node.port, node.tun, peer.name, kernelHello, 2*kernelHello,
		node.prefix.String(), node.table, node.protocol, kernelMeshPrefix, node.table, node.priority)
	if err := os.WriteFile(node.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// start builds n from its file as the daemon does and runs it
// the reconciler is handed over before either runs, so a node starting down stops it before its first pass
func (n *kernelNode) start(t *testing.T) {
	t.Helper()
	cfg, err := config.Load(n.configPath)
	if err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	n.cfg, n.events = cfg, events.New()
	node, err := New(cfg, n.events)
	if err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	node.dialRetry = n.retry
	if err := node.SetStateDir(n.stateDir); err != nil {
		node.Close()
		t.Fatal(err)
	}
	routes, err := kernel.New(*cfg.Cap.Table, node.KernelRuntime(), node.Mesh.Routes)
	if err != nil {
		node.Close()
		t.Fatalf("%s's reconciler: %v", n.name, err)
	}
	node.SetReconcilerEnable(routes.SetEnabled)
	node.SetReconcilerTable(routes.SetTable)
	routesCtx, stopRoutes := context.WithCancel(context.Background())
	meshCtx, stopMesh := context.WithCancel(context.Background())
	withdrawn, left := make(chan error, 1), make(chan error, 1)
	go func() { withdrawn <- routes.Run(routesCtx) }()
	go func() { left <- node.Run(meshCtx) }()
	n.client, n.routes = node, routes
	n.stop = sync.OnceFunc(func() {
		stopRoutes()
		select {
		case err := <-withdrawn:
			if err != nil {
				t.Errorf("%s's reconciler withdrew with %v", n.name, err)
			}
		case <-time.After(convergeBudget):
			t.Errorf("%s's reconciler did not stop", n.name)
		}
		stopMesh()
		select {
		case err := <-left:
			if err != nil && !isCanceled(err) {
				t.Errorf("%s stopped with %v", n.name, err)
			}
		case <-time.After(convergeBudget):
			t.Errorf("%s did not stop", n.name)
		}
	})
	t.Cleanup(n.stop)
}

// forwardsTo reports whether the table of n holds a route of its protocol that carries packets for the address of peer out of its tun
func (n *kernelNode) forwardsTo(t *testing.T, peer *kernelNode) bool {
	t.Helper()
	link, err := net.InterfaceByName(n.tun)
	if err != nil {
		t.Fatalf("look up %s: %v", n.tun, err)
	}
	routes, err := dumpRoutes()
	if err != nil {
		t.Fatal(err)
	}
	return slices.Contains(routes, kernelRoute{destination: peer.prefix, table: n.table, protocol: n.protocol, kind: syscall.RTN_UNICAST, device: link.Index})
}

// installed lists what the kernel holds that n put there, an address on its tun or a route or rule of its protocol, empty where it holds none
func (n *kernelNode) installed(t *testing.T) string {
	t.Helper()
	addresses, err := tunAddresses(n.tun)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := dumpRoutes()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := dumpRules()
	if err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, address := range addresses {
		held = append(held, "address "+address.String())
	}
	for _, route := range routes {
		if route.protocol == n.protocol {
			held = append(held, "route "+route.String())
		}
	}
	for _, rule := range rules {
		if rule.protocol == n.protocol {
			held = append(held, "rule "+rule.String())
		}
	}
	return strings.Join(held, ", ")
}

// restored reports whether n carries its address on its tun and holds its rule, the two a down takes away beside the routes
func (n *kernelNode) restored(t *testing.T) bool {
	t.Helper()
	addresses, err := tunAddresses(n.tun)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := dumpRules()
	if err != nil {
		t.Fatal(err)
	}
	rule := kernelRule{family: unix.AF_INET, destination: kernelMeshPrefix, table: n.table, priority: n.priority, protocol: n.protocol}
	return slices.Contains(addresses, n.prefix) && slices.Contains(rules, rule)
}

// converged reports whether each node holds one session and its kernel forwards to the other node
func converged(t *testing.T, alpha, bravo *kernelNode) bool {
	t.Helper()
	return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1 &&
		alpha.forwardsTo(t, bravo) && bravo.forwardsTo(t, alpha)
}

// a node going down closes its session with a Delete, and its peer acts on it at once rather than once the neighbor has gone silent
// the kernel of the peer stops forwarding to the node well inside the time a silent neighbor stays live
// the node withdraws its address, its routes and its rule and keeps its tun
// up brings the session, the routes, the address and the rule back
func TestNodeGoingDownLeavesItsPeerAndItsKernelAtOnce(t *testing.T) {
	kernelNamespace(t)
	alpha, bravo := newKernelMesh(t)
	bravo.retry = shortDialRetry
	alpha.start(t)
	bravo.start(t)
	waitFor(t, convergeBudget, "one session at each end and each kernel forwarding to the other node", func() bool {
		return converged(t, alpha, bravo)
	})

	went := time.Now()
	if _, err := alpha.client.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the kernel of bravo to stop forwarding to alpha", func() bool { return !bravo.forwardsTo(t, alpha) })
	took := time.Since(went)
	t.Logf("the kernel of bravo stopped forwarding to alpha %s after the down, and a silent neighbor stays live for %s", took, liveFor)
	if took > noticedWithin {
		t.Errorf("bravo forwarded to alpha for %s after the down, past the %s only the Delete can meet", took, noticedWithin)
	}
	waitFor(t, convergeBudget, "alpha to withdraw everything it installed", func() bool { return alpha.installed(t) == "" })
	if _, err := net.InterfaceByName(alpha.tun); err != nil {
		t.Errorf("the down took the tun of alpha away: %v", err)
	}
	if what := offTheMesh(alpha.client); what != "" {
		t.Errorf("alpha is down with %s", what)
	}

	if _, err := alpha.client.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "one session at each end and each kernel forwarding to the other node again", func() bool {
		return converged(t, alpha, bravo)
	})
	waitFor(t, convergeBudget, "the address and the rule of alpha back", func() bool { return alpha.restored(t) })
}

// a node restarted while down reads its flag and comes up down since the moment it went
// its tun is there and nothing else of it is, since its reconciler takes the stop before its first pass and its listener answers no dial
// up then puts it back on the mesh and into the kernel
func TestNodeRestartedWhileDownInstallsNothingUntilUp(t *testing.T) {
	kernelNamespace(t)
	alpha, bravo := newKernelMesh(t)
	bravo.retry = shortDialRetry
	alpha.start(t)
	bravo.start(t)
	waitFor(t, convergeBudget, "one session at each end and each kernel forwarding to the other node", func() bool {
		return converged(t, alpha, bravo)
	})
	if _, err := alpha.client.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	since := alpha.client.Status().Down.Since
	alpha.stop()
	waitFor(t, convergeBudget, "the tun of alpha to go with the node", func() bool {
		_, err := net.InterfaceByName(alpha.tun)
		return err != nil
	})

	alpha.start(t)
	waitFor(t, convergeBudget, "the first pass of the reconciler of alpha", func() bool { return !alpha.routes.Stats().At.IsZero() })
	if status := alpha.client.Status().Down; status == nil || !status.Since.Equal(since) {
		t.Fatalf("the restart reports %+v, want down since %s", status, since)
	}
	refused := alpha.client.hub.Refused()
	waitFor(t, convergeBudget, "alpha to refuse a dial of bravo", func() bool { return alpha.client.hub.Refused() > refused })
	if held := alpha.installed(t); held != "" {
		t.Errorf("the node restarted down installed %s", held)
	}
	if _, err := net.InterfaceByName(alpha.tun); err != nil {
		t.Errorf("the node restarted down has no tun: %v", err)
	}
	if what := offTheMesh(alpha.client); what != "" {
		t.Errorf("the node restarted down runs %s", what)
	}

	if _, err := alpha.client.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "one session at each end and each kernel forwarding to the other node again", func() bool {
		return converged(t, alpha, bravo)
	})
	waitFor(t, convergeBudget, "the address and the rule of alpha back", func() bool { return alpha.restored(t) })
}
