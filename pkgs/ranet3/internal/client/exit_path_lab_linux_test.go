// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the two-exit lab's places: the leaf, exit a, exit b, and the waypoint between the leaf and a
const (
	pathLeaf = iota
	pathExitA
	pathExitB
	pathWaypoint
)

const (
	// pathForwarded is the leaf's end of the link to the neighbor cap.exit forward names, and pathUnforwarded its end of the link to the one it does not
	pathForwarded   = "lnf"
	pathUnforwarded = "lnn"
	// pathLAN is the leaf's end of the link to a LAN it announces and forward names, whose prefixes the exits' allow lists hold outside the overlay
	pathLAN = "lnl"
)

var (
	// pathRouter is each node's router-id by family, a host route it announces and its tun holds, the leaf's being rulesHost's own
	pathRouter = [4]map[int]netip.Addr{
		{4: rulesHost[4].own.Addr(), 6: rulesHost[6].own.Addr()},
		{4: netip.MustParseAddr("192.0.2.2"), 6: netip.MustParseAddr("3fff::2")},
		{4: netip.MustParseAddr("192.0.2.3"), 6: netip.MustParseAddr("3fff::3")},
		{4: netip.MustParseAddr("192.0.2.4"), 6: netip.MustParseAddr("3fff::4")},
	}
	// pathSIDA and pathSIDB are the exits' End.DT46 egress segments, and pathSIDW the waypoint's End
	pathSIDA = netip.MustParseAddr("3fff:0:0:a::46")
	pathSIDB = netip.MustParseAddr("3fff:0:0:b::46")
	pathSIDW = netip.MustParseAddr("3fff:0:0:d::1")
	// pathSIDAOutside is a second egress segment of a's, outside the overlay, which b would egress toward as to any internet host
	pathSIDAOutside = netip.MustParseAddr("2001:db8:0:a::46")
	// pathSubnetB is a subnet over pathSIDAOutside that b comes to announce, a route counting as no default
	pathSubnetB = netip.MustParsePrefix("2001:db8:0:a::/64")
	// pathInternet is a host of the internet of each family, which only a default reaches
	pathInternet = map[int]netip.Addr{4: netip.MustParseAddr("203.0.113.99"), 6: netip.MustParseAddr("2001:db8:99::9")}
	// pathLinks are the mesh's veth pairs: the leaf to b, the leaf to the waypoint, and the waypoint to a, so a's routes reach the leaf a hop further than b's
	pathLinks = []labLink{
		{places: [2]int{pathLeaf, pathExitB}, ends: [2]netip.Prefix{netip.MustParsePrefix("198.51.100.1/30"), netip.MustParsePrefix("198.51.100.2/30")}},
		{places: [2]int{pathLeaf, pathWaypoint}, ends: [2]netip.Prefix{netip.MustParsePrefix("198.51.100.5/30"), netip.MustParsePrefix("198.51.100.6/30")}},
		{places: [2]int{pathWaypoint, pathExitA}, ends: [2]netip.Prefix{netip.MustParsePrefix("198.51.100.9/30"), netip.MustParsePrefix("198.51.100.10/30")}},
	}
	// pathUplinks is each uplink's two ends of each family, the node's and then the far host's, for a, b and the leaf
	pathUplinks = map[int][2][2]netip.Prefix{
		pathExitA: {{netip.MustParsePrefix("203.0.113.17/30"), netip.MustParsePrefix("2001:db8:a1::1/64")}, {netip.MustParsePrefix("203.0.113.18/30"), netip.MustParsePrefix("2001:db8:a1::2/64")}},
		pathExitB: {{netip.MustParsePrefix("203.0.113.21/30"), netip.MustParsePrefix("2001:db8:b1::1/64")}, {netip.MustParsePrefix("203.0.113.22/30"), netip.MustParsePrefix("2001:db8:b1::2/64")}},
		pathLeaf:  {{netip.MustParsePrefix("203.0.113.25/30"), netip.MustParsePrefix("2001:db8:c1::1/64")}, {netip.MustParsePrefix("203.0.113.26/30"), netip.MustParsePrefix("2001:db8:c1::2/64")}},
	}
	// pathNeighbors is each neighbor link's two ends of each family, the leaf's and then the neighbor's
	pathNeighbors = map[string][2][2]netip.Prefix{
		pathForwarded:   {{netip.MustParsePrefix("203.0.113.33/28"), netip.MustParsePrefix("2001:db8:f1::1/64")}, {netip.MustParsePrefix("203.0.113.34/28"), netip.MustParsePrefix("2001:db8:f1::2/64")}},
		pathUnforwarded: {{netip.MustParsePrefix("203.0.113.49/28"), netip.MustParsePrefix("2001:db8:f2::1/64")}, {netip.MustParsePrefix("203.0.113.50/28"), netip.MustParsePrefix("2001:db8:f2::2/64")}},
		pathLAN:         {{netip.MustParsePrefix("203.0.113.65/28"), netip.MustParsePrefix("2001:db8:f3::1/64")}, {netip.MustParsePrefix("203.0.113.66/28"), netip.MustParsePrefix("2001:db8:f3::2/64")}},
	}
	// pathLANPrefixes is the LAN's two networks
	pathLANPrefixes = []string{"203.0.113.64/28", "2001:db8:f3::/64"}
)

// pathLab is the two-exit lab: the four nodes, the far host on each uplink with a capture of it, the leaf's two neighbors,
// the leaf's reconciler, each node's antispoof filter, and each exit's translator
type pathLab struct {
	nodes      []*labNode
	captures   map[int]int
	neighbors  map[string]*netnstest.Thread
	routes     *kernel.Reconciler
	stopRoutes func()
	stopW      func()
	borders    map[int]*kernelexit.BorderFilter
	exits      map[int]*kernelexit.Translator
}

// pathSpecs is the lab's four nodes: the leaf in mode 3 along via, forwarding the link to one neighbor and the LAN it announces
// a and b exits advertising a default of each family, each with an egress segment whose allow holds the leaf's own addresses and its LAN, a with a second outside the overlay
// and the waypoint carrying transit, with an End segment of its own
func pathSpecs(via ...netip.Addr) []labSpec {
	hosts := func(place int) []string {
		return []string{netip.PrefixFrom(pathRouter[place][4], 32).String(), netip.PrefixFrom(pathRouter[place][6], 128).String()}
	}
	tunHosts := func(place int) []netip.Prefix {
		return []netip.Prefix{netip.PrefixFrom(pathRouter[place][4], 32), netip.PrefixFrom(pathRouter[place][6], 128)}
	}
	overlay := func() []schema.Prefix {
		var out []schema.Prefix
		for _, prefix := range labOverlay {
			out = append(out, schema.PrefixFrom(prefix))
		}
		return out
	}
	exit := func(sids ...netip.Addr) func(*config.Config) {
		return func(cfg *config.Config) {
			cfg.Cap.Egress = &egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}}
			cfg.Overlay = overlay()
			cfg.Cap.Segment = &srv6.Segments{}
			for _, sid := range sids {
				cfg.Cap.Segment.Local = append(cfg.Cap.Segment.Local, egressSegment(sid.String(), append([]string{rulesHost[4].own.String(), rulesHost[6].own.String()}, pathLANPrefixes...)...))
			}
		}
	}
	leaf := labSpec{announce: append(hosts(pathLeaf), pathLANPrefixes...), dial: []int{pathExitB, pathWaypoint}, forwards: true, change: func(cfg *config.Config) {
		cfg.Cap.Table = &kernel.Table{ID: kernel.DefaultTable, Addresses: []schema.Prefix{schema.PrefixFrom(rulesHost[4].own), schema.PrefixFrom(rulesHost[6].own)}}
		cfg.Overlay = overlay()
		cfg.Cap.Exit = &kernel.ExitMode{Forward: []string{pathForwarded, pathLAN}}
		for _, sid := range via {
			cfg.Cap.Exit.Via = append(cfg.Cap.Exit.Via, schema.AddrFrom(sid))
		}
	}}
	a := labSpec{announce: hosts(pathExitA), hosts: tunHosts(pathExitA), forwards: true, change: exit(pathSIDA, pathSIDAOutside)}
	b := labSpec{announce: hosts(pathExitB), hosts: tunHosts(pathExitB), forwards: true, change: exit(pathSIDB)}
	w := labSpec{announce: append(hosts(pathWaypoint), netip.PrefixFrom(pathSIDW, 128).String()), hosts: tunHosts(pathWaypoint), dial: []int{pathExitA}, change: func(cfg *config.Config) {
		cfg.Cap.Transit = &babel.Transit{}
		// a dear link to the waypoint, so a's routes reach the leaf by a metric b's always beat, whatever the round trips measure
		rx := uint16(512)
		cfg.Cap.Babel.Cost.Rx = &rx
		// the End segment admits an outer source inside the overlay alone, as every SID does
		cfg.Overlay = overlay()
		cfg.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{{SID: schema.AddrFrom(pathSIDW), Behavior: srv6.BehaviorEnd}}}
	}}
	return []labSpec{leaf, a, b, w}
}

// startPathLab builds the lab with the leaf's path along via, starts every node, each node's border, each exit's translator and the leaf's
// reconciler, and waits for the leaf to resolve each SID and hold the steered defaults
func startPathLab(t *testing.T, via ...netip.Addr) *pathLab {
	t.Helper()
	lab := &pathLab{captures: map[int]int{}, neighbors: map[string]*netnstest.Thread{}, borders: map[int]*kernelexit.BorderFilter{}, exits: map[int]*kernelexit.Translator{}}
	lab.nodes = startLab(t, pathSpecs(via...), pathLinks)
	leaf := lab.nodes[pathLeaf]
	if err := leaf.ns.Do(func() error {
		for path, value := range map[string]string{"/proc/sys/net/ipv4/conf/all/rp_filter": "0", "/proc/sys/net/ipv4/conf/default/rp_filter": "0"} {
			if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("turn reverse path filtering off at the leaf: %v", err)
	}
	for _, place := range []int{pathExitA, pathExitB, pathLeaf} {
		lab.captures[place] = pathUplink(t, lab.nodes[place], pathUplinks[place])
	}
	for _, name := range []string{pathForwarded, pathUnforwarded, pathLAN} {
		lab.neighbors[name] = pathNeighbor(t, leaf, name, pathNeighbors[name])
	}
	// the table inet ranet3 is on at every node before a reconciler routes anything into the tun, as the command writes it
	for place, node := range lab.nodes {
		lab.borders[place] = pathBorder(t, node)
	}
	for _, place := range []int{pathExitA, pathExitB} {
		// the exit's kernel routes a reply to the overlay back into its tun through the route startLab writes beside its addresses
		lab.exits[place] = labTranslate(t, lab.nodes[place])
	}

	_, lab.stopW = run(t, lab.nodes[pathWaypoint].loopbackNode)
	run(t, leaf.loopbackNode, lab.nodes[pathExitA].loopbackNode, lab.nodes[pathExitB].loopbackNode)
	lab.startRoutes(t)
	labRoutes(t, leaf, append([]netip.Addr{pathSIDA, pathSIDB, pathSIDW}, pathRouter[pathExitB][4], pathRouter[pathExitB][6])...)
	lab.settle(t, true)
	return lab
}

// startRoutes builds the leaf's reconciler and hands the node its status, its rules, its reload and its network's wake, as the command does
func (lab *pathLab) startRoutes(t *testing.T) {
	t.Helper()
	leaf := lab.nodes[pathLeaf]
	if err := leaf.ns.Do(func() (err error) {
		lab.routes, err = kernel.New(*leaf.client.config().ReconcilerTable(), leaf.client.KernelRuntime(), leaf.client.Mesh.Routes)
		return err
	}); err != nil {
		t.Fatalf("build the leaf's reconciler: %v", err)
	}
	routes := lab.routes
	leaf.client.SetReconciler(Reconciler{Status: func() control.KernelStatus { return kernelStatus(routes) }, Rules: routes.DerivedRules,
		Lookups: func() []kernel.Lookup { return routes.Stats().Lookups }, Table: routes.SetTable, Network: routes.NetworkChanged})
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	lab.stopRoutes = sync.OnceFunc(func() {
		cancel()
		runs.Wait()
	})
	t.Cleanup(lab.stopRoutes)
	// in the leaf's namespace, as every thread of the daemon shares its one, so the socket for the table ranet3_fallback a
	// reload's pass opens goes in it
	runner := netnstest.JoinThread(t, leaf.ns.Path)
	runs.Go(func() {
		if err := runner.Do(func() error { return routes.Run(ctx) }); err != nil {
			t.Errorf("the leaf's reconciler: %v", err)
		}
	})
}

// settle waits for the leaf's table to hold the steered defaults where up says, and neither where it does not
func (lab *pathLab) settle(t *testing.T, up bool) {
	t.Helper()
	waitFor(t, convergeBudget, fmt.Sprintf("the leaf's steered defaults installed %v", up), func() bool {
		return exitDefaults(t, lab.nodes[pathLeaf].ns, up)
	})
}

// pathUplink joins node to a far host of its own over a veth pair whose ends ends gives, routes node's defaults of each family through the far host,
// and returns a capture of the far host's end, where whatever node sends out of its uplink arrives
func pathUplink(t *testing.T, node *labNode, ends [2][2]netip.Prefix) int {
	t.Helper()
	near, far := fmt.Sprintf("u%c", 'a'+pathPlace(node)), fmt.Sprintf("f%c", 'a'+pathPlace(node))
	host := vethHost(t, node.ns, near, far, ends)
	hostDefaults(t, node.ns, near, ends[1][0].Addr(), ends[1][1].Addr())
	var capture int
	if err := host.Do(func() (err error) { capture, err = openCapture(far, labRetry); return err }); err != nil {
		t.Fatalf("capture the far end of %s's uplink: %v", node.name, err)
	}
	t.Cleanup(func() { _ = unix.Close(capture) })
	return capture
}

// pathNeighbor joins the leaf to a neighbor of its own over a veth pair, its end on the leaf named name, the neighbor's defaults through the leaf
func pathNeighbor(t *testing.T, leaf *labNode, name string, ends [2][2]netip.Prefix) *netnstest.Thread {
	t.Helper()
	host := vethHost(t, leaf.ns, name, name+"x", ends)
	hostDefaults(t, host, name+"x", ends[0][0].Addr(), ends[0][1].Addr())
	return host
}

// pathPlace is the lab place node's name carries, as startLab names it
func pathPlace(node *labNode) int { return int(node.name[len("lab-")] - 'a') }

// pathBorder builds and runs node's antispoof filter as the command builds it, until the test ends, and answers it
func pathBorder(t *testing.T, node *labNode) *kernelexit.BorderFilter {
	t.Helper()
	var border *kernelexit.BorderFilter
	if err := node.ns.Do(func() (err error) {
		border, err = kernelexit.NewBorderFilter(node.client.config().Border(), node.client.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("build %s's antispoof filter: %v", node.name, err)
	}
	node.client.SetBorder(border)
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	runs.Go(func() {
		if err := border.Run(ctx); err != nil {
			t.Errorf("%s's antispoof filter: %v", node.name, err)
		}
	})
	t.Cleanup(func() {
		cancel()
		runs.Wait()
	})
	return border
}

// pathLost reports the leaf resolving sid to no peer but through a route that counts as a default, b's, as the reconciler reads it
func pathLost(leaf *labNode, sid netip.Addr) bool {
	_, verdict, match := leaf.client.Mesh.Routes.Resolve(netip.Addr{}, sid)
	return verdict != netstack.RoutePeer || match.Counted
}

// pathSent is one probe the leaf's host sends to the internet, and its number
type pathSent struct {
	probe    rulesProbe
	protocol string
	number   int
}

// send sends echo, UDP and TCP of both families to the internet from the leaf's unbound sockets and from the ones bound to its overlay address,
// numbered from *next, and answers where each first packet left: out of a's uplink, b's or the leaf's own, nowhere, or, for a send the kernel
// refused and nothing left of, what the send met. It fails the test where mesh_entry at the leaf dropped any of them, since every
// packet the steered defaults route into the tun is the host's own.
func (lab *pathLab) send(t *testing.T, next *int) map[pathSent]string {
	t.Helper()
	leaf := lab.nodes[pathLeaf]
	entered := entryDropped(t, leaf.ns, lab.borders[pathLeaf])
	var probes []pathSent
	var fds []int
	outcomes := map[int]rulesOutcome{}
	if err := lab.nodes[pathLeaf].ns.Do(func() error {
		for _, family := range []int{4, 6} {
			for _, socket := range []rulesSocket{rulesUnbound, rulesFromOverlay} {
				for _, protocol := range []string{"udp", "tcp", "echo"} {
					*next++
					p := rulesProbe{destination: pathInternet[family], socket: socket}
					fd, outcome, err := rulesSend(p, protocol, *next)
					if err != nil {
						return fmt.Errorf("%s %s to %s: %w", socket, protocol, p.destination, err)
					}
					if fd >= 0 {
						fds = append(fds, fd)
					}
					outcomes[*next] = outcome
					probes = append(probes, pathSent{p, protocol, *next})
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send the probes: %v", err)
	}
	drained := map[string]map[rulesKey]netip.Addr{}
	for name, place := range map[string]int{"a": pathExitA, "b": pathExitB, "the leaf": pathLeaf} {
		drained[name] = rulesDrain(lab.captures[place])
	}
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
	dropped := entryDropped(t, leaf.ns, lab.borders[pathLeaf])
	t.Logf("mesh_entry at the leaf dropped %d IPv4 and %d IPv6 packets of the probes", dropped[4]-entered[4], dropped[6]-entered[6])
	entryMoved(t, entered, dropped, map[int]uint64{4: 0, 6: 0})
	out := map[pathSent]string{}
	for _, p := range probes {
		var left []string
		for _, name := range []string{"a", "b", "the leaf"} {
			if _, ok := drained[name][rulesKey{p.protocol, p.number}]; ok {
				left = append(left, name)
			}
		}
		switch outcome := outcomes[p.number]; {
		case len(left) == 0 && outcome != rulesSent:
			out[p] = string(outcome)
		case len(left) == 0:
			out[p] = "nowhere"
		case len(left) == 1:
			out[p] = left[0]
		default:
			out[p] = fmt.Sprint(left)
		}
	}
	return out
}

// expect fails the test for each probe whose first packet left elsewhere than out of want's uplink
func (lab *pathLab) expect(t *testing.T, next *int, want string) {
	t.Helper()
	for p, got := range lab.send(t, next) {
		if got != want {
			t.Errorf("%s from a socket %s to %s left out of %s's uplink, want %s's", p.protocol, p.probe.socket, p.probe.destination, got, want)
		}
	}
}

// refused fails the test for each probe whose first packet left by any uplink, each one refused by its route or the switch or
// dropped where no capture sees it
func (lab *pathLab) refused(t *testing.T, next *int) {
	t.Helper()
	for p, got := range lab.send(t, next) {
		if got != "nowhere" && got != string(rulesUnreachable) && got != string(rulesSwitchRefused) {
			t.Errorf("%s from a socket %s to %s left out of %s's uplink, want it refused", p.protocol, p.probe.socket, p.probe.destination, got)
		}
	}
}

// sendNow sends a UDP datagram of each family to the internet from the leaf's unbound sockets, numbered from *next, reading no capture
func (lab *pathLab) sendNow(t *testing.T, next *int) {
	t.Helper()
	var fds []int
	if err := lab.nodes[pathLeaf].ns.Do(func() error {
		for _, family := range []int{4, 6} {
			*next++
			fd, _, err := rulesSend(rulesProbe{destination: pathInternet[family], socket: rulesUnbound}, "udp", *next)
			if err != nil {
				return fmt.Errorf("udp to %s: %w", pathInternet[family], err)
			}
			if fd >= 0 {
				fds = append(fds, fd)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send the datagrams: %v", err)
	}
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

// pathToward reads the capture until a read waits out its timeout, and counts the IPv6 packets toward destination it read
func pathToward(capture int, destination netip.Addr) int {
	buf := make([]byte, 1<<16)
	count := 0
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return count
		}
		if n >= 40 && buf[0]>>4 == 6 && netip.AddrFrom16([16]byte(buf[24:40])) == destination {
			count++
		}
	}
}

// switchState is the leaf's switch as status reads it, "off" where it reads none
func (lab *pathLab) switchState() string {
	exit := lab.nodes[pathLeaf].client.Status().Kernel.Exit
	if exit == nil || exit.Fallback == nil {
		return "off"
	}
	return exit.Fallback.State
}

// awaitSwitch fails the test unless status reads the leaf's switch want within convergeBudget
func (lab *pathLab) awaitSwitch(t *testing.T, want kernel.FallbackState) {
	t.Helper()
	waitFor(t, convergeBudget, "the leaf's switch to read "+string(want), func() bool { return lab.switchState() == string(want) })
}

// reloadFallback writes fallback into the leaf's cap.exit, unwritten where empty, reloads it, and waits for status to read the switch want
func (lab *pathLab) reloadFallback(t *testing.T, fallback kernel.Fallback, want kernel.FallbackState) {
	t.Helper()
	leaf := lab.nodes[pathLeaf]
	cfg := *leaf.client.config()
	mode := *cfg.Cap.Exit
	mode.Fallback = fallback
	cfg.Cap.Exit = &mode
	writeConfig(t, leaf.configPath, &cfg)
	if err := leaf.ns.Do(func() error { return leaf.client.ReloadFrom(leaf.configPath) }); err != nil {
		t.Fatalf("reload the leaf with fallback %q: %v", fallback, err)
	}
	lab.awaitSwitch(t, want)
}

// path is the leaf's kernel.exit_path as status reads it
func (lab *pathLab) path(t *testing.T) control.KernelExitPath {
	t.Helper()
	path := lab.nodes[pathLeaf].client.Status().Kernel.ExitPath
	if path == nil {
		t.Fatalf("status reads no kernel.exit_path in mode 3")
	}
	return *path
}

// reload writes via into the leaf's cap.exit and reloads it, and waits for status to read the path up along it
func (lab *pathLab) reload(t *testing.T, via ...netip.Addr) {
	t.Helper()
	leaf := lab.nodes[pathLeaf]
	cfg := *leaf.client.config()
	mode := *cfg.Cap.Exit
	mode.Via = nil
	var want []string
	for _, sid := range via {
		mode.Via = append(mode.Via, schema.AddrFrom(sid))
		want = append(want, sid.String())
	}
	cfg.Cap.Exit = &mode
	writeConfig(t, leaf.configPath, &cfg)
	if err := leaf.ns.Do(func() error { return leaf.client.ReloadFrom(leaf.configPath) }); err != nil {
		t.Fatalf("reload the leaf onto the path %v: %v", want, err)
	}
	waitFor(t, convergeBudget, fmt.Sprintf("status to read the path %v up", want), func() bool {
		path := lab.path(t)
		return slices.Equal(path.Via, want) && path.State == "up"
	})
}

// awaitEvent fails the test unless the last kernel.path event reads want within convergeBudget, since the pass emits it after the kernel holds its routes
func (lab *pathLab) awaitEvent(t *testing.T, want string) {
	t.Helper()
	got := lab.lastPathEvent()
	for deadline := time.Now().Add(convergeBudget); got != want && time.Now().Before(deadline); got = lab.lastPathEvent() {
		time.Sleep(labPoll)
	}
	if got != want {
		t.Errorf("the last kernel.path event reads %q, want %q", got, want)
	}
}

// awaitDown fails the test unless status reads the path down at sid with nothing installed within convergeBudget, since the pass stores its status after the kernel holds its routes
func (lab *pathLab) awaitDown(t *testing.T, sid netip.Addr) {
	t.Helper()
	down := func(path control.KernelExitPath) bool {
		return path.State == "down" && path.Down == sid.String() && len(path.Installed) == 0
	}
	path := lab.path(t)
	for deadline := time.Now().Add(convergeBudget); !down(path) && time.Now().Before(deadline); path = lab.path(t) {
		time.Sleep(labPoll)
	}
	if !down(path) {
		t.Errorf("status reads the path %+v, want it down at %s with nothing installed", path, sid)
	}
}

// lastPathEvent is the last kernel.path event the leaf's bus recorded, as its state, its segment and its families installed
func (lab *pathLab) lastPathEvent() string {
	events := lab.nodes[pathLeaf].events.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.path" }, 0)
	if len(events) == 0 {
		return ""
	}
	last := events[len(events)-1]
	return last.Attrs["state"] + " " + last.Attrs["segment"] + " " + last.Attrs["installed"]
}

// the two-exit lab: a leaf in mode 3 with via naming exit a's End.DT46 egress segment, a and b each such an exit advertising a default of each family,
// b one hop from the leaf and a two, through a waypoint carrying transit, each node in a network namespace of its own with an uplink of the exits' and the leaf's to a far host
// and the table inet ranet3 written at each, as the command writes it
// the leaf's reconciler installs the steered defaults, and echo, UDP and TCP of both families from its unbound sockets and from the ones bound to its overlay address
// leave a's uplink and none leaves b's, though b's default is the leaf's better, while status reads the path up with both defaults and its steered count grown,
// mesh_entry at the leaf dropping none of them
// and the switch fallback unwritten asks for in mode 3 passing
// with a's egress turned off its SID goes, the defaults go with kernel.path naming the SID, status reads the path down at it and the switch holding,
// and the same sockets leave by no uplink, while under fallback = "uplink" written they leave by the leaf's own
// with a's egress back the defaults return within the settle of a pass of the table's change, and the sockets leave a's uplink again
// a neighbor's ping on a link forward does not name leaves the leaf's uplink and reaches neither exit, and one on the link forward names, from a source the leaf does not own,
// is dropped by mesh_entry on its way into the tun, counted there and never read by the tun
// a ping of each family from a host of the LAN the leaf announces on a link forward names leaves a's uplink alone, a's allow holding the LAN outside the overlay
// a path through the waypoint's End to a, reloaded in, carries the sockets out of a's uplink through the waypoint
// a path of the waypoint's End alone leaves by no uplink, its packets dropped at the waypoint
// with a's egress turned off behind the waypoint, which still resolves, the defaults go, down at a's SID, and the sockets leave by no uplink
// and with via naming a's SID outside the overlay and the waypoint gone, b's default the leaf's one route to that SID,
// a datagram sent before the steered defaults go is answered at the leaf and nothing toward the SID leaves b's uplink, then the defaults go, down at that SID, and the sockets leave by no uplink
// and with b announcing a subnet over that SID, a route counting as no default, the path stays down at the SID with no route of its own,
// and the sockets leave by no uplink and nothing toward the SID leaves b's uplink
// and a clean stop of the reconciler leaves no rule or route of its protocol and no table ranet3_fallback
func TestTUNExitPathLeavesByTheNamedExitAndNoOther(t *testing.T) {
	lab := startPathLab(t, pathSIDA)
	leaf, a, w := lab.nodes[pathLeaf], lab.nodes[pathExitA], lab.nodes[pathWaypoint]
	next := 0

	t.Run("b's default is the leaf's better", func(t *testing.T) {
		// read by the node the table names, since the leaf holds a session to b on each of b's endpoints and either may carry a route
		b := "via example/" + lab.nodes[pathExitB].name + ":"
		for _, every := range []string{"0.0.0.0/0 ", "::/0 "} {
			through := func() bool {
				return slices.ContainsFunc(leaf.client.Mesh.Routes.Debug(), func(line string) bool {
					return strings.HasPrefix(line, every+b)
				})
			}
			for deadline := time.Now().Add(convergeBudget); !through() && time.Now().Before(deadline); {
				time.Sleep(labPoll)
			}
			if !through() {
				t.Errorf("the leaf holds %sthrough no session of b's, its table:\n%s", every, strings.Join(leaf.client.Mesh.Routes.Debug(), "\n"))
			}
		}
	})
	t.Run("named exit", func(t *testing.T) {
		egressed, steered := a.client.Mesh.SegmentCounters().Egressed, lab.path(t).Steered
		lab.expect(t, &next, "a")
		if got := a.client.Mesh.SegmentCounters().Egressed; got <= egressed {
			t.Errorf("a counted %d egressed, as before the probes", got)
		}
		path := lab.path(t)
		want := control.KernelExitPath{Via: []string{pathSIDA.String()}, Source: rulesHost[6].own.Addr().String(), State: "up", Installed: []string{"ipv4", "ipv6"}}
		if path.State != want.State || path.Source != want.Source || !slices.Equal(path.Via, want.Via) || !slices.Equal(path.Installed, want.Installed) || path.Steered <= steered {
			t.Errorf("status reads the path %+v, want %+v with more than %d steered", path, want, steered)
		}
		lab.awaitEvent(t, "up  ipv4 ipv6")
		if rules := leaf.client.DebugRules().Steered; rules == nil || rules.State != "up" || len(rules.Routes) != 2 || !rules.Routes[0].Installed || !rules.Routes[1].Installed {
			t.Errorf("debug rules lists the steered defaults as %+v, want both installed", rules)
		}
		lab.awaitSwitch(t, kernel.FallbackPassing)
	})
	t.Run("a's SID retracted", func(t *testing.T) {
		lab.exits[pathExitA].SetEnabled(false)
		waitFor(t, convergeBudget, "the leaf to lose a's SID", func() bool { return pathLost(leaf, pathSIDA) })
		lab.settle(t, false)
		lab.awaitEvent(t, "down "+pathSIDA.String()+" none")
		lab.awaitDown(t, pathSIDA)
		lab.awaitSwitch(t, kernel.FallbackHolding)
		lab.refused(t, &next)
	})
	t.Run("a's SID retracted under fallback = \"uplink\"", func(t *testing.T) {
		lab.reloadFallback(t, kernel.FallbackUplink, "off")
		lab.expect(t, &next, "the leaf")
		lab.reloadFallback(t, "", kernel.FallbackHolding)
		lab.refused(t, &next)
	})
	t.Run("a's SID back", func(t *testing.T) {
		lab.exits[pathExitA].SetEnabled(true)
		labRoutes(t, leaf, pathSIDA)
		lab.settle(t, true)
		lab.awaitEvent(t, "up  ipv4 ipv6")
		lab.expect(t, &next, "a")
	})
	t.Run("neighbors", func(t *testing.T) {
		for _, family := range []int{4, 6} {
			next++
			unowned := leaf.client.Mesh.TransitCounters().UnownedSource
			entered := entryDropped(t, leaf.ns, lab.borders[pathLeaf])
			var received int
			if err := lab.neighbors[pathForwarded].Do(func() (err error) { received, err = exitPing(pathInternet[family], next); return err }); err != nil {
				t.Fatalf("ping from the forwarded neighbor: %v", err)
			}
			// mesh_entry drops them on their way into the tun, so the tun read never judges them
			entryMoved(t, entered, entryDropped(t, leaf.ns, lab.borders[pathLeaf]), map[int]uint64{family: exitPings, 10 - family: 0})
			if got := leaf.client.Mesh.TransitCounters().UnownedSource; got != unowned || received != 0 {
				t.Errorf("the forwarded neighbor's %d pings of %s drew %d replies and %d unowned_source drops, want none and none", exitPings, pathInternet[family], received, got-unowned)
			}
			forwarded := next
			next++
			if err := lab.neighbors[pathUnforwarded].Do(func() (err error) { _, err = exitPing(pathInternet[family], next); return err }); err != nil {
				t.Fatalf("ping from the other neighbor: %v", err)
			}
			for name, place := range map[string]int{"a": pathExitA, "b": pathExitB, "the leaf": pathLeaf} {
				drained := rulesDrain(lab.captures[place])
				for id, want := range map[int]bool{forwarded: false, next: place == pathLeaf} {
					if _, got := drained[rulesKey{"echo", id}]; got != want {
						t.Errorf("a neighbor's ping %d of %s out of %s's uplink: %v, want %v", id, pathInternet[family], name, got, want)
					}
				}
			}
		}
	})
	t.Run("LAN host behind the leaf", func(t *testing.T) {
		for _, family := range []int{4, 6} {
			next++
			egressed := a.client.Mesh.SegmentCounters().Egressed
			entered := entryDropped(t, leaf.ns, lab.borders[pathLeaf])
			if err := lab.neighbors[pathLAN].Do(func() (err error) { _, err = exitPing(pathInternet[family], next); return err }); err != nil {
				t.Fatalf("ping from the LAN host: %v", err)
			}
			// the leaf announces the LAN, so mesh_entry takes its source for one the leaf owns
			entryMoved(t, entered, entryDropped(t, leaf.ns, lab.borders[pathLeaf]), map[int]uint64{4: 0, 6: 0})
			for name, place := range map[string]int{"a": pathExitA, "b": pathExitB, "the leaf": pathLeaf} {
				if _, got := rulesDrain(lab.captures[place])[rulesKey{"echo", next}]; got != (place == pathExitA) {
					t.Errorf("the LAN host's ping of %s out of %s's uplink: %v, want %v", pathInternet[family], name, got, place == pathExitA)
				}
			}
			if got := a.client.Mesh.SegmentCounters().Egressed; got < egressed+exitPings {
				t.Errorf("a counted %d egressed of the LAN host's %d pings of %s", got-egressed, exitPings, pathInternet[family])
			}
		}
	})
	t.Run("path through the waypoint", func(t *testing.T) {
		lab.reload(t, pathSIDW, pathSIDA)
		forwarded := w.client.Mesh.SegmentCounters().Forwarded
		lab.expect(t, &next, "a")
		if got := w.client.Mesh.SegmentCounters().Forwarded; got <= forwarded {
			t.Errorf("the waypoint counted %d forwarded, as before the probes", got)
		}
	})
	t.Run("path whose last segment is an End", func(t *testing.T) {
		// RFC 8986 section 4.8 makes the End.DT46 SID the last of a policy, which the leaf cannot see of another node's SID, so the End drops what reaches it with no segment left
		lab.reload(t, pathSIDW)
		dropped := w.client.Mesh.SegmentCounters().Dropped
		lab.expect(t, &next, "nowhere")
		if got := w.client.Mesh.SegmentCounters().Dropped; got <= dropped {
			t.Errorf("the waypoint counted %d dropped, as before the probes", got)
		}
	})
	t.Run("a's SID retracted behind the waypoint", func(t *testing.T) {
		lab.reload(t, pathSIDW, pathSIDA)
		lab.exits[pathExitA].SetEnabled(false)
		waitFor(t, convergeBudget, "the leaf to lose a's SID", func() bool { return pathLost(leaf, pathSIDA) })
		if pathLost(leaf, pathSIDW) {
			t.Fatal("the leaf lost the waypoint's SID beside a's, so this proves nothing of a later SID")
		}
		lab.settle(t, false)
		lab.awaitDown(t, pathSIDA)
		lab.awaitEvent(t, "down "+pathSIDA.String()+" none")
		lab.awaitSwitch(t, kernel.FallbackHolding)
		lab.refused(t, &next)
		lab.exits[pathExitA].SetEnabled(true)
		labRoutes(t, leaf, pathSIDA)
		lab.settle(t, true)
	})
	t.Run("waypoint gone", func(t *testing.T) {
		lab.reload(t, pathSIDAOutside)
		lab.expect(t, &next, "a")
		unrouted := leaf.client.Mesh.PathCounters().Unrouted
		lab.stopW()
		waitFor(t, convergeBudget, "the leaf to lose a's SID outside the overlay", func() bool { return pathLost(leaf, pathSIDAOutside) })
		// a session's end removes its routes with no hold at a leaf that carries no transit, so the next lookup reaches b's default
		if _, verdict, match := leaf.client.Mesh.Routes.Resolve(netip.Addr{}, pathSIDAOutside); verdict != netstack.RoutePeer || !match.Counted {
			t.Fatalf("the leaf resolves a's SID outside the overlay as verdict %v, counted %v, not through b's default alone, so this proves nothing of the window", verdict, match.Counted)
		}
		lab.sendNow(t, &next)
		if got := pathToward(lab.captures[pathExitB], pathSIDAOutside); got != 0 {
			t.Errorf("%d packets toward a's SID outside the overlay left b's uplink", got)
		}
		if got := leaf.client.Mesh.PathCounters().Unrouted; got <= unrouted {
			t.Errorf("the leaf counted %d unrouted along the path, as before the datagrams sent with b's default its one route to a's SID", got)
		}
		lab.settle(t, false)
		lab.awaitDown(t, pathSIDAOutside)
		lab.awaitEvent(t, "down "+pathSIDAOutside.String()+" none")
		lab.awaitSwitch(t, kernel.FallbackHolding)
		lab.refused(t, &next)
	})
	t.Run("b's subnet over a's SID", func(t *testing.T) {
		b := lab.nodes[pathExitB]
		cfg := *b.client.config()
		route := babel.Routes{Announce: append(slices.Clone(cfg.Cap.Route.Announce), schema.Announce{Prefix: schema.PrefixFrom(pathSubnetB)})}
		cfg.Cap.Route = &route
		writeConfig(t, b.configPath, &cfg)
		if err := b.ns.Do(func() error { return b.client.ReloadFrom(b.configPath) }); err != nil {
			t.Fatalf("b's reload to announce %s: %v", pathSubnetB, err)
		}
		waitFor(t, convergeBudget, "the leaf to reach a's SID through b's subnet", func() bool {
			_, verdict, match := leaf.client.Mesh.Routes.Resolve(netip.Addr{}, pathSIDAOutside)
			return verdict == netstack.RoutePeer && !match.Counted && match.Bits == pathSubnetB.Bits()
		})
		// the pass the table's change starts reads the SID again, and a pass taking the subnet for its route would install the steered defaults
		held := func(path control.KernelExitPath) bool {
			return path.State == "down" && path.Down == pathSIDAOutside.String() && path.Verdict == "no route of its own" && len(path.Installed) == 0
		}
		path := lab.path(t)
		for deadline := time.Now().Add(convergeBudget); !held(path) && time.Now().Before(deadline); path = lab.path(t) {
			time.Sleep(labPoll)
		}
		if !held(path) {
			t.Errorf("status reads the path %+v, want it down at %s with no route of its own and nothing installed", path, pathSIDAOutside)
		}
		lab.sendNow(t, &next)
		if got := pathToward(lab.captures[pathExitB], pathSIDAOutside); got != 0 {
			t.Errorf("%d packets toward a's SID outside the overlay left b's uplink", got)
		}
		lab.settle(t, false)
		lab.refused(t, &next)
	})
	t.Run("clean stop", func(t *testing.T) {
		lab.stopRoutes()
		var rules []kernelRule
		var left []kernelRoute
		var tables map[uint8]uint32
		if err := leaf.ns.Do(func() (err error) {
			if rules, err = dumpRules(); err != nil {
				return err
			}
			if left, err = dumpRoutes(); err != nil {
				return err
			}
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			tables, err = nftables.Tables(conn, kernel.FallbackTable)
			return err
		}); err != nil {
			t.Fatalf("read the leaf back: %v", err)
		}
		if len(tables) > 0 {
			t.Errorf("the stop left the table %s in the families %v", kernel.FallbackTable, tables)
		}
		for _, rule := range rules {
			if rule.protocol == kernel.DefaultProtocol {
				t.Errorf("the stop left the rule %s", rule)
			}
		}
		for _, route := range left {
			if route.protocol == kernel.DefaultProtocol {
				t.Errorf("the stop left the route %s", route)
			}
		}
	})
}
