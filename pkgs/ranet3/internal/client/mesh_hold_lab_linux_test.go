// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel/kerneltest"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// holdAlt is the leaf's end of the link the operator's own routes leave by, and holdAltFar its far end's
	holdAlt    = "rula"
	holdAltFar = "rulz"
	// holdTable is the operator's own table, and holdBird BIRD's protocol
	holdTable = 300
	holdBird  = 12
	// holdHelperReady names, in the crash helper's environment, the file it writes once its first pass took the down set
	holdHelperReady = "RANET3_HOLD_LAB_READY"
	// holdNeighborPort is the port the leaf's neighbor on the uplink listens on, and holdDialWait how long the leaf waits for its answer,
	// which on a veth comes at once
	holdNeighborPort = 42901
	holdDialWait     = 2 * time.Second
)

// holdNeighbor is, in each family, a host on the uplink's far end inside the overlay prefix of holdHost and inside the network of
// holdHost's uplinkCover, which holds that prefix whole, so a neighbor of the leaf's on the uplink's link
var holdNeighbor = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.9/24"), 6: netip.MustParsePrefix("3fff::9/20")}

// holdHost is the lab's addresses in one family: the overlay prefix, the leaf inside it, a subnet of the prefix holding the leaf and
// one route covering the prefix, the uplink's address whose network covers the prefix, the alternate link's two ends, and a
// destination outside the overlay
var holdHost = map[int]struct {
	overlay, leaf, subnet, cover, uplinkCover, alt, altFar netip.Prefix
	unrelated                                              netip.Addr
}{
	4: {
		netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("192.0.2.0/28"),
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.0.2.130/24"),
		netip.MustParsePrefix("203.0.113.193/26"), netip.MustParsePrefix("203.0.113.194/26"), netip.MustParseAddr("203.0.113.50"),
	},
	6: {
		netip.MustParsePrefix("3fff::/21"), netip.MustParsePrefix("3fff::7/128"), netip.MustParsePrefix("3fff::/64"),
		netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("3fff:800::10/20"),
		netip.MustParsePrefix("2001:db8:aa::1/64"), netip.MustParsePrefix("2001:db8:aa::2/64"), netip.MustParseAddr("2001:db8:ee::99"),
	},
}

// where a lookup of the leaf ends: out of the tun, out of the alternate link from main, the operator's table or the mesh's, out of
// the uplink through its gateway's default or to its own network, or refused by an unreachable route or rule
const (
	holdTun         = "tun"
	holdAltMain     = "alt/main"
	holdAltTable    = "alt/300"
	holdAltMesh     = "alt/200"
	holdUplink      = "uplink default"
	holdUplinkLink  = "uplink link"
	holdRefused     = "refused by a route"
	holdRefusedRule = "refused by a rule"
)

// the states a form is read in: before ranet3, running with the leaf live and retracted, down, down and its reconciler disabled,
// after a clean stop, restarted with the leaf live, and killed from there
var holdStates = []string{"before ranet3", "running live", "running retracted", "down", "down disabled", "stopped", "restarted", "killed"}

// holdForm is one of the operator's routes beside the mesh, as the design's table writes it, where the leaf's lookup ends in each of
// holdStates, the same in both families, and how many overlay prefixes the down set holds
type holdForm struct {
	name  string
	write func(n netnstest.Netlink, family int) error
	want  [8]string
	held  int
}

// holdForms is the design's eleven forms and none
func holdForms() []holdForm {
	route := func(to func(int) netip.Prefix, table uint32, metric func(int) uint32, proto uint8) func(netnstest.Netlink, int) error {
		return func(n netnstest.Netlink, family int) error {
			return holdRoute(n, to(family), table, metric(family), proto)
		}
	}
	rule := func(priority uint32) func(netnstest.Netlink, int) error {
		return func(n netnstest.Netlink, family int) error {
			if err := holdRoute(n, holdHost[family].overlay, holdTable, 0, unix.RTPROT_BOOT); err != nil {
				return err
			}
			return holdRule(n, priority, holdHost[family].overlay)
		}
	}
	leaf := func(family int) netip.Prefix { return holdHost[family].leaf }
	subnet := func(family int) netip.Prefix { return holdHost[family].subnet }
	overlay := func(family int) netip.Prefix { return holdHost[family].overlay }
	cover := func(family int) netip.Prefix { return holdHost[family].cover }
	zero := func(int) uint32 { return 0 }
	// the lowest metric a route of each family holds, IPv6 taking 0 as its default
	low := func(family int) uint32 { return map[int]uint32{4: 0, 6: 1}[family] }
	last := func(int) uint32 { return ^uint32(0) }
	main := uint32(unix.RT_TABLE_MAIN)
	operator := [8]string{holdAltMain, holdTun, holdRefused, holdAltMain, holdAltMain, holdAltMain, holdTun, holdRefused}
	shorter := func(before string) [8]string {
		return [8]string{before, holdTun, holdRefused, holdRefusedRule, before, holdRefusedRule, holdTun, holdRefused}
	}
	return []holdForm{
		{"none", nil, shorter(holdUplink), 2},
		{"leaf host route in main", route(leaf, main, zero, unix.RTPROT_BOOT), operator, 2},
		{"subnet of the prefix holding the leaf in main", route(subnet, main, zero, unix.RTPROT_BOOT), operator, 2},
		{"prefix in main at the lowest metric", route(overlay, main, low, unix.RTPROT_BOOT), operator, 2},
		{"prefix in main at the last metric", route(overlay, main, last, unix.RTPROT_BOOT), operator, 2},
		{"shorter route covering the prefix in main", route(cover, main, zero, unix.RTPROT_BOOT), shorter(holdAltMain), 2},
		// the uplink's network holds the overlay prefix whole, so the prefix is a carve-out: running its hold is a throw to main, and
		// down it has no pair, so the leaf goes onto the uplink's link in every state but the live ones
		{"uplink's own network covering the prefix", func(n netnstest.Netlink, family int) error {
			return n.AddAddresses(rulesUplink, holdHost[family].uplinkCover)
		}, [8]string{holdUplinkLink, holdTun, holdUplinkLink, holdUplinkLink, holdUplinkLink, holdUplinkLink, holdTun, holdUplinkLink}, 0},
		{"own table at 1000 ahead of 5100", rule(1000), [8]string{holdAltTable, holdAltTable, holdAltTable, holdAltTable, holdAltTable, holdAltTable, holdAltTable, holdAltTable}, 2},
		{"own table at 6000 behind ranet3's", rule(6000), [8]string{holdAltTable, holdTun, holdRefused, holdAltTable, holdAltTable, holdAltTable, holdTun, holdRefused}, 2},
		{"own table at 32800 behind main", rule(32800), shorter(holdUplink), 2},
		{"BIRD's leaf route in main", route(leaf, main, zero, holdBird), operator, 2},
		{"BIRD's leaf route in the mesh's table", route(leaf, kernel.DefaultTable, zero, holdBird),
			[8]string{holdUplink, holdAltMesh, holdAltMesh, holdRefusedRule, holdUplink, holdRefusedRule, holdAltMesh, holdAltMesh}, 2},
	}
}

// holdRoute adds a route to to through the alternate link's far end in table at metric under proto, in the calling thread's namespace
func holdRoute(n netnstest.Netlink, to netip.Prefix, table, metric uint32, proto uint8) error {
	link, err := net.InterfaceByName(holdAlt)
	if err != nil {
		return err
	}
	family, gateway := byte(unix.AF_INET6), holdHost[6].altFar.Addr()
	if to.Addr().Is4() {
		family, gateway = unix.AF_INET, holdHost[4].altFar.Addr()
	}
	// struct rtmsg of include/uapi/linux/rtnetlink.h, its table in RTA_TABLE
	header := []byte{family, byte(to.Bits()), 0, 0, 0, proto, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()), netnstest.Attr(unix.RTA_GATEWAY, gateway.AsSlice()),
		netnstest.Attr(unix.RTA_OIF, netnstest.U32(uint32(link.Index))), netnstest.Attr(unix.RTA_TABLE, netnstest.U32(table)),
		netnstest.Attr(unix.RTA_PRIORITY, netnstest.U32(metric)))
	if err := n.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		return fmt.Errorf("the route to %s in %d at %d: %w", to, table, metric, err)
	}
	return nil
}

// holdRule adds the operator's rule at priority looking holdTable up to to, under protocol boot, in the calling thread's namespace
func holdRule(n netnstest.Netlink, priority uint32, to netip.Prefix) error {
	family := byte(unix.AF_INET6)
	if to.Addr().Is4() {
		family = unix.AF_INET
	}
	// struct fib_rule_hdr of include/uapi/linux/fib_rules.h, its table in FRA_TABLE
	header := []byte{family, byte(to.Bits()), 0, 0, 0, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	body := slices.Concat(header, netnstest.Attr(unix.FRA_PRIORITY, netnstest.U32(priority)), netnstest.Attr(unix.FRA_DST, to.Addr().AsSlice()),
		netnstest.Attr(unix.FRA_TABLE, netnstest.U32(holdTable)), netnstest.Attr(unix.FRA_PROTOCOL, []byte{unix.RTPROT_BOOT}))
	if err := n.Request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		return fmt.Errorf("the rule at %d to %s: %w", priority, to, err)
	}
	return nil
}

// holdConfig is the rules lab's leaf with the lab's overlay, a prefix of each family holding the leaf's own addresses
func holdConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := rulesConfig(t)
	cfg.Overlay = []schema.Prefix{schema.PrefixFrom(holdHost[4].overlay), schema.PrefixFrom(holdHost[6].overlay)}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the leaf's configuration is refused: %v", err)
	}
	return cfg
}

// holdDaemon is the leaf's node and its reconciler, handed over whole as the command hands it, with the peer the leaf's route goes to
type holdDaemon struct {
	node    *Client
	routes  *kernel.Reconciler
	learned *netstack.Peer
	// end ends the reconciler alone and waits for its last withdrawal, as the daemon's cancel does ahead of the client's stop, and
	// stop ends it and then the node
	end, stop func()
}

// startHoldDaemon starts the leaf's node in leaf's namespace with its state in dir, a session counting as live, the leaf live where
// live is set, and its reconciler
func startHoldDaemon(t *testing.T, leaf *netnstest.Thread, dir string, live bool) *holdDaemon {
	t.Helper()
	cfg := holdConfig(t)
	d := &holdDaemon{}
	if err := leaf.Do(func() (err error) {
		d.node, err = New(cfg, events.New())
		return err
	}); err != nil {
		t.Fatalf("start the leaf: %v", err)
	}
	if err := d.node.SetStateDir(dir); err != nil {
		d.node.Close()
		t.Fatal(err)
	}
	d.learned = netstack.NewPeer("example/peer", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the peer is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(d.learned.Close)
	for _, family := range rulesHost {
		d.node.Mesh.Routes.Set(netip.Prefix{}, family.own, netstack.Assigned)
	}
	d.live(live)
	if err := leaf.Do(func() (err error) {
		rt := d.node.KernelRuntime()
		rt.Sessions = func() int { return 1 }
		d.routes, err = kernel.New(*cfg.ReconcilerTable(), rt, d.node.Mesh.Routes)
		return err
	}); err != nil {
		d.node.Close()
		t.Fatalf("build the reconciler: %v", err)
	}
	d.node.SetReconciler(ReconcilerOf(d.routes))
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	d.end = sync.OnceFunc(func() {
		cancel()
		runs.Wait()
	})
	d.stop = sync.OnceFunc(func() {
		d.end()
		d.node.Close()
	})
	t.Cleanup(d.stop)
	runner := netnstest.JoinThread(t, leaf.Path)
	runs.Go(func() {
		if err := runner.Do(func() error { return d.routes.Run(ctx) }); err != nil {
			t.Errorf("the reconciler: %v", err)
		}
	})
	return d
}

// live puts the leaf's route of each family in the mesh's table, or takes it out
func (d *holdDaemon) live(on bool) {
	for _, family := range []int{4, 6} {
		if on {
			d.node.Mesh.Routes.Set(netip.Prefix{}, holdHost[family].leaf, d.learned)
		} else {
			d.node.Mesh.Routes.Remove(netip.Prefix{}, holdHost[family].leaf)
		}
	}
}

// holdWhere is where ns sends the host's own packet to destination
func holdWhere(t *testing.T, ns *netnstest.Thread, destination netip.Addr) string {
	t.Helper()
	where, err := holdLookup(ns, netip.Addr{}, destination)
	if err != nil {
		t.Fatal(err)
	}
	return where
}

// holdLookup is holdWhere for a packet from source, none where it is the zero address, for a goroutine of a test's own, failing
// with the error of the thread it asks on
func holdLookup(ns *netnstest.Thread, source, destination netip.Addr) (string, error) {
	var route kernel.MatchedRoute
	var err error
	if doErr := ns.Do(func() error { route, err = kernel.RouteGet(source, destination, ""); return nil }); doErr != nil {
		return "", doErr
	}
	return holdAnswer(route, err), nil
}

// holdAnswer names where a lookup's answer sends the packet
func holdAnswer(route kernel.MatchedRoute, err error) string {
	switch {
	case errors.Is(err, unix.EHOSTUNREACH):
		return holdRefused
	case errors.Is(err, unix.ENETUNREACH):
		return holdRefusedRule
	case err != nil:
		return "an error, " + err.Error()
	case route.Type == "unreachable":
		return holdRefused
	case len(route.NextHops) != 1:
		return fmt.Sprintf("%+v", route)
	}
	hop := route.NextHops[0]
	switch {
	case hop.Device == rulesTUN:
		return holdTun
	case hop.Device == holdAlt && route.Table == unix.RT_TABLE_MAIN:
		return holdAltMain
	case hop.Device == holdAlt && route.Table == holdTable:
		return holdAltTable
	case hop.Device == holdAlt && route.Table == kernel.DefaultTable:
		return holdAltMesh
	case hop.Device == rulesUplink && !hop.Gateway.IsValid():
		return holdUplinkLink
	case hop.Device == rulesUplink && route.Prefix.Bits() == 0:
		return holdUplink
	}
	return fmt.Sprintf("%+v", route)
}

// holdRules counts the rules of the down set of the leaf's overlay the leaf holds and the reconciler's rules at 5110, and fails t
// for a rule of the reconciler's at the down set's priorities outside that set
func holdRules(t *testing.T, leaf *netnstest.Thread) (down, overlay int) {
	t.Helper()
	var rules []kernel.DumpedRule
	if err := leaf.Do(func() (err error) { rules, err = kernel.DumpRules(); return err }); err != nil {
		t.Fatalf("read the leaf's rules: %v", err)
	}
	set := kerneltest.DownSet([]schema.Prefix{schema.PrefixFrom(holdHost[4].overlay), schema.PrefixFrom(holdHost[6].overlay)})
	for _, rule := range rules {
		switch {
		case slices.Contains(set, rule):
			down++
		case rule.Protocol == kernel.DefaultProtocol && (rule.Priority == 32764 || rule.Priority == 32765):
			t.Errorf("the leaf holds the rule %+v at a priority of the down set outside it", rule)
		case rule.Protocol == kernel.DefaultProtocol && rule.Priority == 5110:
			overlay++
		}
	}
	return down, overlay
}

// holdOperator lists what the form wrote that the leaf still holds: its routes in main, the operator's table and the mesh's of a
// protocol other than the reconciler's and of a destination the form names, and its rules looking the operator's table up
func holdOperator(t *testing.T, leaf *netnstest.Thread) []string {
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
		t.Fatalf("read the leaf back: %v", err)
	}
	var named []netip.Prefix
	for _, host := range holdHost {
		named = append(named, host.overlay, host.leaf, host.subnet, host.cover, host.uplinkCover.Masked())
	}
	var out []string
	for _, route := range routes {
		if route.protocol != kernel.DefaultProtocol && slices.Contains(named, route.destination) {
			out = append(out, "route "+route.String())
		}
	}
	for _, rule := range rules {
		if rule.table == holdTable {
			out = append(out, "rule "+rule.String())
		}
	}
	slices.Sort(out)
	return out
}

// The leaf's own packet to a leaf of the mesh, beside each form of an operator's route, in each state of the node: before ranet3,
// running with the leaf live and retracted, down, down with its reconciler disabled, after a clean stop, restarted and killed. Down
// and stopped, each overlay prefix's two rules ahead of main let an operator's route of main as long as the prefix or longer, and
// every rule ahead of main, answer, and refuse the rest, a shorter route of main and its default among them, and disable reconciler
// takes them. A prefix the uplink's own network holds whole has no such rules, and the leaf goes onto that link as it does running. Running, restarted and killed, the node holds what it held before them. In every state the destination outside the
// overlay leaves by the uplink's default and every route and rule the form wrote stays. Between the stop and the pass of the restart
// that puts 5110 back, the leaf's lookup with no source and from the uplink's address ends in the tun, a refusal, or where the form
// sends it running live or stopped, which is a route of main as long as the prefix or a rule ahead of main. That window is sampled
// without a pause and caught a reverted order in some runs alone, each time by a single read, so it guards no order: the fake
// kernel's tests of a stop's and a start's writes in internal/kernel do.
func TestNodeGoingDownHoldsTheOverlayAgainstEachOperatorRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	for _, form := range holdForms() {
		t.Run(form.name, func(t *testing.T) {
			leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
			rulesUplinkPair(t, leaf, far)
			vethHost(t, leaf, holdAlt, holdAltFar, [2][2]netip.Prefix{{holdHost[4].alt, holdHost[6].alt}, {holdHost[4].altFar, holdHost[6].altFar}})
			if form.write != nil {
				if err := leaf.Do(func() error {
					n, err := netnstest.OpenNetlink()
					if err != nil {
						return err
					}
					defer n.Close()
					return errors.Join(form.write(n, 4), form.write(n, 6))
				}); err != nil {
					t.Fatalf("write the form: %v", err)
				}
			}
			written := holdOperator(t, leaf)
			read := func(state int, down int) {
				t.Helper()
				for _, family := range []int{4, 6} {
					if got := holdWhere(t, leaf, holdHost[family].leaf.Addr()); got != form.want[state] {
						t.Errorf("%s, IPv%d: the leaf %s, want %s", holdStates[state], family, got, form.want[state])
					}
					if got := holdWhere(t, leaf, holdHost[family].unrelated); got != holdUplink {
						t.Errorf("%s, IPv%d: the destination outside the overlay %s, want %s", holdStates[state], family, got, holdUplink)
					}
				}
				if got, _ := holdRules(t, leaf); got != down {
					t.Errorf("%s: the leaf holds %d rules of the down set, want %d", holdStates[state], got, down)
				}
				if got := holdOperator(t, leaf); !slices.Equal(got, written) {
					t.Errorf("%s: the form's routes and rules are %v, want %v", holdStates[state], got, written)
				}
			}
			read(0, 0)

			d := startHoldDaemon(t, leaf, filepath.Join(t.TempDir(), "running"), true)
			settle := func(d *holdDaemon, what string, done func() bool) {
				t.Helper()
				waitFor(t, convergeBudget, what, func() bool { return !d.routes.Stats().At.IsZero() && done() })
			}
			settle(d, "the leaf live", func() bool {
				down, overlay := holdRules(t, leaf)
				return down == 0 && overlay == 2 && holdLive(t, leaf, form)
			})
			read(1, 0)
			d.live(false)
			settle(d, "the leaf retracted", func() bool { return !holdInstalled(t, leaf) })
			read(2, 0)
			if _, err := d.node.Down(context.Background()); err != nil {
				t.Fatal(err)
			}
			// the status takes the withdrawal's count once it has ended, after its writes
			settle(d, "the down set in place", func() bool {
				down, overlay := holdRules(t, leaf)
				return down == 2*form.held && overlay == 0 && d.node.Status().Kernel.Held == form.held
			})
			var line strings.Builder
			control.RenderStatus(&line, d.node.Status())
			// a count of none prints nothing
			if says := strings.Contains(line.String(), fmt.Sprintf(", %d refused while down", form.held)); says != (form.held > 0) ||
				form.held == 0 && strings.Contains(line.String(), "refused while down") {
				t.Errorf("down: the status of %d overlay prefixes refused reads:\n%s", form.held, line.String())
			}
			read(3, 2*form.held)
			if _, err := d.node.SetSubsystem(context.Background(), control.SubsystemReconciler, false); err != nil {
				t.Fatal(err)
			}
			settle(d, "the down set gone", func() bool { down, _ := holdRules(t, leaf); return down == 0 })
			read(4, 0)
			d.stop()

			d = startHoldDaemon(t, leaf, filepath.Join(t.TempDir(), "stopped"), true)
			settle(d, "the leaf live again", func() bool {
				down, overlay := holdRules(t, leaf)
				return down == 0 && overlay == 2 && holdLive(t, leaf, form)
			})
			// the leaf's lookup from the stop until the restart's pass put 5110 back, read without a pause on a thread of its own, with
			// each answer outside what the window allows counted as a leak
			allowed := []string{holdTun, holdRefused, holdRefusedRule, form.want[1], form.want[5]}
			sampler := netnstest.JoinThread(t, leaf.Path)
			var sampling atomic.Bool
			var samples atomic.Int64
			var leaks sync.Map
			var sampleErr atomic.Value
			sampled := make(chan struct{})
			sampling.Store(true)
			window := time.Now()
			go func() {
				defer close(sampled)
				for sampling.Load() {
					for _, family := range []int{4, 6} {
						for _, source := range []netip.Addr{{}, rulesHost[family].uplink.Addr()} {
							where, err := holdLookup(sampler, source, holdHost[family].leaf.Addr())
							if err != nil {
								sampleErr.Store(err)
								return
							}
							samples.Add(1)
							if !slices.Contains(allowed, where) {
								n, _ := leaks.LoadOrStore(fmt.Sprintf("IPv%d from %v %s", family, source, where), new(atomic.Int64))
								n.(*atomic.Int64).Add(1)
							}
						}
					}
				}
			}()
			d.stop()
			read(5, 2*form.held)
			d = startHoldDaemon(t, leaf, filepath.Join(t.TempDir(), "restarted"), true)
			settle(d, "the restart's leaf live", func() bool {
				down, overlay := holdRules(t, leaf)
				return down == 0 && overlay == 2 && holdLive(t, leaf, form)
			})
			sampling.Store(false)
			<-sampled
			if err, _ := sampleErr.Load().(error); err != nil {
				t.Fatalf("read the leaf between the stop and the restart: %v", err)
			}
			length := time.Since(window)
			t.Logf("the leaf read %d times in the %s between the stop and the restart's pass, %.0f a second", samples.Load(), length, float64(samples.Load())/length.Seconds())
			leaks.Range(func(where, n any) bool {
				t.Errorf("between the stop and the restart's pass the leaf, %s, %d of %d times", where, n.(*atomic.Int64).Load(), samples.Load())
				return true
			})
			read(6, 0)
			d.stop()

			ready := filepath.Join(t.TempDir(), "ready")
			kill := startExitHelper(t, leaf, "TestNodeGoingDownHoldsTheOverlayCrashHelper", holdHelperReady+"="+ready)
			waitFor(t, convergeBudget, "the crash helper's first pass to take the down set", func() bool {
				_, err := os.Stat(ready)
				return err == nil
			})
			kill()
			waitFor(t, convergeBudget, "the tun to go with the helper", func() bool { _, err := holdTunIndex(leaf); return err != nil })
			if _, overlay := holdRules(t, leaf); overlay != 2 {
				t.Errorf("killed: the leaf holds %d rules at 5110, want the 2 the helper left", overlay)
			}
			read(7, 0)
		})
	}
}

// A node whose uplink's own network holds an overlay prefix whole reaches its neighbor inside that prefix on the uplink's link, in
// both families, before ranet3, running, after ranet3 down and after a clean stop: the down set leaves such a prefix out, so its
// addresses go onto the link while down as they do while the node runs
func TestNodeGoingDownReachesItsNeighborInsideAPrefixItsUplinkHoldsWhole(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	address := func(ns *netnstest.Thread, link string, prefixes ...netip.Prefix) {
		t.Helper()
		if err := ns.Do(func() error {
			n, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer n.Close()
			return n.AddAddresses(link, prefixes...)
		}); err != nil {
			t.Fatalf("address %s: %v", link, err)
		}
	}
	address(leaf, rulesUplink, holdHost[4].uplinkCover, holdHost[6].uplinkCover)
	address(far, rulesFar, holdNeighbor[4], holdNeighbor[6])
	for _, family := range []int{4, 6} {
		var listener net.Listener
		if err := far.Do(func() (err error) {
			listener, err = net.Listen("tcp", netip.AddrPortFrom(holdNeighbor[family].Addr(), holdNeighborPort).String())
			return err
		}); err != nil {
			t.Fatalf("the neighbor's listener: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}
	reach := func(state string) {
		t.Helper()
		for _, family := range []int{4, 6} {
			to := netip.AddrPortFrom(holdNeighbor[family].Addr(), holdNeighborPort).String()
			var err error
			if doErr := leaf.Do(func() error {
				var conn net.Conn
				if conn, err = net.DialTimeout("tcp", to, holdDialWait); err == nil {
					_ = conn.Close()
				}
				return nil
			}); doErr != nil {
				t.Fatal(doErr)
			}
			if err != nil {
				t.Errorf("%s, IPv%d: the neighbor at %s does not answer: %v", state, family, to, err)
			}
		}
	}
	reach("before ranet3")
	d := startHoldDaemon(t, leaf, filepath.Join(t.TempDir(), "running"), true)
	waitFor(t, convergeBudget, "the leaf running", func() bool {
		_, overlay := holdRules(t, leaf)
		return !d.routes.Stats().At.IsZero() && overlay == 2 && holdInstalled(t, leaf)
	})
	reach("running")
	if _, err := d.node.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the down's withdrawal", func() bool {
		_, overlay := holdRules(t, leaf)
		return overlay == 0 && !holdInstalled(t, leaf)
	})
	if down, _ := holdRules(t, leaf); down != 0 {
		t.Errorf("down: the leaf holds %d rules of the down set, want none", down)
	}
	reach("down")
	d.stop()
	reach("stopped")
}

// holdLive reports whether the reconciler holds the leaf's routes and the leaf's lookup ends where the form's running live column
// says, out of the tun, by BIRD's route or by the operator's table ahead of 5110. BIRD's route in the mesh's table holds the key the
// reconciler's would, which it leaves alone
func holdLive(t *testing.T, leaf *netnstest.Thread, form holdForm) bool {
	t.Helper()
	return (form.want[1] == holdAltMesh || holdInstalled(t, leaf)) && holdWhere(t, leaf, holdHost[4].leaf.Addr()) == form.want[1] &&
		holdWhere(t, leaf, holdHost[6].leaf.Addr()) == form.want[1]
}

// holdInstalled reports whether the reconciler holds a route to the leaf of either family
func holdInstalled(t *testing.T, leaf *netnstest.Thread) bool {
	t.Helper()
	var routes []kernelRoute
	if err := leaf.Do(func() (err error) { routes, err = dumpRoutes(); return err }); err != nil {
		t.Fatalf("read the leaf's routes: %v", err)
	}
	return slices.ContainsFunc(routes, func(route kernelRoute) bool {
		return route.protocol == kernel.DefaultProtocol && (route.destination == holdHost[4].leaf || route.destination == holdHost[6].leaf)
	})
}

// holdTunIndex is the index of the leaf's tun, an error where it holds none
func holdTunIndex(leaf *netnstest.Thread) (int, error) {
	var index int
	err := leaf.Do(func() error {
		link, err := net.InterfaceByName(rulesTUN)
		if err != nil {
			return err
		}
		index = link.Index
		return nil
	})
	return index, err
}

// the lab's crash helper, which runs the leaf's node and its reconciler with the leaf live in the namespace exitHelperNamespace
// names, writes the file holdHelperReady names once its first pass took the down set the lab's stop left, and runs until it is
// killed. Run without them, as the netlink check's run of its lab's pattern runs it, it passes at once.
func TestNodeGoingDownHoldsTheOverlayCrashHelper(t *testing.T) {
	path, ready := os.Getenv(exitHelperNamespace), os.Getenv(holdHelperReady)
	if path == "" || ready == "" {
		return
	}
	leaf := netnstest.JoinThread(t, path)
	d := startHoldDaemon(t, leaf, t.TempDir(), true)
	waitFor(t, convergeBudget, "the first pass to take the down set", func() bool {
		stats := d.routes.Stats()
		return !stats.At.IsZero() && stats.Err == "" && stats.Held == 0
	})
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// A reload that reaches the reconciler after its last withdrawal, as one racing the daemon's stop does when it took the client's
// lock before the stop began there, is refused with the reconciler's stop, so the node keeps the overlay whose down set the
// withdrawal left, and the kernel holds that down set and no rule of the reload's
func TestReloadAfterTheReconcilersLastWithdrawalIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	d := startHoldDaemon(t, leaf, filepath.Join(t.TempDir(), "running"), true)
	waitFor(t, convergeBudget, "the leaf running", func() bool {
		down, overlay := holdRules(t, leaf)
		return !d.routes.Stats().At.IsZero() && down == 0 && overlay == 2
	})
	running := d.node.config().Overlay
	d.end()
	if down, overlay := holdRules(t, leaf); down != 4 || overlay != 0 {
		t.Fatalf("the last withdrawal left %d rules of the down set and %d of 5110, want 4 and none", down, overlay)
	}
	next := *d.node.config()
	next.Overlay = append(slices.Clone(running), schema.MustPrefix("10.99.0.0/16"))
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, &next)
	err := leaf.Do(func() error { return d.node.ReloadFrom(path) })
	if !errors.Is(err, kernel.ErrStopping) {
		t.Errorf("the reload after the last withdrawal was answered %v, want %v", err, kernel.ErrStopping)
	}
	if got := d.node.config().Overlay; !slices.Equal(got, running) {
		t.Errorf("after the reload the node holds the overlay %v, want %v", got, running)
	}
	if down, _ := holdRules(t, leaf); down != 4 {
		t.Errorf("after the reload the kernel holds %d rules of the running overlay's down set, want 4", down)
	}
}
