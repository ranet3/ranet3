// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// A start with no reconciler finds the down set an earlier instance left under the default protocol in the kernel's own dump, in a
// namespace of its own, and warns once naming each of its rules with the command that deletes it, and not the same set under
// another protocol or a rule of another shape, and leaves every rule there
func TestStartWithNoReconcilerWarnsOfTheDownSetLeft(t *testing.T) {
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ours := &netlinkPlatform{table: Table{ID: DefaultTable, Proto: DefaultProtocol}, conn: conn}
	another := &netlinkPlatform{table: Table{ID: DefaultTable, Proto: 99}, conn: conn}
	for _, rule := range downRules(downOverlay) {
		if err := ours.AddRule(rule); err != nil {
			t.Fatalf("add %s: %v", rule, err)
		}
		if err := another.AddRule(rule); err != nil {
			t.Fatalf("add %s under another protocol: %v", rule, err)
		}
	}
	// a rule at the refusal's priority that looks a table up, which no stop writes
	other := Rule{Family: FamilyIPv4, Priority: priorityDownRefused, To: schema.PrefixFrom(prefix("198.51.100.0/24")), Table: 300}
	if err := ours.AddRule(other); err != nil {
		t.Fatalf("add %s: %v", other, err)
	}
	before, err := DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	said := logged(t)
	WarnHeldOverlay(downOverlay)
	text := said.String()
	if n := strings.Count(text, downWarning); n != 1 {
		t.Errorf("the start warned %d times, want once:\n%s", n, text)
	}
	for _, want := range downWarned {
		if !strings.Contains(text, want) {
			t.Errorf("the warning does not name %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "198.51.100.0/24") || strings.Contains(text, "protocol 99") {
		t.Errorf("the warning names a rule outside the down set:\n%s", text)
	}
	after, err := DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(after, before) {
		t.Errorf("the start changed the rules from %+v to %+v", before, after)
	}
}

// A stop through a real kernel leaves the down set under the reconciler's own protocol, which the fake's rules do not carry, as the
// only rules of that protocol, so a start of the same protocol lists and deletes them
func TestNetlinkStopLeavesTheDownSetUnderItsProtocol(t *testing.T) {
	const device = "ranetdown0"
	plat := rootRulePlatform(t, device)
	tbl, rt := platformFor(device)
	rt.Overlay = downOverlay
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, prefix("192.0.2.7/32"), nil)
	routes.Set(netip.Prefix{}, prefix("3fff::7/128"), nil)
	r := newReconciler(tbl.Normalized(), rt, nil, routes, plat)
	// the tun is down, so the pass's routes fail, and the stop takes the rules the pass added
	_ = r.reconcile()
	if got := r.DerivedRules(); len(got) == 0 {
		t.Fatal("the pass derived no rules, so the stop proves nothing")
	}
	if err := r.withdraw(errStopped); err != nil {
		t.Fatal(err)
	}
	dumped, err := DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	var ours []DumpedRule
	for _, rule := range dumped {
		if rule.Protocol == DefaultProtocol {
			ours = append(ours, rule)
		}
	}
	want := dumpedDown(downOverlay, DefaultProtocol)
	if !sameRules(ours, want) {
		t.Errorf("the stop left the rules %+v under protocol %d, want the down set %+v", ours, DefaultProtocol, want)
	}
}

// walkingKernel is the recording fake handing each write it took to after, once the write is done, and main is the routes main
// holds beside its default and the links' networks
type walkingKernel struct {
	*recordingKernel
	after func(write string)
	main  []netip.Prefix
}

func (k *walkingKernel) wrote(write string, err error) error {
	if k.after != nil {
		if err != nil {
			write += " (failed)"
		}
		k.after(write)
	}
	return err
}

func (k *walkingKernel) AddRule(rule Rule) error {
	return k.wrote("add rule "+rule.String(), k.recordingKernel.AddRule(rule))
}

func (k *walkingKernel) DelRule(rule Rule) error {
	return k.wrote("delete rule "+rule.String(), k.recordingKernel.DelRule(rule))
}

func (k *walkingKernel) AddRoute(route Route) error {
	return k.wrote("add route "+route.String(), k.recordingKernel.AddRoute(route))
}

func (k *walkingKernel) DelRoute(route Route) error {
	return k.wrote("delete route "+route.String(), k.recordingKernel.DelRoute(route))
}

// walkEnd is where the host's own lookup of to ends as the fake's rules and routes stand, with main's rule at 32766, main holding a
// default, k's main and the network of each link of network but lo, and the mesh's table as the fake holds it, each route of it
// leaving by the tun at its own destination. Rules of one priority go in the order they were added, those the fake held before any
// add first, as the kernel puts a new rule after each of its priority.
func (k *walkingKernel) walkEnd(network NetworkState, mesh schema.TableID, to netip.Addr) string {
	host := fib{tables: map[schema.TableID][]fibRoute{}}
	order := map[Rule]int{}
	k.mu.Lock()
	for i, rule := range k.ruleAdded {
		order[rule] = i + 1
	}
	for rule := range k.rules {
		host.rules = append(host.rules, rule)
	}
	for route := range k.routes {
		host.tables[mesh] = append(host.tables[mesh], fibRoute{destination: route.Destination, source: route.Source, metric: route.Metric,
			device: "tun:" + route.Destination.String(), throw: route.Throw, unreachable: route.Unreachable})
	}
	k.mu.Unlock()
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		host.rules = append(host.rules, Rule{Family: family, Priority: 32766, Table: schema.TableMain})
	}
	slices.SortFunc(host.rules, func(a, b Rule) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), cmp.Compare(order[a], order[b]), strings.Compare(a.String(), b.String()))
	})
	host.tables[schema.TableMain] = []fibRoute{{destination: prefix("0.0.0.0/0"), device: "main's default"}, {destination: prefix("::/0"), device: "main's default"}}
	for _, route := range k.main {
		host.tables[schema.TableMain] = append(host.tables[schema.TableMain], fibRoute{destination: route, device: "main:" + route.String()})
	}
	for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
		if link.Name == Loopback {
			continue
		}
		for _, address := range slices.Concat(link.Prefixes, link.Peers) {
			host.tables[schema.TableMain] = append(host.tables[schema.TableMain], fibRoute{destination: address.Masked(), device: "link:" + link.Name})
		}
	}
	return host.walk(fibPacket{destination: to})
}

// Where one write of a down pair fails, alone or in a pass whose route listing fails too, no write of a stop of a running node, of
// disable reconciler, of the stopped pass of a Run that takes a reload, of a start that stages or of a stop of the daemon, each
// narrowing an overlay prefix inside the old one or widening it over the old one where it reloads, sends an address that a prefix
// holds before and after it by a route of main shorter than that prefix, rules of one priority walked in the order they were added.
// Only main's lookup of an old prefix whose delete failed answers as it did before. Once the faults clear, the same act leaves the
// down set of the overlay in force, and none after disable reconciler.
func TestDownPairWriteThatFailsSendsNoHeldAddressByAShorterRouteOfMain(t *testing.T) {
	busy := errors.New("netlink says no")
	wide, narrow, beside, six := prefix("192.0.2.0/24"), prefix("192.0.2.0/26"), prefix("192.0.2.128/26"), prefix("3fff::/21")
	walked := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("3fff::1")}
	for _, s := range []struct {
		what            string
		before, overlay []schema.Prefix
		running         bool
		act             string
	}{
		{"a stop of a running node", prefixes(narrow, six), prefixes(narrow, six), true, "stop"},
		{"disable reconciler", prefixes(narrow, six), prefixes(narrow, six), false, "disable"},
		{"a reload while stopped narrowing", prefixes(wide), prefixes(narrow), false, "reload"},
		{"a reload while stopped widening", prefixes(beside), prefixes(wide), false, "reload"},
		{"a start that stages narrowing", prefixes(wide), prefixes(narrow), false, "pass"},
		{"a start that stages widening", prefixes(beside), prefixes(wide), false, "pass"},
		{"a start that stages narrowing beside an IPv6 pair", prefixes(wide, six), prefixes(narrow, six), false, "pass"},
		{"a stop of the daemon narrowing", prefixes(wide), prefixes(narrow), false, "shutdown"},
		{"a stop of the daemon widening", prefixes(beside), prefixes(wide), false, "shutdown"},
	} {
		seeded, held := downRules(s.before), s.overlay
		if s.running {
			seeded = nil
		}
		if s.act == "disable" {
			held = nil
		}
		// the writes of the old pairs and of the new ones, each failed in a row of its own
		var writes []Rule
		for _, rule := range seeded {
			if !slices.Contains(downRules(held), rule) {
				writes = append(writes, rule)
			}
		}
		for _, rule := range downRules(held) {
			if !slices.Contains(seeded, rule) {
				writes = append(writes, rule)
			}
		}
		for _, failing := range append([]Rule{{}}, writes...) {
			deleting := slices.Contains(seeded, failing)
			for _, blind := range []bool{false, true} {
				name := s.what + ", every write answering"
				if failing.To.IsValid() {
					name = s.what + ", " + map[bool]string{false: "add", true: "delete"}[deleting] + " of " + failing.String() + " failing"
				}
				if blind {
					name += ", the route listing failing"
				}
				t.Run(name, func(t *testing.T) {
					k := &walkingKernel{recordingKernel: newRecording(t), main: []netip.Prefix{prefix("192.0.2.0/25"), prefix("3fff::/20")}}
					tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
					overlay := s.overlay
					if s.act == "reload" {
						overlay = s.before
					}
					r := newReconciler(tbl, Runtime{Interface: "ranet0", Overlay: overlay}, nil, downTable(), k)
					for _, rule := range seeded {
						k.rules[rule] = true
					}
					if s.running {
						if err := r.reconcile(); err != nil {
							t.Fatalf("the running pass: %v", err)
						}
					}
					// stale is the old prefix whose lookup of main a failed delete leaves
					var stale []netip.Prefix
					if deleting && failing.Priority == priorityDownMain {
						stale = append(stale, failing.To.Prefix)
					}
					// least is the length a route of main needs to answer to with, where a prefix held before and after the act
					// holds to: that of the shortest such prefix, or of the stale one
					least := func(to netip.Addr) (int, bool) {
						holds := func(p schema.Prefix) bool { return p.Prefix.Contains(to) }
						if !slices.ContainsFunc(held, holds) || !slices.ContainsFunc(s.before, holds) {
							return 0, false
						}
						bits := to.BitLen()
						for _, p := range slices.Concat(SchemaPrefixes(held), stale) {
							if p.Contains(to) {
								bits = min(bits, p.Bits())
							}
						}
						return bits, true
					}
					var trail []string
					check := func(at string) {
						for _, to := range walked {
							end := k.walkEnd(NetworkState{}, tbl.ID, to)
							trail = append(trail, at+": "+to.String()+" ends at "+end)
							length := 0
							switch {
							case strings.HasPrefix(end, "main:"):
								length = netip.MustParsePrefix(strings.TrimPrefix(end, "main:")).Bits()
							case end != "main's default":
								continue
							}
							if bits, refused := least(to); refused && length < bits {
								t.Errorf("%s: %s ends at %s, shorter than the /%d that holds it", at, to, end, bits)
							}
						}
					}
					act := func() error {
						switch s.act {
						case "disable":
							r.DropHold()
							return r.withdraw(errStopped)
						case "pass":
							return r.reconcile()
						case "shutdown":
							cause := errors.New("the daemon stops")
							return errors.Join(r.withdraw(cause), r.mendDownSet(cause))
						}
						return r.withdraw(errStopped)
					}
					arm := func() {
						del := map[Rule]error{}
						if failing.To.IsValid() && deleting {
							del[failing] = busy
						}
						if failing.To.IsValid() && !deleting {
							k.mu.Lock()
							k.failAddRule[failing] = busy
							k.mu.Unlock()
						}
						var routes error
						if blind {
							routes = busy
						}
						k.failing(routes, nil, del)
					}
					clear := func() {
						k.mu.Lock()
						delete(k.failAddRule, failing)
						k.mu.Unlock()
						k.failing(nil, nil, nil)
					}
					judge := func(err error) {
						if (failing.To.IsValid() || blind) && err == nil {
							t.Error("the act failed a write and returned no error")
						}
						if failing.To.IsValid() && s.act != "pass" && (err == nil || !strings.Contains(err.Error(), leftText(failing.Family))) {
							t.Errorf("the act returned %v, want it to say the %s routes and rules are left", err, failing.Family)
						}
						if failing.To.IsValid() && s.act != "pass" && (err == nil || !strings.Contains(err.Error(), failing.String())) {
							t.Errorf("the act returned %v, want it to name the failed write of %s", err, failing)
						}
					}
					k.after = check
					if s.act == "reload" {
						// a Run started stopped runs its first stopped pass and no other until the reload wakes it, so the pass after
						// that one is the reload's, and it runs again on its retry while a write fails
						r.enabled.Store(false)
						ctx, cancel := context.WithCancelCause(context.Background())
						done := make(chan error, 1)
						go func() { done <- r.Run(ctx) }()
						end := sync.OnceFunc(func() { cancel(nil); <-done })
						t.Cleanup(end)
						<-r.FirstPass()
						waitFor(t, func() bool { return !r.Stats().At.IsZero() })
						at := r.Stats().At
						arm()
						if err := r.SetTable(r.Table(), s.overlay, nil); err != nil {
							t.Fatal(err)
						}
						var err error
						if got := passAfter(t, r, at).Err; got != "" {
							err = errors.New(got)
						}
						judge(err)
						clear()
						// a wake runs the next stopped pass at once, ahead of the retry's timer, and it finds no fault
						at = r.Stats().At
						r.SetEnabled(false)
						passAfter(t, r, at)
						waitFor(t, func() bool { return k.holds(downRules(held)) && r.Stats().Err == "" })
						end()
						check("at the end once the faults clear")
					} else {
						arm()
						err := act()
						check("at the end")
						judge(err)
						clear()
						err = act()
						check("at the end once the faults clear")
						if s.act != "pass" && (err != nil || !k.holds(downRules(held))) {
							t.Errorf("once the faults clear the act returned %v and left %v, want the down set %v", err, k.rules, downRules(held))
						}
					}
					k.after = nil
					if t.Failed() {
						t.Log(strings.Join(trail, "\n"))
					}
				})
			}
		}
	}
}

// A staged start's pass that deletes the mesh's own route at an overlay prefix, on which the start kept that prefix's 5110, deletes
// that 5110 first, so beside an exit's default in the mesh's table no lookup to the prefix goes into the mesh by the default, or
// leaves by main's, after any write of the pass, in both families: where the prefix's hold cannot be added, also where that pass
// cannot list the rules, which leaves the route's delete to a pass that can, and where the carve-out that equals the prefix goes
// with the route. Where the carve-out stays, its throw takes the route's place.
func TestStagedStartDeletesA5110AheadOfTheMeshsRouteItRestsOn(t *testing.T) {
	busy := errors.New("netlink says no")
	whole := []netip.Prefix{prefix("192.0.2.0/25"), prefix("3fff::/21")}
	at := map[netip.Addr]netip.Prefix{}
	for _, to := range []string{"192.0.2.1", "192.0.2.126", "3fff::1", "3fff:7ff:ffff::1"} {
		address := netip.MustParseAddr(to)
		at[address] = whole[slices.IndexFunc(whole, func(p netip.Prefix) bool { return p.Contains(address) })]
	}
	for _, c := range []struct {
		what                          string
		carved, lost, failHold, blind bool
	}{
		{"a prefix whose hold cannot be added", false, false, true, false},
		{"a prefix whose hold cannot be added, the rules unlisted at the route's delete", false, false, true, true},
		{"a prefix a carve-out equals, the carve-out lost with the route", true, true, false, false},
		{"a prefix a carve-out equals, the carve-out kept", true, false, false, false},
	} {
		t.Run(c.what, func(t *testing.T) {
			table := netstack.NewRouteTable()
			for _, p := range []string{"0.0.0.0/0", "::/0", "192.0.2.0/25", "3fff::/21"} {
				table.Set(netip.Prefix{}, prefix(p), nil)
			}
			network := new(atomic.Pointer[NetworkState])
			network.Store(&NetworkState{})
			held := carvedOverlay
			if c.carved {
				network.Store(&carvedNetwork)
				held = carvedHeld
			}
			k := &walkingKernel{recordingKernel: newRecording(t)}
			tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
			rt := Runtime{Interface: "ranet0", Overlay: carvedOverlay, Network: func() NetworkState { return *network.Load() }}
			r := newReconciler(tbl, rt, nil, table, k)
			for _, rule := range downRules(held) {
				k.rules[rule] = true
			}
			// the start stays staged, by the holds it cannot add or else by the release's first add
			k.mu.Lock()
			if c.failHold {
				for _, p := range whole {
					k.failAdd[Route{Destination: p, Metric: holdMetric, Unreachable: true}] = busy
				}
			} else {
				k.failAddRule[main5410(FamilyIPv4)] = busy
			}
			k.mu.Unlock()
			_ = r.reconcile()
			for _, p := range whole {
				if lookup := (Rule{Family: familyOf(p.Addr()), Priority: priorityOverlay, To: schema.PrefixFrom(p), Table: tbl.ID}); !k.holdsAll([]Rule{lookup}) {
					t.Fatalf("the start staged no %s on the mesh's route there: %v", lookup, k.rules)
				}
			}
			k.after = func(write string) {
				now := *network.Load()
				for _, to := range slices.SortedFunc(maps.Keys(at), netip.Addr.Compare) {
					end := k.walkEnd(now, tbl.ID, to)
					route, viaTun := strings.CutPrefix(end, "tun:")
					if end == "main's default" || viaTun && netip.MustParsePrefix(route).Bits() < at[to].Bits() {
						t.Errorf("after %s the lookup of %s ends at %s", write, to, end)
					}
				}
			}
			for _, p := range whole {
				table.Remove(netip.Prefix{}, p)
			}
			if c.lost {
				network.Store(&NetworkState{})
			}
			if c.blind {
				k.failing(nil, busy, nil)
				_ = r.reconcile()
				k.failing(nil, nil, nil)
			}
			_ = r.reconcile()
			k.after = nil
			for _, p := range whole {
				mesh := Route{Destination: p, Metric: routeMetric(p, false)}
				if !slices.ContainsFunc(k.taken(), func(w kernelWrite) bool { return w.op == "delete route" && w.route == mesh }) {
					t.Errorf("the start never deleted the mesh's route %s", mesh)
				}
			}
		})
	}
}

// The throw at an overlay prefix of host length that cap.table assigns and the uplink's network holds whole, on a real kernel in a
// namespace of its own, beside a mesh's table that holds an exit's default and then none, in both families: while the tun holds the
// address the local table answers its lookup, and with the address off the tun, another address of the tun's keeping the mesh's
// routes through it, the lookup goes past the mesh's table to main's route for the uplink's network, where without the throw it
// would follow the exit's default into the mesh
func TestNetlinkLookupOfAnAssignedAddressAnUplinkHoldsMeetsTheUplink(t *testing.T) {
	plat := rootRulePlatform(t, stagedMesh)
	for _, path := range []string{"ipv6/conf/all/accept_dad", "ipv6/conf/default/accept_dad"} {
		writeBatchSysctl(t, path, "0")
	}
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createLink(conn, "up0", "dummy"); err != nil {
		t.Fatalf("make up0: %v", err)
	}
	for _, name := range []string{"lo", stagedMesh, "up0"} {
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
	}
	up, err := conn.link(0, "up0")
	if err != nil {
		t.Fatalf("look up up0: %v", err)
	}
	var network NetworkState
	for i, address := range []netip.Prefix{prefix("192.0.2.130/24"), prefix("3fff:800::10/20")} {
		writeBatchAddress(t, conn, up.index, address)
		family := &network.IPv4
		if i == 1 {
			family = &network.IPv6
		}
		family.Links = append(family.Links, Link{Name: "up0", Prefixes: []netip.Prefix{address}})
		family.Addresses = append(family.Addresses, address.Addr())
	}
	for destination, gateway := range map[string]string{"0.0.0.0/0": "192.0.2.1", "::/0": "3fff:800::1"} {
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix(destination), batchHop{index: up.index, gateway: netip.MustParseAddr(gateway)})
	}
	network.IPv4.Default = DefaultRoute{Interface: "up0", Gateway: netip.MustParseAddr("192.0.2.1")}
	network.IPv6.Default = DefaultRoute{Interface: "up0", Gateway: netip.MustParseAddr("3fff:800::1")}
	assigned := []netip.Prefix{prefix("192.0.2.5/32"), prefix("3fff::5/128")}
	// the tun's other addresses, which keep the mesh's routes through it in each family once an assigned one is off
	others := []netip.Prefix{prefix("203.0.113.9/32"), prefix("2001:db8:1::9/128")}
	tbl, rt := platformFor(stagedMesh)
	rt.Overlay = prefixes(append(slices.Clone(assigned), prefix("203.0.113.0/24"), prefix("2001:db8:1::/48"))...)
	rt.Network = func() NetworkState { return network }
	tbl.Addresses = prefixes(slices.Concat(assigned, others)...)
	tbl = tbl.WithMode(&ExitMode{Fallback: FallbackUplink}).Normalized()
	routes := netstack.NewRouteTable()
	for _, p := range slices.Concat(assigned, others) {
		routes.Set(netip.Prefix{}, p, netstack.Assigned)
	}
	defaults := []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0")}
	for _, p := range defaults {
		routes.Set(netip.Prefix{}, p, nil)
	}
	r := newReconciler(tbl, rt, tbl.Assigned(nil), routes, plat)
	settle := func(state string) {
		var err error
		for range 3 {
			if err = r.reconcile(); err == nil {
				return
			}
		}
		t.Fatalf("%s: the pass fails: %v", state, err)
	}
	answer := func(to netip.Addr) string {
		route, indexes, err := matchedRoute(conn, netip.Addr{}, to, 0, 0, 0)
		switch {
		case err != nil:
			return "error " + err.Error()
		case route.Table == unix.RT_TABLE_LOCAL:
			return "local"
		case len(indexes) == 0:
			return "no hop"
		}
		hop, err := conn.link(indexes[0], "")
		if err != nil {
			return "error " + err.Error()
		}
		return "dev " + hop.name
	}
	check := func(state, want string) {
		for _, p := range assigned {
			got := answer(p.Addr())
			t.Logf("%s: %s answers %s", state, p.Addr(), got)
			if got != want {
				t.Errorf("%s: the lookup of %s answers %s, want %s", state, p.Addr(), got, want)
			}
		}
	}
	off := func() {
		for _, p := range assigned {
			if err := plat.DelAddr(p); err != nil {
				t.Fatalf("take %s off the tun: %v", p, err)
			}
		}
	}
	settle("an exit's default")
	listed, err := plat.Routes()
	if err != nil {
		t.Fatalf("list the mesh's table: %v", err)
	}
	for _, p := range append(slices.Clone(defaults), assigned...) {
		if !slices.ContainsFunc(listed, func(route Route) bool { return route.Destination == p && route.Throw == (p.Bits() > 0) }) {
			t.Fatalf("the mesh's table holds no %s at %s: %v", map[bool]string{true: "throw", false: "default"}[p.Bits() > 0], p, listed)
		}
	}
	check("on the tun, an exit's default in the mesh's table", "local")
	off()
	check("off the tun, an exit's default in the mesh's table", "dev up0")
	for _, p := range defaults {
		routes.Remove(netip.Prefix{}, p)
	}
	settle("no default")
	check("on the tun, no shorter route in the mesh's table", "local")
	off()
	check("off the tun, no shorter route in the mesh's table", "dev up0")
}

// walkingPlatform is a netlink platform handing each rule write it took to after, once the write is done
type walkingPlatform struct {
	*netlinkPlatform
	after func(write string)
}

func (p *walkingPlatform) AddRule(rule Rule) error {
	err := p.netlinkPlatform.AddRule(rule)
	p.after("add rule " + rule.String())
	return err
}

func (p *walkingPlatform) DelRule(rule Rule) error {
	err := p.netlinkPlatform.DelRule(rule)
	p.after("delete rule " + rule.String())
	return err
}

// A stopped pass after a reload that narrows the overlay prefix inside the one the down set holds sends no lookup of an address of
// the new prefix by main's route as long as the old prefix after any of its writes, through a real kernel, which puts a new rule
// after each of its priority, so the new pair's 32764 would stand behind the old one's
func TestNetlinkStoppedPassNarrowingSendsNoLookupByAShorterRouteOfMain(t *testing.T) {
	plat := rootRulePlatform(t, stagedMesh)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createLink(conn, "up0", "dummy"); err != nil {
		t.Fatalf("make up0: %v", err)
	}
	up, err := conn.link(0, "up0")
	if err != nil {
		t.Fatalf("look up up0: %v", err)
	}
	setLinkFlags(t, conn, up.index, unix.IFF_UP)
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("192.0.2.0/25"), batchHop{index: up.index})
	wide, narrow := prefixes(prefix("192.0.2.0/24")), prefixes(prefix("192.0.2.0/26"))
	for _, rule := range downRules(wide) {
		if err := plat.AddRule(rule); err != nil {
			t.Fatalf("add %s: %v", rule, err)
		}
	}
	to := netip.MustParseAddr("192.0.2.1")
	answer := func() string {
		route, indexes, err := matchedRoute(conn, netip.Addr{}, to, 0, 0, 0)
		switch {
		case err != nil:
			return "error " + err.Error()
		case len(indexes) == 0:
			return "no hop, table " + strconv.Itoa(int(route.Table))
		}
		hop, err := conn.link(indexes[0], "")
		if err != nil {
			return "error " + err.Error()
		}
		return "dev " + hop.name
	}
	if got := answer(); got != "dev up0" {
		t.Fatalf("under the down set of %s the lookup of %s answers %s, want dev up0 by main's route", wide[0], to, got)
	}
	tbl, rt := platformFor(stagedMesh)
	rt.Overlay = narrow
	walking := &walkingPlatform{netlinkPlatform: plat, after: func(write string) {
		got := answer()
		t.Logf("after %s: %s answers %s", write, to, got)
		if got == "dev up0" {
			t.Errorf("after %s the lookup of %s leaves by main's route shorter than %s", write, to, narrow[0])
		}
	}}
	r := newReconciler(tbl.Normalized(), rt, nil, netstack.NewRouteTable(), walking)
	if err := r.withdraw(errStopped); err != nil {
		t.Fatal(err)
	}
	dumped, err := DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	var ours []DumpedRule
	for _, rule := range dumped {
		if rule.Protocol == DefaultProtocol {
			ours = append(ours, rule)
		}
	}
	if want := dumpedDown(narrow, DefaultProtocol); !sameRules(ours, want) {
		t.Errorf("the stopped pass left the rules %+v, want the down set %+v", ours, want)
	}
}
