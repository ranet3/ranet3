// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// The staged start through the package's own writer on a real kernel, in the topology of a staged start lab: each failing state
// reached by a write the platform fails, each answer the kernel selects compared with the lab's staged form GB, and every write of
// the release after it checked against the target the lab holds a failing start to (stagedBreaks).

// stagedRunWait bounds how long Run takes to bring the kernel to a state the test waits for, and stagedPoll is how often the test
// reads the rules while it waits
const (
	stagedRunWait = 10 * time.Second
	stagedPoll    = 2 * time.Millisecond
)

// stagedBlock is one of the lab's blocks: mode off, or mode 2 under fallback uplink or none, with a live exit default in the mesh's
// table or without one
type stagedBlock struct {
	name             string
	mode, none, live bool
	// via is mode 3, its path a SID of the mesh's that resolves through its own /128, so the pass installs its steered defaults
	via bool
}

var (
	stagedOff     = stagedBlock{name: "off"}
	stagedUpLive  = stagedBlock{name: "2u-live", mode: true, live: true}
	stagedUpNone  = stagedBlock{name: "2u-nodef", mode: true}
	stagedNoLive  = stagedBlock{name: "2n-live", mode: true, none: true, live: true}
	stagedNoNodef = stagedBlock{name: "2n-nodef", mode: true, none: true}
	stagedVia     = stagedBlock{name: "3n-live", mode: true, none: true, live: true, via: true}
)

// stagedSID is the mode 3 block's path
var stagedSID = netip.MustParseAddr("fd20:0:5::1")

// stagedOverlay is the lab's overlay, and stagedNew a prefix a reload adds that no pair of the earlier stop covers
var (
	stagedOverlay = prefixes(prefix("10.20.0.0/16"), prefix("fd20::/32"))
	stagedNew     = prefix("172.31.0.0/24")
)

// stagedCell is one of the lab's questions: the host's own packet, or one arriving on iif, from src to dst, marked as the underlay
// where mark is set
type stagedCell struct {
	name, src, dst, iif string
	mark                bool
}

var stagedCells = map[int][]stagedCell{
	4: {
		{name: "o0", dst: "10.20.7.7"},
		{name: "oT", src: "10.20.1.1", dst: "10.20.7.7"},
		{name: "oU", src: "198.51.100.2", dst: "10.20.7.7"},
		{name: "oP", dst: "10.20.5.7"},
		{name: "rep", src: "198.51.100.2", dst: "203.0.113.50"},
		{name: "out", dst: "203.0.113.50"},
		{name: "l+o", src: "192.168.50.10", dst: "10.20.7.7", iif: "lanp"},
		{name: "l+x", src: "192.168.50.10", dst: "203.0.113.50", iif: "lanp"},
		{name: "l-o", src: "192.168.60.10", dst: "10.20.7.7", iif: "lanm"},
		{name: "l-x", src: "192.168.60.10", dst: "203.0.113.50", iif: "lanm"},
		{name: "cv", dst: "10.20.200.9"},
		{name: "mk", dst: "10.20.98.77", mark: true},
		{name: "oS", src: "10.20.1.1", dst: "203.0.113.50"},
		{name: "oSb", src: "10.20.1.5", dst: "203.0.113.50"},
		{name: "sx", dst: "45.0.5.9"},
		{name: "sm", dst: "46.0.0.9"},
	},
	6: {
		{name: "o0", dst: "fd20:0:7::7"},
		{name: "oT", src: "fd20:0:1::1", dst: "fd20:0:7::7"},
		{name: "oU", src: "2001:db8:a::2", dst: "fd20:0:7::7"},
		{name: "oP", dst: "fd20:0:5::7"},
		{name: "rep", src: "2001:db8:a::2", dst: "2001:db8:ff::50"},
		{name: "out", dst: "2001:db8:ff::50"},
		{name: "l+o", src: "fd50::10", dst: "fd20:0:7::7", iif: "lanp"},
		{name: "l+x", src: "fd50::10", dst: "2001:db8:ff::50", iif: "lanp"},
		{name: "l-o", src: "fd60::10", dst: "fd20:0:7::7", iif: "lanm"},
		{name: "l-x", src: "fd60::10", dst: "2001:db8:ff::50", iif: "lanm"},
		{name: "cv", dst: "fd20:0:200::9"},
		{name: "mk", dst: "fd20:0:98::77", mark: true},
		{name: "oS", src: "fd20:0:1::1", dst: "2001:db8:ff::50"},
		{name: "oSb", src: "fd20:0:1::5", dst: "2001:db8:ff::50"},
		{name: "sx", dst: "2a01:e5::9"},
		{name: "sm", dst: "2a02:c0::9"},
	},
}

// stagedNewCells asks for the prefix stagedNew, with no source and from the uplink's address
var stagedNewCells = []stagedCell{{name: "new", dst: "172.31.0.9"}, {name: "newU", src: "198.51.100.2", dst: "172.31.0.9"}}

// stagedOutside is the cells to a destination outside the overlay: besides the lab's, the host's
// send outside from the tun's address and from another address of its own prefix, a subnet main and the mesh's table both hold,
// and one only the mesh's table holds
var stagedOutside = []string{"rep", "out", "l+x", "l-x", "oS", "oSb", "sx", "sm"}

// stagedClosed is the outside cells under fallback = "none" a failing start refuses: the host's own and the forwarded LAN's
var stagedClosed = []string{"rep", "out", "l+x", "oS", "oSb", "sx", "sm"}

// stagedPlatform is the netlink platform with the writes a test fails on demand, each rule write recorded, and after called after
// each rule write, landed or failed
type stagedPlatform struct {
	*netlinkPlatform
	mu        sync.Mutex
	listing   bool
	failAdd   func(Rule) bool
	failDel   func(Rule) bool
	failRoute func(Route) bool
	// armList, where it holds for a rule write that landed, fails the next listing of the rules
	armList   func(write string) bool
	listFails bool
	// listArmed says armList set listFails
	listArmed bool
	// routeAfter is called after each route write that landed, onRoutes ahead of each listing of the routes, and failAddrs fails
	// the listing of the tun's addresses
	routeAfter func(write string)
	onRoutes   func()
	failAddrs  bool
	writes     []string
	after      func(write string)
	// ruleLists counts the listings of the rules
	ruleLists int
	// met counts each kind of failure the platform answered with, and arms is each arming of a kind by set, from nil, with the
	// count met then, so the lab's cleanup tells that each arming was met
	met  map[string]int
	arms []stagedArm
	t    *testing.T
}

// stagedArm is one arming of a kind of failure: the count met when set armed it
type stagedArm struct {
	kind string
	at   int
	open bool
}

// faults is each kind of failure the platform holds armed now
func (p *stagedPlatform) faults() map[string]bool {
	return map[string]bool{
		"rule add": p.failAdd != nil, "rule delete": p.failDel != nil, "route add": p.failRoute != nil, "route listing": p.listing,
		"rule listing after a write": p.armList != nil, "rule listing": p.listFails, "address listing": p.failAddrs,
	}
}

// meet counts a failure of kind the platform answered with, under mu
func (p *stagedPlatform) meet(kind string) {
	if p.met == nil {
		p.met = map[string]int{}
	}
	p.met[kind]++
}

// unmet fails the lab for each arming of kind, or of every kind where kind is empty, still open and never met, and closes them
func (p *stagedPlatform) unmet(kind string) {
	for i, arm := range p.arms {
		if arm.open && (kind == "" || arm.kind == kind) {
			p.arms[i].open = false
			if p.met[arm.kind] == arm.at && p.t != nil {
				p.t.Errorf("the platform armed a %s failure that nothing met before it was cleared", arm.kind)
			}
		}
	}
}

var errStagedRefused = errors.New("netlink says no")

func (p *stagedPlatform) Addrs() ([]netip.Prefix, error) {
	p.mu.Lock()
	fails := p.failAddrs
	p.mu.Unlock()
	if fails {
		p.mu.Lock()
		p.meet("address listing")
		p.mu.Unlock()
		return nil, errors.New("the address dump fails")
	}
	return p.netlinkPlatform.Addrs()
}

func (p *stagedPlatform) Routes() ([]Route, error) {
	p.mu.Lock()
	listing, on := p.listing, p.onRoutes
	p.mu.Unlock()
	if on != nil {
		on()
	}
	if listing {
		p.mu.Lock()
		p.meet("route listing")
		p.mu.Unlock()
		return nil, errors.New("the route dump fails")
	}
	return p.netlinkPlatform.Routes()
}

func (p *stagedPlatform) Rules() ([]Rule, error) {
	p.mu.Lock()
	fails, armed := p.listFails, p.listArmed
	p.listFails, p.listArmed = false, false
	p.ruleLists++
	if fails {
		p.meet("rule listing")
		p.unmet("rule listing")
	}
	if armed {
		p.meet("rule listing after a write")
	}
	p.mu.Unlock()
	if fails {
		return nil, errors.New("the rule dump fails")
	}
	return p.netlinkPlatform.Rules()
}

func (p *stagedPlatform) AddRoute(route Route) error {
	p.mu.Lock()
	fail := p.failRoute != nil && p.failRoute(route)
	if fail {
		p.meet("route add")
	}
	p.mu.Unlock()
	if fail {
		return errStagedRefused
	}
	err := p.netlinkPlatform.AddRoute(route)
	p.routeWrote(err, "add route "+route.String())
	return err
}

func (p *stagedPlatform) DelRoute(route Route) error {
	err := p.netlinkPlatform.DelRoute(route)
	p.routeWrote(err, "delete route "+route.String())
	return err
}

func (p *stagedPlatform) routeWrote(err error, what string) {
	p.mu.Lock()
	after := p.routeAfter
	p.mu.Unlock()
	if err == nil && after != nil {
		after(what)
	}
}

func (p *stagedPlatform) AddRule(rule Rule) error {
	return p.write("add "+rule.String(), "rule add", func(p *stagedPlatform) bool { return p.failAdd != nil && p.failAdd(rule) }, func() error {
		return p.netlinkPlatform.AddRule(rule)
	})
}

func (p *stagedPlatform) DelRule(rule Rule) error {
	return p.write("delete "+rule.String(), "rule delete", func(p *stagedPlatform) bool { return p.failDel != nil && p.failDel(rule) }, func() error {
		return p.netlinkPlatform.DelRule(rule)
	})
}

func (p *stagedPlatform) write(what, kind string, fails func(*stagedPlatform) bool, do func() error) error {
	p.mu.Lock()
	fail := fails(p)
	if fail {
		p.meet(kind)
	}
	p.mu.Unlock()
	err := errStagedRefused
	if !fail {
		err = do()
	}
	p.mu.Lock()
	if err != nil {
		what += " (failed)"
	} else if p.armList != nil && p.armList(what) {
		p.listFails, p.listArmed = true, true
	}
	p.writes = append(p.writes, what)
	after := p.after
	p.mu.Unlock()
	if after != nil {
		after(what)
	}
	return err
}

// set changes the platform's faults under its lock
func (p *stagedPlatform) set(change func(*stagedPlatform)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	before := p.faults()
	change(p)
	for kind, armed := range p.faults() {
		switch {
		case armed && !before[kind]:
			p.arms = append(p.arms, stagedArm{kind: kind, at: p.met[kind], open: true})
		case !armed && before[kind] && kind != "rule listing":
			p.unmet(kind)
		}
	}
}

// taken returns the rule writes since the last call
func (p *stagedPlatform) taken() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.writes
	p.writes = nil
	return out
}

// stagedLab is one block of the lab in a namespace of its own, with its reconciler and the references: the answers of a running
// node and of a completed down
type stagedLab struct {
	block     stagedBlock
	plat      *stagedPlatform
	r         *Reconciler
	tbl       Table
	rt        Runtime
	routes    *netstack.RouteTable
	want      map[string]map[string]string
	run, down map[string]string
	// set is the rules the running pass derived
	set []Rule
	// network holds the host's network the reconciler reads, and deleted says a down rule's delete landed in the pass the
	// sampler watches, so the release passed its commit point
	network *NetworkState
	deleted bool
}

const stagedMesh = "mesh0"

func newStagedLab(t *testing.T, block stagedBlock) *stagedLab {
	t.Helper()
	plat := &stagedPlatform{netlinkPlatform: rootRulePlatform(t, stagedMesh), t: t}
	t.Cleanup(func() {
		plat.mu.Lock()
		defer plat.mu.Unlock()
		plat.unmet("")
	})
	for path, value := range map[string]string{
		"ipv4/ip_forward": "1", "ipv6/conf/all/forwarding": "1", "ipv6/conf/all/accept_dad": "0", "ipv6/conf/default/accept_dad": "0",
		"ipv4/conf/all/rp_filter": "0", "ipv4/conf/default/rp_filter": "0",
	} {
		writeBatchSysctl(t, path, value)
	}
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	links := map[string][2]netip.Prefix{
		"up0":  {prefix("198.51.100.2/24"), prefix("2001:db8:a::2/64")},
		"lanp": {prefix("192.168.50.1/24"), prefix("fd50::1/64")},
		"lanm": {prefix("192.168.60.1/24"), prefix("fd60::1/64")},
		"cv0":  {prefix("10.20.200.1/24"), prefix("fd20:0:200::1/64")},
	}
	index := map[string]uint32{}
	for _, name := range []string{"lo", stagedMesh, "up0", "lanp", "lanm", "cv0"} {
		if _, ok := links[name]; ok {
			if err := createLink(conn, name, "dummy"); err != nil {
				t.Fatalf("make %s: %v", name, err)
			}
		}
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	var network NetworkState
	for _, name := range []string{"cv0", "lanm", "lanp", "up0"} {
		for i, address := range links[name] {
			writeBatchAddress(t, conn, index[name], address)
			family := &network.IPv4
			if i == 1 {
				family = &network.IPv6
			}
			family.Links = append(family.Links, Link{Name: name, Prefixes: []netip.Prefix{address}})
			family.Addresses = append(family.Addresses, address.Addr())
		}
	}
	for _, address := range []string{"10.20.1.5/32", "fd20:0:1::5/128"} {
		writeBatchAddress(t, conn, index["lo"], prefix(address))
	}
	network.IPv4.Default = DefaultRoute{Interface: "up0", Gateway: netip.MustParseAddr("198.51.100.1")}
	network.IPv6.Default = DefaultRoute{Interface: "up0", Gateway: netip.MustParseAddr("2001:db8:a::1")}
	for destination, gateway := range map[string]string{
		"0.0.0.0/0": "198.51.100.1", "::/0": "2001:db8:a::1", "10.0.0.0/8": "198.51.100.9", "fd00::/8": "2001:db8:a::9",
		"10.20.98.0/24": "198.51.100.8", "fd20:0:98::/48": "2001:db8:a::8", "45.0.5.0/24": "198.51.100.7", "2a01:e5::/48": "2001:db8:a::7",
	} {
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix(destination), batchHop{index: index["up0"], gateway: netip.MustParseAddr(gateway)})
	}
	tbl, rt := platformFor(stagedMesh)
	rt.Overlay = stagedOverlay
	held := &network
	rt.Network = func() NetworkState { return *held }
	tbl.Addresses = prefixes(prefix("10.20.1.1/32"), prefix("fd20:0:1::1/128"))
	if block.mode {
		mode := &ExitMode{Forward: []string{"lanp"}, Fallback: FallbackUplink}
		if block.none {
			mode.Fallback = FallbackNone
		}
		if block.via {
			mode.Fallback, mode.Via = "", []schema.Addr{schema.AddrFrom(stagedSID)}
		}
		tbl = tbl.WithMode(mode)
		if block.via {
			tbl = tbl.WithPathSource(netip.MustParseAddr("fd20:0:1::1"))
		}
	}
	tbl = tbl.Normalized()
	routes := netstack.NewRouteTable()
	for _, mesh := range []string{"10.20.5.0/24", "fd20:0:5::/48", "10.20.96.0/22", "fd20:0:98::/47", "45.0.0.0/16", "2a01:e0::/44", "46.0.0.0/16", "2a02:c0::/48"} {
		routes.Set(netip.Prefix{}, prefix(mesh), nil)
	}
	for _, own := range []string{"10.20.1.0/24", "fd20:0:1::/48"} {
		routes.Set(netip.Prefix{}, prefix(own), netstack.Local)
	}
	if block.via {
		routes.Set(netip.Prefix{}, netip.PrefixFrom(stagedSID, 128), nil)
	}
	if block.live && block.mode {
		routes.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
		routes.Set(netip.Prefix{}, prefix("::/0"), nil)
	}
	l := &stagedLab{block: block, plat: plat, tbl: tbl, rt: rt, routes: routes, want: stagedWant(t, block.name), network: held}
	l.r = l.reconciler()
	return l
}

// reconciler is a reconciler of the lab's on its platform, as a process starting anew builds one
func (l *stagedLab) reconciler() *Reconciler {
	return newReconciler(l.tbl, l.rt, l.tbl.Assigned(nil), l.routes, l.plat)
}

// stagedWant reads the lab's answers for block from testdata, by "form state" and then "cell/family". The file is the lab's logs
// as a script that turns each logged cell into its code writes them, regenerated by running the lab and that script, never edited
// by hand.
func stagedWant(t *testing.T, block string) map[string]map[string]string {
	t.Helper()
	f, err := os.Open("testdata/staged-start-cells.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[string]string{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 6 || fields[0] != block {
			continue
		}
		key := fields[1] + " " + fields[2]
		if out[key] == nil {
			out[key] = map[string]string{}
		}
		out[key][fields[3]+"/"+fields[4]] = fields[5]
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// answer is where the kernel sends c, in the lab's codes: F refused by the down set's 32765, F5 by 5450, Fh by a hold, M into the
// mesh, C out of the carve-out link, U out of the uplink by its default, U9, U8 and U7 by the operator's routes shorter and longer
// than the overlay and to a subnet outside it
func stagedAnswer(c stagedCell) string {
	conn, err := dialNetlink()
	if err != nil {
		return "err " + err.Error()
	}
	defer conn.Close()
	var src netip.Addr
	if c.src != "" {
		src = netip.MustParseAddr(c.src)
	}
	var arrival, mark uint32
	if c.iif != "" {
		link, err := conn.link(0, c.iif)
		if err != nil {
			return "err " + err.Error()
		}
		arrival = link.index
	}
	if c.mark {
		mark = schema.UnderlayMark
	}
	route, indexes, err := matchedRoute(conn, src, netip.MustParseAddr(c.dst), arrival, 0, mark)
	switch {
	case errors.Is(err, unix.ENETUNREACH):
		switch refuser(c) {
		case priorityDownRefused:
			return "F"
		case priorityRefused:
			return "F5"
		}
		return "F?"
	case errors.Is(err, unix.EHOSTUNREACH):
		return "Fh"
	case errors.Is(err, unix.EINVAL):
		return "Fi"
	case err != nil:
		return "err " + err.Error()
	case len(indexes) == 0:
		return "no hop"
	}
	link, err := conn.link(indexes[0], "")
	if err != nil {
		return "err " + err.Error()
	}
	switch link.name {
	case stagedMesh:
		return "M"
	case "cv0":
		return "C"
	case "up0":
		switch route.Prefix.String() {
		case "10.0.0.0/8", "fd00::/8":
			return "U9"
		case "10.20.98.0/24", "fd20:0:98::/48":
			return "U8"
		case "45.0.5.0/24", "2a01:e5::/48":
			return "U7"
		}
		return "U"
	}
	return "dev " + link.name
}

// refuser is the priority of the rule that refused c, which the kernel answers ENETUNREACH: the first unreachable rule c's lookup
// meets in the kernel's rules by priority, past what a goto c's mark matches jumps over. A lookup rule before it answered nothing, or
// the kernel would not have refused, since no table of the lab's holds an unreachable route but the holds, which answer
// EHOSTUNREACH. 0 where no rule of the walk refuses.
func refuser(c stagedCell) uint32 {
	dumped, err := DumpRules()
	if err != nil {
		return 0
	}
	slices.SortStableFunc(dumped, func(a, b DumpedRule) int { return cmp.Compare(a.Priority, b.Priority) })
	dst := netip.MustParseAddr(c.dst)
	family, iif := familyOf(dst), cmp.Or(c.iif, "lo")
	var src netip.Addr
	if c.src != "" {
		src = netip.MustParseAddr(c.src)
	}
	var mark, past uint32
	if c.mark {
		mark = schema.UnderlayMark
	}
	for _, rule := range dumped {
		mask := cmp.Or(rule.FWMask, ^uint32(0))
		switch {
		case rule.Family != family || rule.Priority < past:
		case rule.To.IsValid() && !rule.To.Contains(dst):
		case rule.From.IsValid() && (!src.IsValid() && rule.From.Bits() != 0 || src.IsValid() && !rule.From.Contains(src)):
		case rule.IIF != "" && rule.IIF != iif:
		case rule.FWMark != 0 && mark&mask != rule.FWMark:
		case rule.Action == actionGoto.String():
			past = rule.Goto
		case rule.Action == actionUnreachable.String():
			return rule.Priority
		}
	}
	return 0
}

// cells is every cell's answer, by "cell/family"
func (l *stagedLab) cells() map[string]string {
	out := map[string]string{}
	for _, family := range []int{4, 6} {
		for _, c := range stagedCells[family] {
			out[fmt.Sprintf("%s/%d", c.name, family)] = stagedAnswer(c)
		}
	}
	return out
}

// same checks got against want, the lab's form and state named, cell by cell
func (l *stagedLab) same(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if len(want) == 0 {
		t.Errorf("%s: the lab has no answers for it", what)
		return
	}
	for _, key := range slices.Sorted(maps.Keys(want)) {
		if got[key] != want[key] {
			t.Errorf("%s %s: the kernel selects %s, the lab %s", what, key, got[key], want[key])
		}
	}
}

// stagedBreaks names how got breaks the target a staged start and its release are held to beside the references: an overlay cell a completed down refuses never leaves in the clear but where the running node sends it so, nothing goes
// into the mesh where neither carries it there, and under fallback uplink and in mode off nothing is refused that both admit, and
// a destination outside the overlay gets the completed down's answer until the release's commit point and the completed down's or
// the running node's after it. A send the completed down refuses because its source is gone there has no answer of the completed
// down to keep. It is empty where got keeps them all.
func stagedBreaks(block stagedBlock, cell, got, down, run string, committed bool) string {
	refused := func(a string) bool { return strings.HasPrefix(a, "F") }
	clear := func(a string) bool { return strings.HasPrefix(a, "U") || a == "C" }
	outside := slices.Contains(stagedOutside, strings.Split(cell, "/")[0])
	if outside && refused(down) {
		// the send has no source in the completed down, and main's default answers it there as it does its twin from an
		// address the completed down keeps
		down = "U"
	}
	switch {
	case refused(down) && clear(got) && got != run && !outside:
		return "clear"
	case got == "M" && down != "M" && run != "M":
		return "mesh"
	case block.none:
		return ""
	case refused(got) && !refused(down) && !refused(run):
		return "refused"
	case outside && !committed && !refused(down) && got != down:
		return "outside before the commit"
	case outside && got != down && got != run:
		return "outside"
	}
	return ""
}

// sample checks every cell against stagedBreaks after write, reporting each break
func (l *stagedLab) sample(t *testing.T, write string) {
	if strings.Contains(write, "delete priority 3276") && !strings.HasSuffix(write, "(failed)") {
		l.deleted = true
	}
	got := l.cells()
	for _, key := range slices.Sorted(maps.Keys(got)) {
		if broke := stagedBreaks(l.block, key, got[key], l.down[key], l.run[key], l.deleted); broke != "" {
			t.Errorf("after %s, %s: the kernel selects %s (down %s, running %s), which breaks the target (%s)", write, key, got[key], l.down[key], l.run[key], broke)
		}
	}
}

// closed checks, under fallback = "none", that a failing start refuses every cell of stagedClosed
func (l *stagedLab) closed(t *testing.T, state string) {
	if !l.block.none {
		return
	}
	got := l.cells()
	for _, family := range []int{4, 6} {
		for _, cell := range stagedClosed {
			key := fmt.Sprintf("%s/%d", cell, family)
			if !strings.HasPrefix(got[key], "F") {
				t.Errorf("%s, %s: under none the kernel selects %s, want it refused", state, key, got[key])
			}
		}
	}
}

// ruleSet is the rules the last pass derived
func (l *stagedLab) ruleSet() []Rule {
	if set := l.r.derived.Load(); set != nil {
		return *set
	}
	return nil
}

// rulesNow is the reconciler's rules as a dump through a connection of the test's own reads them, since Run may be writing on the
// platform's
func rulesNow(t *testing.T) []DumpedRule {
	t.Helper()
	dumped, err := DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(dumped, func(rule DumpedRule) bool { return rule.Protocol != DefaultProtocol })
}

// holding reports whether held holds rule
func holding(held []DumpedRule, rule Rule) bool {
	return slices.Contains(held, rule.dumped(DefaultProtocol))
}

// references runs a pass to the running node and a stop to the completed down, reads both, and checks them with the lab's
func (l *stagedLab) references(t *testing.T) {
	t.Helper()
	if err := l.r.reconcile(); err != nil {
		t.Fatalf("the running pass: %v", err)
	}
	l.set = slices.Clone(l.ruleSet())
	if l.block.via && l.r.pathDown.IsValid() {
		t.Fatalf("mode 3's path is down at %s (%s), so the pass installs no steered default", l.r.pathDown, l.r.pathVerdict)
	}
	l.run = l.cells()
	l.same(t, "the running node", l.run, l.want["REF run"])
	l.stop(t)
	l.down = l.cells()
	l.same(t, "the completed down", l.down, l.want["REF down"])
}

// stop runs the stop's withdrawal, which leaves the down set alone
func (l *stagedLab) stop(t *testing.T) {
	t.Helper()
	if err := l.r.withdraw(errStopped); err != nil {
		t.Fatalf("the stop: %v", err)
	}
}

// heal clears every fault and runs passes, each write sampled against the target, until one succeeds, and checks the running node
func (l *stagedLab) heal(t *testing.T, what string, passes int) {
	t.Helper()
	l.deleted = false
	l.plat.set(func(p *stagedPlatform) {
		p.listing, p.failAdd, p.failDel, p.failRoute, p.armList, p.onRoutes, p.failAddrs = false, nil, nil, nil, nil, nil, false
		p.after = func(write string) { l.sample(t, what+": "+write) }
	})
	defer l.plat.set(func(p *stagedPlatform) { p.after = nil })
	var err error
	for range passes {
		if err = l.r.reconcile(); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("%s: the pass after it: %v", what, err)
	}
	l.same(t, what+", the pass after it", l.cells(), l.run)
	if stats := l.r.routePass; stats.Held != 0 || len(stats.Owed) != 0 {
		t.Errorf("%s: after the pass after it the record holds %d prefixes and owes %v", what, stats.Held, stats.Owed)
	}
}

// failing runs, from the completed down, a pass that fails as fault has it, checks its answers with the lab's form GB in state,
// then heals and stops again
func (l *stagedLab) failing(t *testing.T, state string, fault func(*stagedPlatform), check func(t *testing.T)) {
	t.Helper()
	l.plat.set(fault)
	l.plat.taken()
	if err := l.r.reconcile(); err == nil {
		t.Errorf("%s: the pass reported no error", state)
	}
	l.same(t, state, l.cells(), l.want["GB "+state])
	l.deleted = l.r.released
	l.sample(t, state)
	// a failed 5450 leaves nothing that holds (routing.md), a failed take-back leaves the completed down's or the running
	// node's answers beside it, and a node that runs is no failing start
	if state != "X-5450" && state != "LU-5410" && !l.r.released {
		l.closed(t, state)
	}
	if check != nil {
		check(t)
	}
	l.heal(t, state, 3)
	l.stop(t)
}

// priorityIs fails every rule of priority
func priorityIs(priority uint32) func(Rule) bool {
	return func(rule Rule) bool { return rule.Priority == priority }
}

// stagedStates runs each failing state of the lab in block through the package's writer
func stagedStates(t *testing.T, block stagedBlock) {
	l := newStagedLab(t, block)
	l.references(t)
	l.failing(t, "L-listing", func(p *stagedPlatform) { p.listing = true }, nil)
	l.failing(t, "G-5110", func(p *stagedPlatform) { p.failAdd = priorityIs(priorityOverlay) }, nil)
	l.failing(t, "H-hold", func(p *stagedPlatform) {
		p.failRoute = func(route Route) bool {
			return route.Unreachable && slices.Contains(SchemaPrefixes(stagedOverlay), route.Destination)
		}
	}, nil)
	l.failing(t, "X-5100", func(p *stagedPlatform) { p.failAdd = priorityIs(priorityUnderlayPastOverlay) }, nil)
	if block.none {
		l.failing(t, "X-5450", func(p *stagedPlatform) { p.failAdd = priorityIs(priorityRefused) }, nil)
	}
	// ready: the release's first add fails, and the take-back of nothing leaves every rule staged
	first := l.releaseOrder()[0]
	l.failing(t, "ready", func(p *stagedPlatform) { p.failAdd = func(rule Rule) bool { return rule == first } }, nil)
	// a write after both 5410 and before the commit fails, an add where one follows IPv6's 5410 and otherwise the reread, and the
	// take-back of each family's 5410 fails too, so both stand beside the down set
	order := l.releaseOrder()
	after := slices.IndexFunc(order, func(rule Rule) bool { return rule.Family == FamilyIPv6 && rule.Priority == priorityMain }) + 1
	l.failing(t, "LU-5410", func(p *stagedPlatform) {
		if after < len(order) {
			p.failAdd = func(rule Rule) bool { return rule == order[after] }
		} else {
			last := "add " + order[after-1].String()
			p.armList = func(write string) bool { return write == last }
		}
		p.failDel = priorityIs(priorityMain)
	}, func(t *testing.T) {
		if owed := l.r.routePass.Owed; len(owed) != 2 || !strings.HasPrefix(owed[0], "delete priority 5410") || !strings.HasPrefix(owed[1], "delete priority 5410") {
			t.Errorf("LU-5410: the record owes %v, want the deletes of both 5410", owed)
		}
		// a pass whose address listing fails, in modes 2 and 3 a pass that judges no rule, still deletes them ahead of its route
		// writes
		if l.block.mode {
			l.plat.set(func(p *stagedPlatform) { p.failAdd, p.failDel, p.armList, p.failAddrs = nil, nil, nil, true })
			_ = l.r.reconcile()
			l.plat.set(func(p *stagedPlatform) { p.failAddrs = false })
			if held := rulesNow(t); slices.ContainsFunc(held, func(rule DumpedRule) bool { return rule.Priority == priorityMain }) || l.r.routePass.Held != 2 {
				t.Errorf("LU-5410: after a pass whose address listing failed the kernel holds a 5410 %v and the record %d prefixes, want none and 2",
					slices.ContainsFunc(held, func(rule DumpedRule) bool { return rule.Priority == priorityMain }), l.r.routePass.Held)
			}
			for _, rule := range l.set {
				if rule.Priority == priorityMain {
					if err := l.plat.netlinkPlatform.AddRule(rule); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		// the next pass deletes them first, ahead of every other write, and its route write of a throw inside the IPv4 prefix
		// finds no 5410 to send the overlay out by main's shorter route
		before := *l.network
		narrower := before
		narrower.IPv4.Links = append(slices.Clone(before.IPv4.Links), Link{Name: "cvn", Prefixes: []netip.Prefix{prefix("10.20.7.1/24")}})
		*l.network = narrower
		var thrown bool
		l.plat.set(func(p *stagedPlatform) {
			p.failAdd, p.failDel, p.armList = nil, nil, nil
			p.routeAfter = func(write string) {
				thrown = thrown || strings.Contains(write, "10.20.7.0/24")
				if slices.ContainsFunc(rulesNow(t), func(rule DumpedRule) bool { return rule.Priority == priorityMain }) {
					t.Errorf("LU-5410: a 5410 stands at the route write %s", write)
				}
				if got := stagedAnswer(stagedCells[4][0]); !strings.HasPrefix(got, "F") {
					t.Errorf("LU-5410: after the route write %s, o0/4 goes %s, want it refused", write, got)
				}
			}
		})
		l.plat.taken()
		_ = l.r.reconcile()
		l.plat.set(func(p *stagedPlatform) { p.routeAfter = nil })
		*l.network = before
		if !thrown {
			t.Error("LU-5410: the pass wrote no throw for the carve-out inside the IPv4 prefix")
		}
		writes := l.plat.taken()
		if len(writes) < 2 || !strings.HasPrefix(writes[0], "delete priority 5410") || !strings.HasPrefix(writes[1], "delete priority 5410") {
			t.Errorf("LU-5410: the next pass wrote %v first, want the deletes of both 5410", writes[:min(len(writes), 4)])
		}
		// back to the state for heal to start from
		l.stop(t)
		l.plat.set(func(p *stagedPlatform) { p.listing = true })
		_ = l.r.reconcile()
	})
	// a down rule's delete fails after the running rules went in: the running node's answers, a delete owed
	l.failing(t, "DD-down", func(p *stagedPlatform) { p.failDel = isDownRule }, func(t *testing.T) {
		// the node runs, so nothing reads as refused while down, and each pair is a delete owed
		want := []string{"delete the pair of 10.20.0.0/16 (32765, 32764)", "delete the pair of fd20::/32 (32765, 32764)"}
		if stats := l.r.routePass; stats.Held != 0 || stats.HeldUnknown || !slices.Equal(stats.Owed, want) {
			t.Errorf("DD-down: the record holds %d prefixes (not known %v) and owes %v, want 0 and %v", stats.Held, stats.HeldUnknown, stats.Owed, want)
		}
		l.plat.set(func(p *stagedPlatform) { p.failDel = nil })
		l.plat.taken()
		if err := l.r.reconcile(); err != nil {
			t.Errorf("DD-down: the pass that owes the deletes: %v", err)
		}
		for _, write := range l.plat.taken() {
			if !strings.Contains(write, "priority 3276") {
				t.Errorf("DD-down: the pass that owes the deletes wrote %s, want the down rules' deletes alone", write)
			}
		}
		l.stop(t)
		l.plat.set(func(p *stagedPlatform) { p.failDel = isDownRule })
		_ = l.r.reconcile()
	})
	stagedB1(t, l)
	stagedNewPrefix(t, l)
	stagedHoldMoved(t, l)
	stagedHoldStolen(t, l)
	if block.mode {
		stagedAddresses(t, l)
	}
	stagedTeardown(t, l)
}

// a start whose listing of the tun's addresses fails, in modes 2 and 3 a pass that judges no rule: under fallback = "none" its
// entry adds 5490, 5400 and 5450 for lo and each link forward expands to, each write taking an outside cell from the completed
// down's answer only to a refusal, so the kernel answers as the lab's GB L-listing, every closed cell refused by 5450, and in any
// other mode as the completed down. Under none a pass from the completed down that cannot release then has every closed cell
// refused at each of its route writes, since its entry wrote 5450 ahead of them.
func stagedAddresses(t *testing.T, l *stagedLab) {
	t.Helper()
	l.deleted = false
	l.plat.set(func(p *stagedPlatform) {
		p.failAddrs = true
		p.after = func(write string) {
			l.sample(t, "addresses: "+write)
			if !l.block.none {
				return
			}
			got := l.cells()
			for _, family := range []int{4, 6} {
				for _, cell := range stagedClosed {
					key := fmt.Sprintf("%s/%d", cell, family)
					if got[key] != "F5" && got[key] != l.down[key] {
						t.Errorf("addresses: after %s, %s goes %s, want the completed down's %s or refused by 5450", write, key, got[key], l.down[key])
					}
				}
			}
		}
	})
	if err := l.r.reconcile(); err == nil {
		t.Error("addresses: the pass whose address listing failed reported no error")
	}
	l.plat.set(func(p *stagedPlatform) { p.after = nil })
	want := l.down
	if l.block.none {
		want = l.want["GB L-listing"]
	}
	got := l.cells()
	l.same(t, "addresses", got, want)
	if l.block.none {
		for _, family := range []int{4, 6} {
			for _, cell := range stagedClosed {
				if key := fmt.Sprintf("%s/%d", cell, family); got[key] != "F5" {
					t.Errorf("addresses: %s goes %s, want it refused by 5450", key, got[key])
				}
			}
		}
	}
	l.heal(t, "addresses", 3)
	l.stop(t)
	if !l.block.none {
		return
	}
	first := l.releaseOrder()[0]
	writes := 0
	l.plat.set(func(p *stagedPlatform) {
		p.failAdd = func(rule Rule) bool { return rule == first }
		p.routeAfter = func(write string) {
			writes++
			l.closed(t, "at the start's route write "+write)
		}
	})
	_ = l.r.reconcile()
	l.plat.set(func(p *stagedPlatform) { p.routeAfter = nil })
	if writes == 0 {
		t.Error("addresses: the start from the completed down wrote no route")
	}
	l.heal(t, "the start under none", 3)
	l.stop(t)
}

// a process starting anew over a running set with the down set beside it and the IPv6 family's last late rule missing, as a crash
// while a down delete was owed leaves them, tears the running set down as a withdrawal does, from the last priority, each goto
// ahead of its nop, and releases again: at no write does a cell go into the mesh or out in the clear where neither the completed
// down nor the running node sends it so
func stagedTeardown(t *testing.T, l *stagedLab) {
	t.Helper()
	l.heal(t, "teardown, the running set", 1)
	for _, rule := range downRules(stagedOverlay) {
		if err := l.plat.netlinkPlatform.AddRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	var missing Rule
	for _, rule := range l.set {
		if rule.Family == FamilyIPv6 && stepOf(rule.Priority, l.block.none) == stepLate {
			missing = rule
		}
	}
	if err := l.plat.netlinkPlatform.DelRule(missing); err != nil {
		t.Fatal(err)
	}
	l.r = l.reconciler()
	l.deleted = true
	l.plat.set(func(p *stagedPlatform) { p.after = func(write string) { l.sample(t, "teardown: "+write) } })
	if err := l.r.reconcile(); err != nil {
		t.Errorf("teardown: the pass: %v", err)
	}
	l.plat.set(func(p *stagedPlatform) { p.after = nil })
	l.same(t, "teardown, the pass after it", l.cells(), l.run)
	if slices.ContainsFunc(downRules(stagedOverlay), func(rule Rule) bool { return holding(rulesNow(t), rule) }) {
		t.Error("teardown: after the pass a rule of the down set stands")
	}
	l.stop(t)
}

// a hold another writer deletes after the pass listed the routes gets no 5110 back, since a staged 5110 comes back only once a
// reread of the routes shows its hold
func stagedHoldStolen(t *testing.T, l *stagedLab) {
	t.Helper()
	whole := prefix("10.20.0.0/16")
	overlayLookup := func(to netip.Prefix) bool {
		return slices.ContainsFunc(rulesNow(t), func(rule DumpedRule) bool { return rule.Priority == priorityOverlay && rule.To == to })
	}
	l.plat.set(func(p *stagedPlatform) { p.failAdd = priorityIs(priorityOverlay) })
	_ = l.r.reconcile()
	first := l.releaseOrder()[0]
	listings := 0
	l.plat.set(func(p *stagedPlatform) {
		p.failAdd = func(rule Rule) bool { return rule == first }
		p.onRoutes = func() {
			listings++
			if listings == 2 {
				if err := p.netlinkPlatform.DelRoute(Route{Destination: whole, Metric: holdMetric, Unreachable: true}); err != nil {
					t.Errorf("hold stolen: deleting the hold: %v", err)
				}
			}
		}
	})
	_ = l.r.reconcile()
	l.plat.set(func(p *stagedPlatform) { p.onRoutes = nil })
	if listings < 2 {
		t.Errorf("hold stolen: the pass listed the routes %d times, want a reread for the overlay's lookups", listings)
	}
	if overlayLookup(whole) || !overlayLookup(prefix("fd20::/32")) {
		t.Errorf("hold stolen: after the pass a 5110 of 10.20.0.0/16 stands %v and of fd20::/32 %v, want the IPv6 one alone", overlayLookup(whole), overlayLookup(prefix("fd20::/32")))
	}
	if got := stagedAnswer(stagedCells[4][0]); !strings.HasPrefix(got, "F") {
		t.Errorf("hold stolen: o0/4 goes %s, want it refused", got)
	}
	l.heal(t, "hold stolen", 3)
	l.stop(t)
}

// releaseOrder is the release's adds in the order it writes them, from the last pass's rules
func (l *stagedLab) releaseOrder() []Rule { return inStep(l.set, stepFirst, l.block.none) }

// A release whose delete of the IPv4 refusal fails keeps that pair whole, and the pass after it
// deletes the pair, refusal first, and nothing of the running rules, every write keeping the target
func stagedB1(t *testing.T, l *stagedLab) {
	t.Helper()
	refusal := downRules(stagedOverlay)[0]
	l.deleted = false
	l.plat.set(func(p *stagedPlatform) {
		p.failDel = func(rule Rule) bool { return rule == refusal }
		p.after = func(write string) { l.sample(t, "B1: "+write) }
	})
	if err := l.r.reconcile(); err == nil {
		t.Error("B1: the pass whose delete of the IPv4 refusal failed reported no error")
	}
	held := rulesNow(t)
	if !holding(held, refusal) || !holding(held, downRules(stagedOverlay)[1]) || holding(held, downRules(stagedOverlay)[2]) {
		t.Errorf("B1: after the pass the kernel holds %v, want the IPv4 pair whole and no IPv6 rule of the down set", held)
	}
	l.plat.set(func(p *stagedPlatform) { p.failDel = nil })
	l.plat.taken()
	l.heal(t, "B1", 1)
	l.stop(t)
}

// a reload's overlay prefix no pair of the earlier stop covers gets its pair first in a start that fails, and its hold once the
// start releases
func stagedNewPrefix(t *testing.T, l *stagedLab) {
	t.Helper()
	l.r.rt.Overlay = append(slices.Clone(stagedOverlay), schema.PrefixFrom(stagedNew))
	defer func() { l.r.rt.Overlay = stagedOverlay }()
	l.plat.set(func(p *stagedPlatform) { p.listing = true })
	_ = l.r.reconcile()
	// under none 5450 refuses the host's own send ahead of the pair
	refused := "F"
	if l.block.none {
		refused = "F5"
	}
	for _, c := range stagedNewCells {
		if got := stagedAnswer(c); got != refused {
			t.Errorf("new prefix, %s: the start whose listing failed sends it %s, want it refused (%s)", c.name, got, refused)
		}
	}
	if pair := downRules([]schema.Prefix{schema.PrefixFrom(stagedNew)}); !holding(rulesNow(t), pair[0]) || !holding(rulesNow(t), pair[1]) {
		t.Error("new prefix: the start whose listing failed added no pair for it")
	}
	l.plat.set(func(p *stagedPlatform) { p.listing = false })
	if err := l.r.reconcile(); err != nil {
		t.Fatalf("new prefix: the pass after it: %v", err)
	}
	for _, c := range stagedNewCells {
		if got := stagedAnswer(c); got != "Fh" {
			t.Errorf("new prefix, %s: the running node sends it %s, want its hold", c.name, got)
		}
	}
	l.stop(t)
}

func TestNetlinkStagedStartModeOff(t *testing.T)           { stagedStates(t, stagedOff) }
func TestNetlinkStagedStartUplinkLiveDefault(t *testing.T) { stagedStates(t, stagedUpLive) }
func TestNetlinkStagedStartUplinkNoDefault(t *testing.T)   { stagedStates(t, stagedUpNone) }
func TestNetlinkStagedStartNoneLiveDefault(t *testing.T)   { stagedStates(t, stagedNoLive) }
func TestNetlinkStagedStartNoneNoDefault(t *testing.T)     { stagedStates(t, stagedNoNodef) }

// mode 3 with its steered defaults installed, which the lab's 3n-live block stands for
func TestNetlinkStagedStartModeThree(t *testing.T) { stagedStates(t, stagedVia) }

// stagedRun drives block through the real Run: a process starting anew finds every derived rule and the down set, as one stopped
// after its last adds leaves them, and takes the down set alone, then a down and an up, every write of the release checked against
// the target on the test's own thread, whose namespace the lab is in
func stagedRun(t *testing.T, block stagedBlock) {
	l := newStagedLab(t, block)
	l.references(t)
	if err := l.r.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range downRules(stagedOverlay) {
		if err := l.plat.netlinkPlatform.AddRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	running := l.set
	r := l.reconciler()
	l.r = r
	asks := make(chan chan struct{})
	l.plat.set(func(p *stagedPlatform) {
		p.writes = nil
		p.after = func(string) {
			ask := make(chan struct{})
			asks <- ask
			<-ask
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	// serve answers each write's ask, sampling on this thread, until until reports true
	serve := func(what string, check func(write string), until func() bool) {
		deadline := time.After(stagedRunWait)
		for !until() {
			select {
			case ask := <-asks:
				l.plat.mu.Lock()
				write := l.plat.writes[len(l.plat.writes)-1]
				l.plat.mu.Unlock()
				check(what + ": " + write)
				close(ask)
			case <-deadline:
				t.Fatalf("%s: Run did not get there within stagedRunWait", what)
			case <-time.After(stagedPoll):
			}
		}
	}
	keepsRunning := func(write string) {
		held := rulesNow(t)
		if missing := slices.DeleteFunc(slices.Clone(running), func(rule Rule) bool { return holding(held, rule) }); len(missing) > 0 {
			t.Errorf("after %s the kernel lacks %v of the running rules", write, missing)
		}
		l.sample(t, write)
	}
	downRulesNow := func() int {
		n := 0
		for _, rule := range downRules(stagedOverlay) {
			if holding(rulesNow(t), rule) {
				n++
			}
		}
		return n
	}
	l.deleted = true
	serve("the start that finds the running rules and the down set", keepsRunning, func() bool { return !r.Stats().At.IsZero() && downRulesNow() == 0 })
	r.SetEnabled(false)
	serve("the down", func(string) {}, func() bool {
		held := rulesNow(t)
		return len(held) == len(downRules(stagedOverlay)) && !slices.ContainsFunc(downRules(stagedOverlay), func(rule Rule) bool { return !holding(held, rule) })
	})
	r.SetEnabled(true)
	l.deleted = false
	serve("the up", func(write string) { l.sample(t, write) }, func() bool { return downRulesNow() == 0 && len(rulesNow(t)) == len(running) })
	l.same(t, "after the up through Run", l.cells(), l.run)
	l.plat.set(func(p *stagedPlatform) { p.after = nil })
	// a write already waiting on its ask is let go
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case ask := <-asks:
				close(ask)
			case <-stop:
				return
			}
		}
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(stagedRunWait):
		t.Error("run did not return after its cancel")
	}
}

func TestNetlinkStagedRunModeOff(t *testing.T)           { stagedRun(t, stagedOff) }
func TestNetlinkStagedRunUplinkLiveDefault(t *testing.T) { stagedRun(t, stagedUpLive) }
func TestNetlinkStagedRunUplinkNoDefault(t *testing.T)   { stagedRun(t, stagedUpNone) }

// a pass whose route writes move an overlay prefix's hold while its 5110 is staged deletes that 5110 ahead of them, and puts it
// back only once a reread of the routes shows the hold: a carve-out of the whole IPv4 prefix replaces its hold by a
// throw and back, every route write checked, so beside an exit default no overlay cell goes into the mesh at 5110 in between
func stagedHoldMoved(t *testing.T, l *stagedLab) {
	t.Helper()
	first := l.releaseOrder()[0]
	whole := prefix("10.20.0.0/16")
	overlayLookup := func() bool {
		return slices.ContainsFunc(rulesNow(t), func(rule DumpedRule) bool { return rule.Priority == priorityOverlay && rule.To == whole })
	}
	l.plat.set(func(p *stagedPlatform) { p.failAdd = func(rule Rule) bool { return rule == first } })
	_ = l.r.reconcile()
	if !overlayLookup() {
		t.Fatal("hold moved: the start that cannot release staged no 5110 for 10.20.0.0/16")
	}
	before := *l.network
	moved := before
	moved.IPv4.Links = append(slices.Clone(before.IPv4.Links), Link{Name: "cvh", Prefixes: []netip.Prefix{prefix("10.20.0.1/16")}})
	for _, step := range []struct {
		what    string
		network NetworkState
	}{{"the carve-out of the whole prefix", moved}, {"its end", before}} {
		*l.network = step.network
		var touched bool
		l.plat.set(func(p *stagedPlatform) {
			p.routeAfter = func(write string) {
				if !strings.Contains(write, " 10.20.0.0/16 ") && !strings.HasSuffix(write, " 10.20.0.0/16") && !strings.Contains(write, "10.20.0.0/16 ") {
					return
				}
				touched = true
				if overlayLookup() {
					t.Errorf("hold moved, %s: after %s the 5110 of 10.20.0.0/16 stands", step.what, write)
				}
				for _, c := range stagedCells[4] {
					if slices.Contains([]string{"o0", "oT", "oU", "l+o", "l-o"}, c.name) {
						if got := stagedAnswer(c); got == "M" {
							t.Errorf("hold moved, %s: after %s, %s/4 goes into the mesh", step.what, write, c.name)
						}
					}
				}
			}
		})
		_ = l.r.reconcile()
		l.plat.set(func(p *stagedPlatform) { p.routeAfter = nil })
		if !touched {
			t.Errorf("hold moved, %s: the pass wrote no route at 10.20.0.0/16", step.what)
		}
		if !overlayLookup() {
			t.Errorf("hold moved, %s: after the pass no 5110 of 10.20.0.0/16 stands, though the kernel holds its route", step.what)
		}
	}
	l.heal(t, "hold moved", 3)
	l.stop(t)
}

// stagedReload is a reload of the overlay from the lab's IPv4 prefix P to q, in mode off with main holding a route as long as P,
// from the completed down under P and from a start under P that staged its 5110: after the add of q's 32765 every
// write leaves the host's send to probe, inside q, refused, as the completed down under q does, and no pair of P stays.
func stagedReload(t *testing.T, q netip.Prefix, probe string, always bool) {
	l := newStagedLab(t, stagedOff)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	link, err := conn.link(0, "up0")
	if err != nil {
		t.Fatal(err)
	}
	for destination, gateway := range map[string]string{"10.20.0.0/16": "198.51.100.6", "172.16.0.0/12": "198.51.100.9"} {
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix(destination), batchHop{index: link.index, gateway: netip.MustParseAddr(gateway)})
	}
	reloaded := []schema.Prefix{schema.PrefixFrom(q), stagedOverlay[1]}
	refusalOfQ := "add " + downRules(reloaded)[0].String()
	for _, old := range []string{"pair", "staged"} {
		if err := l.r.reconcile(); err != nil {
			t.Fatal(err)
		}
		l.set = slices.Clone(l.ruleSet())
		l.stop(t)
		first := l.releaseOrder()[0]
		if old == "staged" {
			l.plat.set(func(p *stagedPlatform) { p.failAdd = func(rule Rule) bool { return rule == first } })
			_ = l.r.reconcile()
		}
		l.r.rt.Overlay = reloaded
		refusing := always
		l.plat.set(func(p *stagedPlatform) {
			p.failAdd = func(rule Rule) bool { return rule.Priority == priorityUplinkSource || rule.Priority == priorityMain }
			p.after = func(write string) {
				if write == refusalOfQ {
					refusing = true
				}
				if got := stagedAnswer(stagedCell{dst: probe}); refusing && !strings.HasPrefix(got, "F") {
					t.Errorf("reload to %s from the old %s: after %s the host's send to %s goes %s, want it refused", q, old, write, probe, got)
				}
			}
		})
		_ = l.r.reconcile()
		l.plat.set(func(p *stagedPlatform) { p.after, p.failAdd = nil, nil })
		if !refusing {
			t.Errorf("reload to %s from the old %s: the pass added no 32765 for it", q, old)
		}
		held := rulesNow(t)
		for _, rule := range downRules(stagedOverlay[:1]) {
			if holding(held, rule) && q != stagedOverlay[0].Prefix {
				t.Errorf("reload to %s from the old %s: %s of the removed prefix stands", q, old, rule)
			}
		}
		if got := stagedAnswer(stagedCell{dst: probe}); !strings.HasPrefix(got, "F") {
			t.Errorf("reload to %s from the old %s: after the pass the host's send to %s goes %s", q, old, probe, got)
		}
		if err := l.r.reconcile(); err != nil {
			t.Fatalf("reload to %s from the old %s: the pass after it: %v", q, old, err)
		}
		l.stop(t)
		l.r.rt.Overlay = stagedOverlay
		if err := l.r.reconcile(); err != nil {
			t.Fatalf("reload back from %s: %v", q, err)
		}
	}
}

func TestNetlinkStagedReloadDisjoint(t *testing.T) {
	stagedReload(t, prefix("172.31.0.0/24"), "172.31.0.9", false)
}

func TestNetlinkStagedReloadInside(t *testing.T) {
	// inside the old prefix the probe is refused before the reload, by the old pair, and at every write after it
	stagedReload(t, prefix("10.20.0.0/17"), "10.20.7.7", true)
}

func TestNetlinkStagedReloadContaining(t *testing.T) {
	stagedReload(t, prefix("10.16.0.0/12"), "10.17.0.9", false)
}

// stagedDebt seeds, beside a complete running set, each kind of down rule a delete cut short leaves, as a process starting anew
// finds it, and checks the record: a whole pair or a lone refusal, of the overlay or of a prefix a reload removed, is a
// delete owed by prefix, a lone lookup is deleted without a report, nothing reads as refused while down, and the running set
// stands throughout
func stagedDebt(t *testing.T, block stagedBlock) {
	l := newStagedLab(t, block)
	if err := l.r.reconcile(); err != nil {
		t.Fatal(err)
	}
	running := slices.Clone(l.ruleSet())
	// an idle pass over the running set lists the rules once and writes nothing
	l.plat.mu.Lock()
	listed := l.plat.ruleLists
	l.plat.mu.Unlock()
	l.plat.taken()
	if err := l.r.reconcile(); err != nil {
		t.Fatal(err)
	}
	l.plat.mu.Lock()
	listed = l.plat.ruleLists - listed
	l.plat.mu.Unlock()
	if writes := l.plat.taken(); listed != 1 || len(writes) != 0 {
		t.Errorf("an idle pass listed the rules %d times and wrote %v, want once and nothing", listed, writes)
	}
	removed := schema.PrefixFrom(prefix("10.30.0.0/16"))
	ours, theirs := downRules(stagedOverlay[:1]), downRules([]schema.Prefix{removed})
	for _, debt := range []struct {
		name string
		left []Rule
		owed []string
	}{
		{"a whole pair", ours, []string{"delete the pair of 10.20.0.0/16 (32765, 32764)"}},
		{"a lone refusal", ours[:1], []string{"delete the refusal of 10.20.0.0/16 (32765)"}},
		{"a lone lookup", ours[1:], nil},
		{"a removed prefix's pair", theirs, []string{"delete the pair of 10.30.0.0/16 (32765, 32764)"}},
		{"a removed prefix's lone refusal", theirs[:1], []string{"delete the refusal of 10.30.0.0/16 (32765)"}},
	} {
		for _, rule := range debt.left {
			if err := l.plat.netlinkPlatform.AddRule(rule); err != nil {
				t.Fatal(err)
			}
		}
		l.r = l.reconciler()
		l.plat.set(func(p *stagedPlatform) { p.failDel = isDownRule })
		if err := l.r.reconcile(); err == nil {
			t.Errorf("%s: the pass whose deletes fail reported no error", debt.name)
		}
		stats := l.r.routePass
		if stats.Held != 0 || stats.HeldUnknown || !slices.Equal(stats.Owed, debt.owed) {
			t.Errorf("%s: the record holds %d prefixes (not known %v) and owes %q, want 0 and %q", debt.name, stats.Held, stats.HeldUnknown, stats.Owed, debt.owed)
		}
		held := rulesNow(t)
		for _, rule := range running {
			if !holding(held, rule) {
				t.Errorf("%s: the running rule %s is gone", debt.name, rule)
			}
		}
		l.plat.set(func(p *stagedPlatform) { p.failDel = nil })
		if err := l.r.reconcile(); err != nil {
			t.Errorf("%s: the pass after it: %v", debt.name, err)
		}
		if stats := l.r.routePass; len(stats.Owed) != 0 || slices.ContainsFunc(rulesNow(t), func(rule DumpedRule) bool { return rule.Priority >= priorityDownMain }) {
			t.Errorf("%s: after the pass after it the record owes %q", debt.name, stats.Owed)
		}
	}
	// after a release whose every late add fails, the record owes each install from the pass of the commit on, on the passes after
	// it and on one that cannot list the tun's addresses, until a pass installs them
	l.stop(t)
	late := func(rule Rule) bool { return stepOf(rule.Priority, block.none) == stepLate }
	var installs []string
	for _, rule := range running {
		if late(rule) {
			installs = append(installs, "install "+rule.String())
		}
	}
	l.plat.set(func(p *stagedPlatform) { p.failAdd = late })
	for pass := range 2 {
		if err := l.r.reconcile(); err == nil {
			t.Errorf("late adds: pass %d reported no error", pass)
		}
		if owed := l.r.routePass.Owed; !slices.Equal(owed, installs) {
			t.Errorf("late adds: after pass %d the record owes %q, want %q", pass, owed, installs)
		}
	}
	if block.mode {
		l.plat.set(func(p *stagedPlatform) { p.failAddrs = true })
		_ = l.r.reconcile()
		if owed := l.r.routePass.Owed; !slices.Equal(owed, installs) {
			t.Errorf("late adds: after a pass whose address listing failed the record owes %q, want %q", owed, installs)
		}
	}
	l.plat.set(func(p *stagedPlatform) { p.failAdd, p.failAddrs = nil, false })
	if err := l.r.reconcile(); err != nil || len(l.r.routePass.Owed) != 0 {
		t.Errorf("late adds: the pass that installs them reported %v and owes %q", err, l.r.routePass.Owed)
	}
}

// stagedFarEndWait is how long a far end reads for a datagram sent before it, which the kernel queues on the tun in the send
const stagedFarEndWait = 100 * time.Millisecond

// stagedFarEnd makes the tun name and holds its far end, from which the test reads what the kernel sends out of it
func stagedFarEnd(t *testing.T, name string) *os.File {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("create tun %s: %v", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// stagedRead counts the IPv4 datagrams far reads within stagedFarEndWait, by destination
func stagedRead(t *testing.T, far *os.File) map[netip.Addr]int {
	t.Helper()
	counted := map[netip.Addr]int{}
	if err := far.SetReadDeadline(time.Now().Add(stagedFarEndWait)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	for {
		n, err := far.Read(packet)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return counted
		}
		if err != nil {
			t.Fatalf("read the far end of %s: %v", far.Name(), err)
		}
		if n >= 20 && packet[0]>>4 == 4 {
			counted[netip.AddrFrom4([4]byte(packet[16:20]))]++
		}
	}
}

// stagedSend sends one UDP datagram of the host's own to each of dsts, an error from the send being the kernel's refusal
func stagedSend(t *testing.T, dsts ...netip.Addr) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open a datagram socket: %v", err)
	}
	defer unix.Close(fd)
	for _, dst := range dsts {
		_ = unix.Sendto(fd, []byte("held?"), 0, &unix.SockaddrInet4{Port: 9, Addr: dst.As4()})
	}
}

// The release read at the packets, in mode off with main holding a route shorter than the IPv4 overlay prefix out of an uplink
// whose far end the test reads, and the mesh's tun read too: from the completed down through a start whose release is taken
// back at its last add and the pass that releases, after every rule write no datagram of the host's own to the mesh's address
// reaches the uplink's far end, one to an address outside the overlay does, and once released the mesh's address gets its
// datagram through the mesh's tun.
func TestNetlinkStagedReleaseAtTheUplinksFarEnd(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const meshName, uplinkName = "ranetpk0", "ranetpkup0"
	mesh, uplink := stagedFarEnd(t, meshName), stagedFarEnd(t, uplinkName)
	index := map[string]uint32{}
	for _, name := range []string{meshName, uplinkName} {
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	writeBatchAddress(t, conn, index[uplinkName], prefix("198.51.100.10/25"))
	for _, destination := range []string{"0.0.0.0/0", "192.0.2.0/24"} {
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix(destination), batchHop{index: index[uplinkName]})
	}
	tbl, rt := platformFor(meshName)
	rt.Overlay = downOverlay
	tbl = tbl.Normalized()
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := &stagedPlatform{netlinkPlatform: opened.(*netlinkPlatform)}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, prefix("192.0.2.7/32"), nil)
	routes.Set(netip.Prefix{}, prefix("3fff::7/128"), nil)
	r := newReconciler(tbl, rt, tbl.Assigned(nil), routes, plat)
	if err := r.reconcile(); err != nil {
		t.Fatalf("the running pass: %v", err)
	}
	order := inStep(*r.derived.Load(), stepFirst, false)
	if err := r.withdraw(errStopped); err != nil {
		t.Fatalf("the stop: %v", err)
	}
	held, outside := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("203.0.113.5")
	count := func() (up, meshed map[netip.Addr]int) {
		stagedRead(t, uplink)
		stagedRead(t, mesh)
		stagedSend(t, held, outside)
		return stagedRead(t, uplink), stagedRead(t, mesh)
	}
	checks := 0
	plat.set(func(p *stagedPlatform) {
		p.failAdd = func(rule Rule) bool { return rule == order[len(order)-1] }
		p.after = func(write string) {
			checks++
			if up, _ := count(); up[held] != 0 || up[outside] != 1 {
				t.Errorf("after %s the uplink's far end counted %v, want none to %s and one to %s", write, up, held, outside)
			}
		}
	})
	if err := r.reconcile(); err == nil {
		t.Error("the start whose last release add failed reported no error")
	}
	plat.set(func(p *stagedPlatform) { p.failAdd = nil })
	if err := r.reconcile(); err != nil {
		t.Fatalf("the pass that releases: %v", err)
	}
	plat.set(func(p *stagedPlatform) { p.after = nil })
	if checks == 0 {
		t.Fatal("the passes wrote no rule")
	}
	if up, meshed := count(); up[held] != 0 || up[outside] != 1 || meshed[held] != 1 {
		t.Errorf("once released the uplink's far end counted %v and the mesh's %v, want one to %s at the uplink and one to %s in the mesh", up, meshed, outside, held)
	}
}

func TestNetlinkStagedNoneLiveDefaultBothListingsFail(t *testing.T) {
	stagedBothListingsFail(t, stagedNoLive)
}
func TestNetlinkStagedNoneNoDefaultBothListingsFail(t *testing.T) {
	stagedBothListingsFail(t, stagedNoNodef)
}

// under fallback = "none", a pass from the completed down whose first listing of the rules and listing of the tun's addresses both
// fail: it adds the refusing rules of the staged set without a listing, 5490, 5400 and 5450 for lo and the forwarded link, and
// writes no other rule, so in both families the host's and the forwarded link's lookups the down set leaves to 5450 are refused
// (F5), the overlay's and the carve-out neighbor's among them, as a staged start under none refuses them
func stagedBothListingsFail(t *testing.T, block stagedBlock) {
	l := newStagedLab(t, block)
	l.references(t)
	l.plat.taken()
	l.plat.set(func(p *stagedPlatform) { p.listFails, p.failAddrs = true, true })
	if err := l.r.reconcile(); err == nil {
		t.Error("the pass whose listings failed reported no error")
	}
	l.plat.set(func(p *stagedPlatform) { p.failAddrs = false })
	var want []string
	for _, rule := range stagedRefusing(l.set) {
		want = append(want, "add "+rule.String())
	}
	if writes := l.plat.taken(); !slices.Equal(writes, want) {
		t.Errorf("the pass whose listings failed wrote %q, want %q", writes, want)
	}
	// the cells of a staged start under none whose route listing fails, which holds the down set and those three alone
	l.same(t, "the pass whose listings failed", l.cells(), l.want["GB L-listing"])
	l.closed(t, "the pass whose listings failed")
}

// stagedRefusing is the rules of set a start under fallback = "none" brings in at its entry beside the staged ones, 5490, 5400 and
// 5450, in set's order
func stagedRefusing(set []Rule) []Rule {
	return slices.DeleteFunc(slices.Clone(set), func(rule Rule) bool {
		return stepOf(rule.Priority, true) != stepStaged || stepOf(rule.Priority, false) == stepStaged
	})
}

func TestNetlinkStagedNoneLiveDefaultFirstRuleListingFails(t *testing.T) {
	stagedFirstRuleListingFails(t, stagedNoLive)
}
func TestNetlinkStagedNoneNoDefaultFirstRuleListingFails(t *testing.T) {
	stagedFirstRuleListingFails(t, stagedNoNodef)
}

// under fallback = "none", a pass from the completed down whose first listing of the rules alone fails holds the host's and the
// forwarded link's traffic outside the overlay refused at each of its route writes, as the refusing rules go in ahead of them
func stagedFirstRuleListingFails(t *testing.T, block stagedBlock) {
	l := newStagedLab(t, block)
	l.references(t)
	writes := 0
	l.plat.set(func(p *stagedPlatform) {
		p.listFails = true
		p.routeAfter = func(write string) {
			writes++
			l.closed(t, "after "+write)
		}
	})
	_ = l.r.reconcile()
	l.plat.set(func(p *stagedPlatform) { p.routeAfter = nil })
	if writes == 0 {
		t.Fatal("the pass whose first rule listing failed wrote no route")
	}
}

// under fallback = "none", a pass from the completed down whose listings of the rules and of the tun's addresses both fail and whose
// adds of 5490 and 5450 fail: its error names each of those rules beside the listing's failure, and no rule whose add landed
func TestNetlinkStagedBlindRefusalFailureIsThePassesError(t *testing.T) {
	l := newStagedLab(t, stagedNoLive)
	l.references(t)
	failing := func(rule Rule) bool { return rule.Priority == priorityMeshEnd || rule.Priority == priorityRefused }
	refusing := stagedRefusing(l.set)
	l.plat.set(func(p *stagedPlatform) { p.listFails, p.failAddrs, p.failAdd = true, true, failing })
	err := l.r.reconcile()
	l.plat.set(func(p *stagedPlatform) { p.failAddrs, p.failAdd = false, nil })
	if err == nil {
		t.Fatal("the pass whose listings and adds failed reported no error")
	}
	if !strings.Contains(err.Error(), "list rules") {
		t.Errorf("the pass's error %q does not name the failed listing of the rules", err)
	}
	named := 0
	for _, rule := range refusing {
		says := strings.Count(err.Error(), "add rule "+rule.String()+":")
		switch {
		case failing(rule) && says != 1:
			t.Errorf("the pass's error names the failed add of %s %d times, want once: %q", rule, says, err)
		case !failing(rule) && says != 0:
			t.Errorf("the pass's error names the add of %s, which landed: %q", rule, err)
		}
		if failing(rule) {
			named++
		}
	}
	if named < 2 {
		t.Fatalf("the row failed %d adds, want more than one", named)
	}
}

// the refusing rules a pass under fallback = "none" adds without a listing, each already standing beside a running set, stand once
// each after it, as the kernel answers each add with EEXIST, and the stop's withdrawal after it leaves none of them
func TestNetlinkStagedBlindRefusalTakesNoSecondCopy(t *testing.T) {
	l := newStagedLab(t, stagedNoLive)
	l.references(t)
	if err := l.r.reconcile(); err != nil {
		t.Fatalf("the running pass: %v", err)
	}
	refusing := stagedRefusing(l.set)
	l.plat.taken()
	l.plat.set(func(p *stagedPlatform) { p.listFails = true })
	_ = l.r.reconcile()
	adds := 0
	for _, write := range l.plat.taken() {
		if slices.ContainsFunc(refusing, func(rule Rule) bool { return write == "add "+rule.String() }) {
			adds++
		}
	}
	if adds != len(refusing) {
		t.Errorf("the pass whose rule listing failed added %d of the %d refusing rules, want each", adds, len(refusing))
	}
	held := rulesNow(t)
	for _, rule := range refusing {
		if copies := len(slices.DeleteFunc(slices.Clone(held), func(d DumpedRule) bool { return d != rule.dumped(DefaultProtocol) })); copies != 1 {
			t.Errorf("after the add over a standing %s the kernel holds %d copies, want 1", rule, copies)
		}
	}
	l.stop(t)
	held = rulesNow(t)
	for _, rule := range refusing {
		if holding(held, rule) {
			t.Errorf("after the stop the kernel still holds %s", rule)
		}
	}
}

// stagedReachBudget is how long a start through Run may take to run from the completed down past three failed passes, the retry's
// 1, 2 and 4 seconds with room for a loaded machine, against a sweep an hour off
const stagedReachBudget = 30 * time.Second

// a start through Run from the completed down whose first hold add, first release add and first delete of a refusal after the
// commit each fail once runs, each failed pass woken again by the retry and none waiting on the notification of its own route
// writes, which wakes no pass: with the sweep an hour off the derived set stands whole and the down set is gone within
// stagedReachBudget, every write the faults armed met
func TestNetlinkStagedStartThroughRunWaitsOnNoOwnRouteWrite(t *testing.T) {
	l := newStagedLab(t, stagedOff)
	l.references(t)
	l.tbl.Reconcile = schema.Duration(time.Hour)
	l.r = l.reconciler()
	first := l.releaseOrder()[0]
	holdFails, addFails, delFails := 1, 1, 1
	l.plat.set(func(p *stagedPlatform) {
		p.failRoute = func(route Route) bool {
			if holdFails > 0 && route.Unreachable && slices.Contains(SchemaPrefixes(stagedOverlay), route.Destination) {
				holdFails--
				return true
			}
			return false
		}
		p.failAdd = func(rule Rule) bool {
			if addFails > 0 && rule == first {
				addFails--
				return true
			}
			return false
		}
		p.failDel = func(rule Rule) bool {
			if delFails > 0 && rule.Priority == priorityDownRefused && isDownRule(rule) {
				delFails--
				return true
			}
			return false
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(stagedRunWait):
			t.Error("run did not return after its cancel")
		}
	})
	deadline := time.Now().Add(stagedReachBudget)
	running := func() bool {
		held := rulesNow(t)
		return !slices.ContainsFunc(downRules(stagedOverlay), func(rule Rule) bool { return holding(held, rule) }) &&
			!slices.ContainsFunc(l.set, func(rule Rule) bool { return !holding(held, rule) })
	}
	for !running() && time.Now().Before(deadline) {
		time.Sleep(stagedPoll)
	}
	if !running() {
		t.Fatalf("the start through Run did not run within %s, the sweep an hour off", stagedReachBudget)
	}
	l.plat.mu.Lock()
	left := holdFails + addFails + delFails
	l.plat.mu.Unlock()
	if left != 0 {
		t.Errorf("%d of the three armed failures were never met", left)
	}
	l.plat.set(func(p *stagedPlatform) { p.failRoute, p.failAdd, p.failDel = nil, nil, nil })
}

func TestNetlinkStagedDebtModeOff(t *testing.T)           { stagedDebt(t, stagedOff) }
func TestNetlinkStagedDebtUplinkLiveDefault(t *testing.T) { stagedDebt(t, stagedUpLive) }
func TestNetlinkStagedDebtNoneLiveDefault(t *testing.T)   { stagedDebt(t, stagedNoLive) }

// stagedNotice is a rule delete's notification as a monitor taking what the reconciler's takes read it: the port of the socket
// that deleted the rule and whether the reconciler's monitor wakes on it
type stagedNotice struct {
	port uint32
	wake bool
}

// stagedNotices opens a monitor of the rule groups beside the lab's platform with the platform's own verdict, reconcilerWakes with
// the platform socket's port, and returns the platform's port and a read of the rule deletes' notifications so far
func stagedNotices(t *testing.T, l *stagedLab) (uint32, func() []stagedNotice) {
	t.Helper()
	plat := l.plat.netlinkPlatform
	port := plat.conn.(*nlConn).socket.Pid()
	wakes := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index, port, nil)
	var mu sync.Mutex
	var seen []stagedNotice
	watch, err := openMonitor("staged-notices", unix.RTMGRP_IPV4_RULE|1<<(unix.RTNLGRP_IPV6_RULE-1), func(message netlink.Message) bool {
		wake := wakes(message)
		if message.Kind == unix.RTM_DELRULE {
			mu.Lock()
			seen = append(seen, stagedNotice{port: message.Pid, wake: wake})
			mu.Unlock()
		}
		return wake
	})
	if err != nil {
		t.Fatalf("open a monitor of the rule groups: %v", err)
	}
	t.Cleanup(func() { _ = watch.Close() })
	return port, func() []stagedNotice {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// stagedDeletes counts the rule deletes that landed among writes
func stagedDeletes(writes []string) int {
	n := 0
	for _, write := range writes {
		if strings.HasPrefix(write, "delete ") && !strings.HasSuffix(write, "(failed)") {
			n++
		}
	}
	return n
}

// a release that fails before its commit point at its last add, the same at every pass, takes back every rule it put by deletes
// whose notifications carry the platform's port and wake no pass, counted against the deletes the passes made and not against a
// clock, while another writer's delete of a rule a take-back deletes, between two such passes, wakes one. The retry's delay is
// TestRetryBacksOffUpToTheSweepAndStartsOverAfterAPass's, where Failed computes it.
func TestNetlinkStagedFailingReleaseWakesNoPassByItsOwnDeletes(t *testing.T) {
	l := newStagedLab(t, stagedOff)
	l.references(t)
	order := l.releaseOrder()
	last := order[len(order)-1]
	port, notices := stagedNotices(t, l)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	l.plat.set(func(p *stagedPlatform) { p.failAdd = func(rule Rule) bool { return rule == last } })
	l.plat.taken()
	own := 0
	failing := func(pass int) {
		t.Helper()
		if err := l.r.reconcile(); err == nil {
			t.Fatalf("failing release %d reported no error", pass)
		}
		writes := l.plat.taken()
		if !slices.Contains(writes, "add "+last.String()+" (failed)") {
			t.Fatalf("failing release %d did not meet its failing add: %q", pass, writes)
		}
		own += stagedDeletes(writes)
	}
	const releases = 3
	for pass := range releases {
		failing(pass)
	}
	if own < releases {
		t.Fatalf("%d failing releases made %d rule deletes, want one at least each", releases, own)
	}
	waitFor(t, func() bool { return len(notices()) >= own })
	// another writer puts the first rule a take-back deletes back and deletes it, through a socket of its own
	foreign := order[0]
	body := l.plat.netlinkPlatform.ruleMessage(foreign)
	if _, err := conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("add %s as another writer: %v", foreign, err)
	}
	if _, err := conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("delete %s as another writer: %v", foreign, err)
	}
	waitFor(t, func() bool { return len(notices()) >= own+1 })
	failing(releases)
	waitFor(t, func() bool { return len(notices()) >= own+1 })
	got := notices()
	if len(got) != own+1 {
		t.Fatalf("the monitor read %d rule deletes' notifications, want the %d the passes made and the other writer's one", len(got), own+1)
	}
	foreignAt := slices.IndexFunc(got, func(n stagedNotice) bool { return n.port != port })
	for i, n := range got {
		switch {
		case i == foreignAt && !n.wake:
			t.Errorf("the other writer's delete, port %d, woke no pass", n.port)
		case i != foreignAt && (n.port != port || n.wake):
			t.Errorf("notification %d carries port %d and wakes %v, want the platform's %d and no wake", i, n.port, n.wake, port)
		}
	}
	if foreignAt < 0 || slices.ContainsFunc(got[foreignAt+1:], func(n stagedNotice) bool { return n.port != port }) {
		t.Errorf("the notifications hold %d of another writer's, want exactly one: %v", len(got)-own, got)
	}
}

// another writer's delete of a running node's IPv4 5110, before, after or between the reconciler's own delete and add of the same
// rule, all made inside a pass after its listing of the rules, as its own writes are, wakes the pass after it through Run, whose
// sweep is an hour off, so that pass has run and the rule stands within the wait
func TestNetlinkStagedAnotherWritersDeleteBesideItsOwnWakesAPass(t *testing.T) {
	l := newStagedLab(t, stagedOff)
	l.tbl.Reconcile = schema.Duration(time.Hour)
	l.r = l.reconciler()
	if err := l.r.reconcile(); err != nil {
		t.Fatalf("the running pass: %v", err)
	}
	var hold Rule
	for _, rule := range l.ruleSet() {
		if rule.Family == FamilyIPv4 && rule.Priority == priorityOverlay {
			hold = rule
		}
	}
	_, notices := stagedNotices(t, l)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	body := l.plat.netlinkPlatform.ruleMessage(hold)
	inner := l.plat.netlinkPlatform
	// each act runs in the pass's goroutine, the own ones on the platform's socket and the other writer's on the test's
	acts := map[string]func() error{
		"another writer's delete": func() error { _, err := conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, body); return err },
		"another writer's add": func() error {
			_, err := conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body)
			return err
		},
		"its own delete": func() error { return inner.DelRule(hold) },
		"its own add":    func() error { return inner.AddRule(hold) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(stagedRunWait):
			t.Error("run did not return after its cancel")
		}
	})
	<-l.r.FirstPass()
	lists := func() int {
		l.plat.mu.Lock()
		defer l.plat.mu.Unlock()
		return l.plat.ruleLists
	}
	for i, form := range []struct {
		name string
		acts []string
	}{
		{"before", []string{"another writer's delete", "its own delete", "its own add"}},
		{"after", []string{"its own delete", "its own add", "another writer's delete"}},
		{"between", []string{"its own delete", "another writer's add", "another writer's delete", "its own add"}},
	} {
		var mu sync.Mutex
		hosted, read := -1, 0
		l.plat.set(func(p *stagedPlatform) {
			p.onRoutes = func() {
				l.plat.set(func(p *stagedPlatform) { p.onRoutes = nil })
				mu.Lock()
				defer mu.Unlock()
				hosted, read = lists(), len(notices())
				for _, name := range form.acts {
					if err := acts[name](); err != nil {
						t.Errorf("%s: %s of %s: %v", form.name, name, hold, err)
					}
				}
			}
		})
		// a route of the mesh's that the pass writes, so a pass runs and hosts the acts
		l.routes.Set(netip.Prefix{}, prefix(fmt.Sprintf("10.20.77.%d/32", i+1)), nil)
		waitFor(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return hosted >= 0 && lists() > hosted && holding(rulesNow(t), hold)
		})
		mu.Lock()
		after := notices()[read:]
		mu.Unlock()
		if !slices.ContainsFunc(after, func(n stagedNotice) bool { return n.wake }) {
			t.Errorf("%s: no rule delete's notification woke a pass: %v", form.name, after)
		}
		if own := slices.ContainsFunc(after, func(n stagedNotice) bool { return n.wake && n.port == inner.conn.(*nlConn).socket.Pid() }); own {
			t.Errorf("%s: the reconciler's own delete woke a pass: %v", form.name, after)
		}
	}
}
