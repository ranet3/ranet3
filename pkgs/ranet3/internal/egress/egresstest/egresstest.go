// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package egresstest is the exit behavior suite: what every backend behind
// egress.Exit owes a leaf, whichever platform carries it. It drives a backend
// through the seam as the dataplane does, playing the leaf, whose packets it
// hands to Egress while their family is ready and announced, as the dataplane
// does for a prefix cap.egress advertises, and the server beyond the exit's
// uplink, and it reads what comes back toward the leaf. A backend's own tests
// run it with an Arm that builds the backend and names the classes it
// carries, on a Network that a platform's harness builds. Only tests import
// it.
package egresstest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// Class names the source the leaf's packets leave the exit under, as a class
// of cap.egress translate does
type Class int

const (
	// Auto is the address of the link the packet leaves by
	Auto Class = iota
	// Address is an address of the exit's that the network routes back to it
	Address
	// None is the leaf's own address, which the network routes back to the
	// exit
	None
	// Inside is Address for the leaf's address alone, inside None for the rest
	// of the overlay prefix, the spare address's among it. Only row 6 runs
	// under it.
	Inside
)

func (c Class) String() string {
	switch c {
	case Address:
		return "address"
	case None:
		return "none"
	case Inside:
		return "address inside none"
	}
	return "auto"
}

// classes is the capability's translate under c: no class for Auto, an
// address from every source of each family for Address, none from the leaf's
// overlay prefix of each family for None, and for Inside that none and an
// address from the leaf's own address
func (c Class) classes(families ...Family) []egress.Class {
	var out []egress.Class
	for _, family := range families {
		switch c {
		case Address:
			out = append(out, egress.Class{From: schema.PrefixFrom(every(family.Overlay)), To: egress.Translation{Addr: family.Class}})
		case None:
			out = append(out, egress.Class{From: schema.PrefixFrom(family.Overlay), To: egress.Translation{None: true}})
		case Inside:
			out = append(out,
				egress.Class{From: schema.PrefixFrom(family.Overlay), To: egress.Translation{None: true}},
				egress.Class{From: schema.PrefixFrom(netip.PrefixFrom(family.Leaf, family.Leaf.BitLen())), To: egress.Translation{Addr: family.Class}})
		}
	}
	return out
}

// seen is the address the server reads family's packets from under c
func (c Class) seen(family Family) netip.Addr {
	switch c {
	case Address, Inside:
		return family.Class
	case None:
		return family.Leaf
	}
	return family.Uplink
}

// spareUnderNone is whether the spare address's flows leave under none
func (c Class) spareUnderNone() bool { return c == None || c == Inside }

// Family is a network's addresses and links in one address family
type Family struct {
	// Name names the family in a test's name
	Name string
	// Leaf is the leaf's address, inside the mesh's Overlay, and Exit every
	// address the exit holds. Spare is a second address of the leaf's inside
	// Overlay, which no socket of the leaf's takes as its source unless it binds
	// to it, so a backend counts of its flows, when the limit's row begins, only
	// those the rows before it left open.
	Leaf, Spare netip.Addr
	Overlay     netip.Prefix
	Exit        []netip.Addr
	// Uplink is the exit's address on the link it sends out of, which Auto
	// translates to, and Class one of its others, which Address translates to
	Uplink, Class netip.Addr
	// Server, Transfer and Second are the server's, Transfer the transfer's
	// alone and Second the other destination of one leaf port
	Server, Transfer, Second netip.Addr
	// Router is the router beyond the exit, which answers for the links behind
	// it: Narrow is the server's beyond a link of NarrowMTU, NoHost is on a
	// link of the router's where nothing holds it, and NoNetwork in no network
	// the router routes
	Router, Narrow, NoHost, NoNetwork netip.Addr
	// MeshMTU is the mesh's, which every packet of the leaf's fits, UplinkMTU
	// the exit's uplink's below it, and NarrowMTU below that
	MeshMTU, UplinkMTU, NarrowMTU int
}

// Host is the exit's side of a network, which an arm builds its backend on
type Host struct {
	// Do runs f where the exit's devices live, which a backend's constructor
	// and its reads of the host need
	Do func(f func() error) error
	// TUN is the mesh device's name, and Write its writer
	TUN   string
	Write func(frames [][]byte, hold netstack.Hold)
	// Mesh is the exit's addresses on the mesh, and Members the prefixes its
	// mesh routes to other nodes, the leaf's
	Mesh    []netip.Addr
	Members func() []netip.Prefix
	// Lanes is the exit's mesh, whose lanes carry a backend's own packets
	// toward the leaf into the mesh's outbound path
	Lanes *netstack.Mesh
}

// Network is a leaf, an exit's host and a server beyond the exit's uplink,
// built anew for each class so that no class meets another's state. The
// server reads what the exit sends from any source, the leaf's own among
// them, so a packet the exit leaves untranslated reaches it. The server's side
// drops each SYN without ACK to simultaneousPort, the simultaneous open's.
type Network interface {
	// Family is the network in IPv6 where v6 is set and in IPv4 where it is not
	Family(v6 bool) Family
	Exit() Host
	// Leaf and Server run f in the leaf's and the server's stack, which keeps
	// every socket f opens
	Leaf(f func() error) error
	Server(f func() error) error
	// Carry hands hand each batch of the packets the leaf's stack sends out of
	// the mesh, from the call until the test ends
	Carry(hand func(packets [][]byte))
	// Back is every packet that came back toward the leaf, in the order it came
	Back() [][]byte
}

// Limit is a behavior an RFC asks of a NAT that a backend lacks by its nature.
// Its arm declares it with the platform's reason and the deviations row that
// records it, and the row holds the backend to what it does instead.
type Limit int

const (
	// PortDependentFiltering admits to a mapping only the replies of the flow
	// that opened it, where RFC 4787 REQ-8 recommends endpoint independent
	// filtering and allows address dependent, each of which admits a datagram
	// from the mapped server's address at another port
	PortDependentFiltering Limit = iota
	// NoHairpinning takes a packet to a mapping on the exit's own address as
	// the exit's, where RFC 4787 REQ-9 and RFC 5382 REQ-8 have the exit carry
	// it to the leaf that holds the mapping
	NoHairpinning
	// UnansweredIPv4DCCP refuses an IPv4 DCCP packet it cannot translate with
	// no answer, where RFC 5508 REQ-8 has a NAT answer a flow it cannot set up
	// with an ICMP destination unreachable of code 13
	UnansweredIPv4DCCP
	// UnansweredUDPLite refuses a UDP-Lite packet it cannot translate with no
	// answer and drops the reply into the mesh to one it carries under none,
	// in either family, where RFC 5508 REQ-8 has a NAT answer the first as for
	// UnansweredIPv4DCCP
	UnansweredUDPLite
	// ResetsUnsolicitedSYN answers a SYN from outside to a port of the exit's
	// that no mapping holds with a reset at once, where RFC 5382 REQ-4 has a
	// NAT answer none for at least 6 seconds
	ResetsUnsolicitedSYN
	// NoInboundTCP ends each connection the leaf opens at the exit and opens
	// its own toward the server, so no connection from outside reaches the
	// leaf, where RFC 5382 REQ-3 and REQ-8 have the exit carry one to a
	// mapping. A simultaneous open still opens, since the exit's own socket in
	// SYN-SENT meets the server's SYN, so REQ-2a holds.
	NoInboundTCP
	// RefusesOtherProtocols carries TCP, UDP and ICMP alone and answers a
	// packet of any other protocol with code 13 over IPv4 and code 1 over
	// IPv6, where RFC 5508 REQ-8 and RFC 6888 REQ-1 have an exit carry a
	// protocol it need not translate as it is
	RefusesOtherProtocols
	// UnrelayedLeafErrors drops the leaf's own ICMP error about a flow, where
	// RFC 5508 REQ-5 has the exit carry it to the server from the mapping
	UnrelayedLeafErrors
	// NoLowPorts gives a leaf's port below 1024 a port of 1024 or above, where
	// RFC 4787 REQ-3 recommends one below 1024
	NoLowPorts
	// OverloadsPorts gives two inside endpoints' UDP flows from one port one
	// external endpoint toward two destinations, the port overloading RFC 4787
	// section 4.2.1 REQ-3 rules out. The suite checks it in UDP alone.
	OverloadsPorts
	// RemapsOnClash takes another external port for an inside endpoint's UDP
	// flow toward a destination that another inside endpoint's flow from the
	// same port reached first, where RFC 4787 section 4.1 REQ-1 and section 8
	// REQ-11 have one mapping serve the endpoint toward every destination. The
	// suite checks it in UDP alone.
	RemapsOnClash
	// OverloadsTCPPorts gives two inside endpoints' connections from one port
	// one external endpoint toward two destinations, the port overloading RFC
	// 5382 section 7.1 REQ-7 rules out
	OverloadsTCPPorts
	// RemapsTCPOnClash takes another external port for an inside endpoint's
	// connection toward a destination that another inside endpoint's
	// connection from the same port reached first, where RFC 5382 section 4.1
	// REQ-1 has one mapping serve the endpoint toward every destination
	RemapsTCPOnClash
)

func (l Limit) String() string {
	switch l {
	case PortDependentFiltering:
		return "port dependent filtering"
	case NoHairpinning:
		return "no hairpinning"
	case UnansweredIPv4DCCP:
		return "unanswered ipv4 dccp"
	case UnansweredUDPLite:
		return "unanswered udp-lite"
	case ResetsUnsolicitedSYN:
		return "resets an unsolicited syn"
	case NoInboundTCP:
		return "no inbound tcp"
	case RefusesOtherProtocols:
		return "refuses other protocols"
	case UnrelayedLeafErrors:
		return "unrelayed leaf errors"
	case NoLowPorts:
		return "no low ports"
	case OverloadsPorts:
		return "overloads ports"
	case RemapsOnClash:
		return "remaps on a clash"
	case OverloadsTCPPorts:
		return "overloads tcp ports"
	case RemapsTCPOnClash:
		return "remaps tcp on a clash"
	}
	return fmt.Sprintf("limit %d", int(l))
}

// Declared is a limit's reason on its platform, and the row of the deviations
// page that records it, named as the page's first column names it
type Declared struct{ Reason, Row string }

// Missed is the reason a backend's count of a source's flows can leave a flow
// open and uncounted, and the row of the limits page that records it, named
// as the page's first column names it
type Missed struct{ Reason, LimitsRow string }

// Arm is a backend as the suite runs it. The suite holds every arm to all
// six rows in both families, to carrying every protocol it can translate and
// refusing those it cannot, to carrying no ICMP message RFC 5508 rules out, to
// Egress from several sessions at once, to the mappings, port ranges,
// fragments, errors and simultaneous open of RFC 4787 and RFC 5382, to
// filtering, hairpinning, the unsolicited SYN and one port of two inside
// endpoints in UDP and TCP as those RFCs ask or as its arm declares it does
// instead, to a withdrawal and a restore by SetEnabled and a batch judged
// ready before that withdrawal reaching it after, and to the share of
// flows its capability names, counted exactly or as its arm declares its count
// misses, and an arm that reads its flows to the idle timers it keeps them to.
// An arm that crosses is held to frames of new flows handed across its stops
// and the starts after them leaving under their class's address or not at all.
type Arm struct {
	// Classes are the source classes the backend carries, at least one
	Classes []Class
	// Limits names each behavior the backend lacks by its nature, with its
	// reason and deviations row
	Limits map[Limit]Declared
	// MissesFlows declares that the backend's count of a source's flows can
	// leave a flow open and uncounted, nil for a backend whose count is exact
	MissesFlows *Missed
	// Terminates is set for a backend that ends the leaf's TCP at the exit and
	// opens its own toward the server, which forwards none of the leaf's
	// segments and so owes no too big for them
	Terminates bool
	// New builds the backend on host for cfg, reporting through hooks
	New func(t testing.TB, host Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit
	// Holds names what the backend holds on host, nothing once it has withdrawn
	Holds func(host Host) ([]string, error)
	// Stopped reads in Status whether the backend, held off by SetEnabled, has
	// what Holds read before in place with a drop of every packet out of the
	// mesh it would translate, nil for a backend that holds nothing while off.
	// What such a backend holds passes a packet of a class of none, a reply
	// toward the leaf of a flow it translated before, and a packet between two
	// mesh addresses, and its drop meets a packet ahead of another writer's
	// masquerade wherever Masquerade puts it. A backend that holds nothing takes
	// no packet while off.
	Stopped func(egress.Status) bool
	// Crossings is how many times the step of frames across a stop takes the
	// backend off with SetEnabled and puts it back, each with frames of new
	// flows handed throughout, and again beside another writer's translation
	// that translates nothing where Untranslating is set, 0 for an arm that
	// leaves the step out
	Crossings int
	// Untranslating has another writer hold a chain where the host translates
	// sources, with no rule in it, and returns what takes it away again
	Untranslating func(host Host) (undo func() error, err error)
	// Remove takes what carries the backend's translation of both families off
	// host in one transaction, as another writer would, nil for a backend
	// nothing else on the host can change
	Remove func(host Host) error
	// Beside starts a second owner of the table the backend writes in, on the
	// exit's host as that host runs it beside the backend, nil for a backend
	// that shares its table with no other owner
	Beside func(t *testing.T, network Network) Owner
	// Reload is another writer's reload of the whole ruleset of host, as a
	// host firewall's restart makes it, which takes what the backend and the
	// second owner write. It is set where Beside is.
	Reload func(host Host) error
	// Masquerade has another writer masquerade every packet leaving host, made
	// after the backend's translation, where the host's own source translation
	// runs, or where ahead is set at a place the host runs ahead of the
	// backend's, and returns what takes it away again. It is nil for a backend
	// whose translation no other writer's can meet.
	Masquerade func(host Host, ahead bool) (undo func() error, err error)
	// Flows reads every flow the backend tracks on host, nil for a backend
	// that cannot read how long it keeps each
	Flows func(host Host) ([]Flow, error)
}

// Owner is a second owner of a backend's table, as Arm.Beside starts it
type Owner struct {
	// Ready is whether the owner's last pass read its own back as written
	Ready func() bool
	// Unready is how often the owner has reported itself not ready
	Unready func() int
}

func (a Arm) check() error {
	if len(a.Classes) == 0 {
		return errors.New("the arm names no class it carries, so no row would run")
	}
	if (a.Beside == nil) != (a.Reload == nil) {
		return errors.New("the arm names a second owner without the reload it is held to, or a reload without the owner")
	}
	if a.Untranslating != nil && a.Crossings == 0 {
		return errors.New("the arm names another writer's translation for the step of frames across a stop, which it leaves out")
	}
	for limit, declared := range a.Limits {
		if declared.Reason == "" || declared.Row == "" {
			return fmt.Errorf("the arm declares %s without its reason and its deviations row", limit)
		}
	}
	if m := a.MissesFlows; m != nil && (m.Reason == "" || m.LimitsRow == "") {
		return errors.New("the arm declares its count misses flows without its reason and its limits row")
	}
	return nil
}

// ones is how many of conditions hold
func ones(conditions ...bool) int {
	n := 0
	for _, c := range conditions {
		if c {
			n++
		}
	}
	return n
}

// level is a level of Run's subtests, counting each it makes, whether
// -test.run selects it or not, so a condition that leaves a class, a row or a step
// out of a level fails at holds and not in silence
type level struct {
	t    *testing.T
	made int
}

func (l *level) run(name string, f func(*testing.T)) {
	l.made++
	l.t.Run(name, f)
}

// holds fails the level unless it made want subtests
func (l *level) holds(want int) {
	l.t.Helper()
	if l.made != want {
		l.t.Errorf("the suite ran %d rows in %s, want %d", l.made, l.t.Name(), want)
	}
}

var defaults = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// every is the default of prefix's family
func every(prefix netip.Prefix) netip.Prefix {
	if prefix.Addr().Is4() {
		return defaults[0]
	}
	return defaults[1]
}

// Run holds arm to every row and step in both families under each of its
// classes, each on a network of its own that build makes, and to row 6 again
// under its first class at a share its capability names, and, for an arm that
// carries Address and None, under Inside at that share, with the frames across
// a stop under each class that translates for an arm that crosses. Row 6 comes
// last in a family, since it leaves the spare address at its limit.
func Run(t *testing.T, build func(t testing.TB) Network, arm Arm) {
	if err := arm.check(); err != nil {
		t.Fatal(err)
	}
	inside := slices.Contains(arm.Classes, Address) && slices.Contains(arm.Classes, None)
	top := &level{t: t}
	for _, class := range arm.Classes {
		top.run(class.String(), func(t *testing.T) {
			network := build(t)
			exit := start(t, network, arm, class, 0)
			under := &level{t: t}
			for _, v6 := range []bool{false, true} {
				r := &rows{network: network, family: network.Family(v6), class: class, exit: exit, terminates: arm.Terminates, flows: arm.Flows, limits: arm.Limits}
				under.run(r.family.Name, func(t *testing.T) {
					family := &level{t: t}
					r.steps(func(name string, step func(*testing.T)) { family.run(name, r.judged(step)) })
					// a family runs the steps of every class, the packets into the mesh for an arm that returns them, the quench in
					// IPv4 alone, the idle timers for an arm that reads its flows, and the steps of a class that translates
					family.holds(9 + ones(!arm.Terminates, !v6, arm.Flows != nil) + 10*ones(class != None))
				})
			}
			under.run("disabled and enabled", func(t *testing.T) { exit.disable(t, network, class) })
			under.run("a batch judged ready before a stop", func(t *testing.T) { exit.judgedBeforeStop(t, network, class) })
			crosses := arm.Crossings != 0 && class != None
			if crosses {
				under.run("frames across a stop", func(t *testing.T) { exit.crossings(t, network, class, arm) })
			}
			if arm.Remove != nil {
				under.run("another writer", func(t *testing.T) { exit.overwritten(t, network, class, arm.Remove) })
			}
			if arm.Beside != nil {
				under.run("another writer's reload beside a second owner", func(t *testing.T) { exit.reloaded(t, network, arm.Beside, arm.Reload) })
			}
			if arm.Masquerade != nil {
				under.run("another writer's translation", func(t *testing.T) { exit.masqueraded(t, network, class, arm.Masquerade) })
			}
			under.run("stop", exit.stop)
			// a class runs both families, the disabling, the batch before a stop, the frames across a stop under a class that
			// translates for an arm that crosses, another writer for each the arm can play, and the stop
			under.holds(5 + ones(crosses, arm.Remove != nil, arm.Beside != nil, arm.Masquerade != nil))
		})
	}
	top.run("a share the capability names", func(t *testing.T) {
		class := arm.Classes[0]
		network := build(t)
		exit := start(t, network, arm, class, namedLimit)
		share := &level{t: t}
		for _, v6 := range []bool{false, true} {
			r := &rows{network: network, family: network.Family(v6), class: class, exit: exit, terminates: arm.Terminates, flows: arm.Flows, limits: arm.Limits}
			share.run(r.family.Name, r.judged(r.sourceLimit))
		}
		share.run("stop", exit.stop)
		share.holds(3)
	})
	if inside {
		// a class that translates inside a class of none meets the limit as every
		// translating class does, and the sources of the class of none around it
		// pass ahead of the limit uncounted
		top.run("a class that translates inside one of none", func(t *testing.T) {
			network := build(t)
			exit := start(t, network, arm, Inside, namedLimit)
			share := &level{t: t}
			for _, v6 := range []bool{false, true} {
				r := &rows{network: network, family: network.Family(v6), class: Inside, exit: exit, terminates: arm.Terminates, flows: arm.Flows, limits: arm.Limits}
				share.run(r.family.Name, r.judged(r.sourceLimit))
			}
			// the class that translates is dropped ahead of the class of none it lies inside
			share.run("a batch judged ready before a stop", func(t *testing.T) { exit.judgedBeforeStop(t, network, Inside) })
			if arm.Crossings != 0 {
				share.run("frames across a stop", func(t *testing.T) { exit.crossings(t, network, Inside, arm) })
			}
			share.run("stop", exit.stop)
			share.holds(4 + ones(arm.Crossings != 0))
		})
	}
	// the run makes each class of the arm's, the share, and Inside for an arm that carries Address and None
	top.holds(len(arm.Classes) + 1 + ones(inside))
}

// steps makes a family's steps through step, holding no testing.T of its own,
// so each subtest of a family is a step the family's level counts
func (r *rows) steps(step func(name string, run func(*testing.T))) {
	step("what the server sees", r.serverSees)
	step("errors toward the leaf", r.errorsTowardTheLeaf)
	step("path mtu", r.pathMTU)
	step("hop limits", r.hopLimits)
	step("port reuse", r.portReuse)
	step("egress from several sessions at once", r.sessions)
	step("packets no flow is tracked for", r.untracked)
	// a backend that terminates refuses return, so nothing goes into the mesh
	if !r.terminates {
		step("packets into the mesh no flow is tracked for", r.untrackedInto)
	}
	if !r.v6() {
		step("icmp a nat does not carry", r.icmpNotCarried)
	}
	step("protocols whose checksum covers the addresses", r.checksummed)
	if r.flows != nil {
		step("idle timers", r.timers)
	}
	if r.class != None {
		step("filtering", r.filtering)
		step("hairpinning", r.hairpinning)
		step("tcp filtering", r.tcpFiltering)
		step("tcp hairpinning", r.tcpHairpinning)
		step("simultaneous open", r.simultaneousOpen)
		step("unsolicited syn", r.unsolicitedSYN)
		step("port ranges", r.portRanges)
		step("one port of two inside endpoints", r.portClash)
		step("out of order fragments", r.fragments)
		step("a mapping surviving an error", r.errorKeepsMapping)
	}
	step("the limit on a source's flows", r.sourceLimit)
}

// running is a backend under test, built for cfg, with what its hooks were
// told
type running struct {
	egress.Exit
	cfg     egress.Egress
	host    Host
	holds   func(Host) ([]string, error)
	stopped func(egress.Status) bool
	flows   func(Host) ([]Flow, error)
	misses  *Missed
	cancel  context.CancelFunc
	// done is closed once Run has returned err
	done chan struct{}
	err  error

	// carries4 and carries6 are each family's word for the prefixes
	// cap.egress advertises as a node keeps it, ready as Ready last told it
	// and announced as Announce answered at the last hook, which hand reads as
	// the dataplane reads the word
	carries4, carries6 atomic.Bool

	mu             sync.Mutex
	ready4, ready6 bool
	// told is every call of Ready, and announced what Announce answered at
	// every call of Republish
	told      []readiness
	announced [][]netip.Prefix
	// handed is every packet handed to Egress, as the leaf sent it
	handed [][]byte
	// withdrawing records the withdrawal under way as the hooks see it, nil
	// while none is
	withdrawing *withdrawal
	// dropped is called on Ready's caller with the families the word stopped
	// carrying because Ready took them, nil while no step watches for it
	dropped func(v4, v6 bool)
	// withheld matches the leaf's packets hand loses, as a path losing them
	// would, nil while no step loses any
	withheld func(packet []byte) bool
}

type readiness struct{ v4, v6, serves bool }

// withdrawal holds the backend's holdings when Ready first said neither family
// is ready and when Republish first read an empty announcement, with the
// reads' errors, and whether a family was ready and announced when it began
type withdrawal struct {
	wasReady, wasAnnounced       bool
	toldNone, republishedNone    bool
	heldAtReady, heldAtRepublish []string
	err                          error
}

// start builds arm's backend for class on network and runs it until both
// families are ready, under the share of flows flows names, the default where
// it is zero
func start(t *testing.T, network Network, arm Arm, class Class, flows uint32) *running {
	t.Helper()
	cfg := egress.Egress{Translate: class.classes(network.Family(false), network.Family(true)), FlowsPerSource: flows, Sweep: schema.Duration(suiteSweep)}
	for _, prefix := range defaults {
		cfg.Advertise = append(cfg.Advertise, schema.PrefixFrom(prefix))
	}
	// the server's flows toward the leaf are then translated into the mesh, as a
	// subnet router's LAN's are, which the idle timers read. A backend that
	// terminates opens no flow toward the leaf, so it refuses return.
	cfg.Return = !arm.Terminates
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the capability is refused: %v", err)
	}
	r := &running{cfg: cfg, host: network.Exit(), holds: arm.Holds, stopped: arm.Stopped, flows: arm.Flows, misses: arm.MissesFlows, done: make(chan struct{})}
	r.Exit = arm.New(t, r.host, cfg, egress.Hooks{Ready: r.ready, Republish: r.republish})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		r.err = r.Run(ctx)
	}()
	t.Cleanup(func() { r.end(t, stopBudget) })
	network.Carry(r.hand)
	r.awaitReady(t)
	return r
}

// end ends Run and waits budget for it to return, failing t where it has not,
// so a backend whose Run never returns fails its class and the suite goes on
// to the next with that Run left running
func (r *running) end(t interface{ Errorf(string, ...any) }, budget time.Duration) {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(budget):
		t.Errorf("Run had not returned %s after its context ended, and is left running", budget)
	}
}

func (r *running) awaitReady(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(readyBudget); ; time.Sleep(pollInterval) {
		announced := r.Announce()
		if r.carries4.Load() && r.carries6.Load() && announcesDefaults(announced) {
			return
		}
		if time.Now().After(deadline) {
			status := r.Status()
			t.Fatalf("within %s the exit was ready %v in IPv4 and %v in IPv6 and announced %v, want both ready and both defaults: %s", readyBudget, status.Ready4, status.Ready6, announced, status.Unready)
		}
	}
}

func announcesDefaults(announced []netip.Prefix) bool {
	return len(announced) == len(defaults) && !slices.ContainsFunc(defaults, func(prefix netip.Prefix) bool { return !slices.Contains(announced, prefix) })
}

// hand is the dataplane's hand-off for a prefix cap.egress advertises
func (r *running) hand(packets [][]byte) {
	r.mu.Lock()
	withheld := r.withheld
	r.mu.Unlock()
	frames := make([][]byte, 0, len(packets))
	var handed [][]byte
	for _, packet := range packets {
		if v6 := packet[0]>>4 == 6; v6 && !r.carries6.Load() || !v6 && !r.carries4.Load() {
			continue
		}
		if withheld != nil && withheld(packet) {
			continue
		}
		frame := make([]byte, netstack.TUNHeadroom+len(packet))
		copy(frame[netstack.TUNHeadroom:], packet)
		frames = append(frames, frame)
		handed = append(handed, slices.Clone(packet))
	}
	if len(frames) == 0 {
		return
	}
	r.mu.Lock()
	r.handed = append(r.handed, handed...)
	r.mu.Unlock()
	r.Egress(frames, nil)
}

// handedSince is every packet handed from the mark'th on
func (r *running) handedSince(mark int) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.handed[mark:])
}

func (r *running) handedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.handed)
}

// ready re-reads the announcement, as a node republishes on every move of
// Ready, before it moves the word
func (r *running) ready(v4, v6, serves bool) {
	announced := r.Announce()
	r.mu.Lock()
	was4, was6 := r.carries4.Load(), r.carries6.Load()
	r.ready4, r.ready6 = v4, v6
	r.carry(announced)
	r.told = append(r.told, readiness{v4, v6, serves})
	if w := r.withdrawing; w != nil && !v4 && !v6 && !w.toldNone {
		w.toldNone = true
		w.heldAtReady = r.held(w)
	}
	dropped := r.dropped
	r.mu.Unlock()
	if dropped != nil && (was4 && !v4 || was6 && !v6) {
		dropped(was4 && !v4, was6 && !v6)
	}
}

func (r *running) republish() {
	announced := r.Announce()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.carry(announced)
	r.announced = append(r.announced, announced)
	if w := r.withdrawing; w != nil && len(announced) == 0 && !w.republishedNone {
		w.republishedNone = true
		w.heldAtRepublish = r.held(w)
	}
}

// carry runs with r.mu held
func (r *running) carry(announced []netip.Prefix) {
	var v4, v6 bool
	for _, prefix := range announced {
		v4, v6 = v4 || prefix.Addr().Is4(), v6 || prefix.Addr().Is6()
	}
	r.carries4.Store(r.ready4 && v4)
	r.carries6.Store(r.ready6 && v6)
}

// held runs with r.mu held
func (r *running) held(w *withdrawal) []string {
	held, err := r.holds(r.host)
	w.err = errors.Join(w.err, err)
	return held
}

func (r *running) record() *withdrawal {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawing = &withdrawal{
		wasReady:     len(r.told) != 0 && r.told[len(r.told)-1] != (readiness{}),
		wasAnnounced: len(r.announced) != 0 && len(r.announced[len(r.announced)-1]) != 0,
	}
	return r.withdrawing
}

// withdrew holds a finished withdrawal to what every backend owes: readiness
// false in both families and the announcement empty while the backend still
// held what carries them, then left, what Holds names, and nothing announced
func (r *running) withdrew(t *testing.T, w *withdrawal, left []string) {
	t.Helper()
	held, err := r.holds(r.host)
	if err != nil {
		t.Fatalf("read what the backend holds: %v", err)
	}
	if !holding(held, left) {
		t.Errorf("once withdrawn the backend held %v, want %v", held, left)
	}
	if announced := r.Announce(); len(announced) != 0 {
		t.Errorf("once withdrawn Announce answered %v, want nothing", announced)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawing = nil
	if w.err != nil {
		t.Errorf("read what the backend held while it withdrew: %v", w.err)
	}
	switch {
	case len(r.told) == 0 || r.told[len(r.told)-1] != (readiness{}):
		t.Errorf("Ready was told %v, want the last call to say neither family is ready and the SIDs are not served", r.told)
	case w.wasReady && !w.toldNone:
		t.Error("the withdrawal told Ready nothing, though a family was ready")
	case w.wasReady && len(w.heldAtReady) == 0:
		t.Error("when the withdrawal told Ready that neither family was ready the backend held nothing, so it withdrew first")
	}
	switch {
	case len(r.announced) == 0 || len(r.announced[len(r.announced)-1]) != 0:
		t.Errorf("Republish read the announcements %v, want the last empty", r.announced)
	case w.wasAnnounced && !w.republishedNone:
		t.Error("the withdrawal called Republish for no empty announcement, though one was announced")
	case w.wasAnnounced && len(w.heldAtRepublish) == 0:
		t.Error("when the withdrawal published the empty announcement the backend held nothing, so it withdrew first")
	}
}

// stop ends Run, which owes the withdrawal withdrew holds it to
func (r *running) stop(t *testing.T) {
	w := r.record()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(stopBudget):
		t.Fatalf("Run had not returned %s after its context ended", stopBudget)
	}
	if r.err != nil {
		t.Errorf("Run returned %v", r.err)
	}
	r.withdrew(t, w, nil)
}

// holding is whether held, as Holds names it, is want in any order
func holding(held, want []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(held)), slices.Sorted(slices.Values(want)))
}

// off takes the backend off with SetEnabled and waits for the withdrawal
// withdrew holds it to, with what Holds read before left where Arm.Stopped is
// set, and for Status to read the backend off, its drop in place where
// Arm.Stopped is set
func (r *running) off(t *testing.T) {
	t.Helper()
	var left []string
	if r.stopped != nil {
		var err error
		if left, err = r.holds(r.host); err != nil {
			t.Fatalf("read what the backend holds: %v", err)
		}
	}
	w := r.record()
	r.SetEnabled(false)
	for deadline := time.Now().Add(stopBudget); ; time.Sleep(pollInterval) {
		r.mu.Lock()
		toldNone, republishedNone := w.toldNone, w.republishedNone
		r.mu.Unlock()
		held, err := r.holds(r.host)
		if toldNone && republishedNone && err == nil && holding(held, left) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within %s of SetEnabled(false) the backend held %v (%v), told Ready neither family %v and published nothing %v, want it to hold %v", stopBudget, held, err, toldNone, republishedNone, left)
		}
	}
	r.withdrew(t, w, left)
	r.awaitStatus(t, "disabled", func(s egress.Status) bool {
		return !s.Ready4 && !s.Ready6 && len(s.Announced) == 0 && (r.stopped == nil || r.stopped(s))
	})
}

// on puts the backend back with SetEnabled and waits for both families to be
// ready and announced in Status
func (r *running) on(t *testing.T) {
	t.Helper()
	r.SetEnabled(true)
	r.awaitReady(t)
	r.awaitStatus(t, "enabled again", func(s egress.Status) bool {
		return s.Ready4 && s.Ready6 && s.Unready == "" && announcesDefaults(s.Announced)
	})
}

// disable takes the backend off with SetEnabled and puts it back, as down and
// up do: it withdraws as the stop does, but for what it keeps where
// Arm.Stopped is set, Status reads neither family ready and nothing announced,
// what it keeps takes nothing into the mesh that no flow is tracked for and no
// ICMP message RFC 5508's REQ-10c has a NAT not carry, and once enabled again
// both families are ready and announced in Status and the leaf's datagrams
// reach the server
func (r *running) disable(t *testing.T, network Network, class Class) {
	icmpInto := r.icmpIntoWhileOff(t, network, class)
	r.off(t)
	r.untrackedIntoWhileOff(t, network, class)
	icmpInto(t)
	r.on(t)
	for _, v6 := range []bool{false, true} {
		family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
		family.udp(t, netip.AddrPortFrom(family.family.Server, enabledPort))
	}
}

// judgedBeforeStop has a batch the dataplane judged ready while both families
// were reach the backend once SetEnabled has taken it off, as a writer lane
// hands the tun a frame a session judged before the stop. The batch holds, in
// each family, a datagram of a flow of the leaf's the backend carried before
// the stop and the first of a flow it never saw, and under Inside the same of
// the spare address's beside them. A datagram of a class that translates
// reaches the server not at all, and the new flow's leaves no flow, since one
// egressed untranslated would carry the leaf's own address out and pin its
// flow untranslated past the next start. One of a class of none reaches it
// from its own address where Arm.Stopped is set, and not at all where the
// backend holds nothing while off. Where Arm.Stopped is set, a reply the server
// sends while the backend is off to each flow it carried before reaches the
// leaf, the exit's own datagram from its mesh address leaves under the class
// of that address, and a datagram the exit's host routes from the mesh device
// back into it reaches the leaf. Once enabled again each flow reaches the
// server from its class's address.
func (r *running) judgedBeforeStop(t *testing.T, network Network, class Class) {
	type judged struct {
		packet, data []byte
		from         netip.AddrPort
		to           netip.AddrPort
		server       *net.UDPConn
		// seen is the address the server reads the flow from, passed whether
		// what the backend holds while off passes it, and carried whether the
		// backend carried the flow before the stop, as the server read it from
		// mapped
		seen            netip.Addr
		passed, carried bool
		mapped          netip.AddrPort
	}
	r.awaitReady(t)
	var batch []judged
	var servers []*net.UDPConn
	for _, v6 := range []bool{false, true} {
		family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
		to := netip.AddrPortFrom(family.family.Server, enabledPort)
		server := family.listenUDP(t, to)
		servers = append(servers, server)
		sources := []netip.Addr{family.family.Leaf}
		if class == Inside {
			sources = append(sources, family.family.Spare)
		}
		for _, source := range sources {
			none := r.cfg.ClassOf(source).To.None
			seen := family.seen()
			if none {
				seen = source
			}
			for _, carried := range []bool{true, false} {
				from := netip.AddrPortFrom(source, leafUnmatchedPort)
				if carried {
					from = netip.AddrPortFrom(source, leafWindowPort)
				}
				data := fmt.Appendf(nil, "judged ready before the stop from %s", from)
				packet := datagram(from, to, leafTTL, data)
				j := judged{packet, data, from, to, server, seen, none && r.stopped != nil, carried, netip.AddrPort{}}
				if carried {
					opened := fmt.Appendf(nil, "carried before the stop from %s", from)
					if j.mapped = receiveFrom(t, udpReader(server), opened, func() { r.hand([][]byte{datagram(from, to, leafTTL, opened)}) }); j.mapped.Addr() != seen {
						t.Fatalf("before the stop the server read the flow from %s, want %s", j.mapped, seen)
					}
				}
				batch = append(batch, j)
			}
		}
	}
	frames := make([][]byte, 0, len(batch))
	for _, j := range batch {
		frame := make([]byte, netstack.TUNHeadroom+len(j.packet))
		copy(frame[netstack.TUNHeadroom:], j.packet)
		frames = append(frames, frame)
	}
	r.off(t)
	// the batch reaches the backend past the hand-off, whose judgment the stop moved
	r.Egress(frames, nil)
	arrived := make(map[string]netip.AddrPort, len(batch))
	for _, server := range servers {
		read, buf, by := udpReader(server), make([]byte, readSize), time.Now().Add(quietPeriod)
		for {
			n, from, err := read(buf, by)
			if err != nil {
				break
			}
			arrived[string(buf[:n])] = from
		}
	}
	for _, j := range batch {
		from, ok := arrived[string(j.data)]
		switch {
		case j.passed && !ok:
			t.Errorf("the server read nothing of the datagram %s under none sent before the stop, which what the backend holds while off passes", j.from)
		case j.passed && from.Addr() != j.seen:
			t.Errorf("the server read the datagram %s under none sent before the stop from %s, want %s", j.from, from, j.seen)
		case !j.passed && ok:
			t.Errorf("once taken off the backend let the datagram %s sent before the stop reach the server from %s, want it dropped", j.from, from)
		}
	}
	if r.flows != nil {
		flows, err := r.flows(r.host)
		if err != nil {
			t.Fatalf("read the backend's flows: %v", err)
		}
		for _, j := range batch {
			if !j.passed && !j.carried && slices.ContainsFunc(flows, func(f Flow) bool { return f.Protocol == syscall.IPPROTO_UDP && f.From == j.from && f.To == j.to }) {
				t.Errorf("the first datagram from %s to %s, sent before the stop and dropped, left a flow", j.from, j.to)
			}
		}
	}
	if r.stopped != nil {
		back := &rows{network: network}
		for _, j := range batch {
			if !j.carried {
				continue
			}
			reply := fmt.Appendf(nil, "a reply while off to %s", j.from)
			if !back.await(func() { _, _ = j.server.WriteToUDPAddrPort(reply, j.mapped) }, func(packet []byte) bool {
				p, ok := parse(packet)
				return ok && p.src == j.to.Addr() && p.dst == j.from.Addr() && bytes.HasSuffix(p.payload, reply)
			}) {
				t.Errorf("no reply the server sent while off to the flow of %s it read from %s came back toward the leaf within %s", j.from, j.mapped, stepBudget)
			}
		}
		for _, v6 := range []bool{false, true} {
			family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
			own, want := family.ownMesh(t), family.seen()
			if r.cfg.ClassOf(own).To.None {
				want = own
			}
			if from := family.sendUnanswered(t, r.host.Do, own, netip.AddrPortFrom(family.family.Server, ownWhileOffPort)); from.Addr() != want {
				t.Errorf("the exit's own datagram from %s sent while off reached the server from %s, want %s", own, from, want)
			}
		}
		// from outside the mesh, since the mesh's edge drops a packet the host
		// sends it from another member's address as forged
		for i, source := range []netip.Addr{netip.MustParseAddr("198.51.100.69"), netip.MustParseAddr("2001:db8:9::5")} {
			from, to := netip.AddrPortFrom(source, leafTransitPort), netip.AddrPortFrom(network.Family(i == 1).Spare, leafTransitPort)
			data := fmt.Appendf(nil, "back into the mesh while off from %s", from)
			frame := slices.Concat(make([]byte, netstack.TUNHeadroom), datagram(from, to, leafTTL, data))
			if !back.await(func() { r.Egress([][]byte{slices.Clone(frame)}, nil) }, func(packet []byte) bool {
				p, ok := parse(packet)
				return ok && p.src == from.Addr() && p.dst == to.Addr() && bytes.HasSuffix(p.payload, data)
			}) {
				t.Errorf("the datagram from %s to %s handed while off, which the host routes back into the mesh, did not come back within %s", from, to, stepBudget)
			}
		}
	}
	r.on(t)
	for _, j := range batch {
		if from := receiveFrom(t, udpReader(j.server), j.data, func() { r.hand([][]byte{j.packet}) }); from.Addr() != j.seen {
			t.Errorf("once enabled again the server read the flow of the datagram %s sent before the stop from %s, want %s", j.from, from, j.seen)
		}
	}
}

const (
	// crossingBurst is the most new flows of each family the frames across a
	// stop hand around one SetEnabled, each crossingPace after the last, which
	// spans the backend's turn that answers it
	crossingBurst = 32
	crossingPace  = 150 * time.Microsecond
	// crossingPort is the server's port the frames across a stop go to, and
	// leafCrossingPort the first of the ports they leave the leaf from, one a
	// flow
	crossingPort     = 10400
	leafCrossingPort = 46000
	// leafTransitPort is the port of the datagram the exit's host routes back
	// into the mesh while the backend is off, and ownWhileOffPort the server's
	// port of the exit's own datagram then
	leafTransitPort = 40802
	ownWhileOffPort = 10401
)

// crossings takes the backend off with SetEnabled and puts it back
// Arm.Crossings times, alone and again beside the chain Arm.Untranslating has
// another writer hold, and hands frames of new flows from the leaf's address in
// both families, one flow of each a crossingPace apart, from just before each
// SetEnabled until the backend reads off or back or crossingBurst flows have
// gone. Once the backend is back for the last time it hands one frame more of
// every flow. The server reads none of them from the leaf's own address: a
// frame the backend took while it translated leaves under its class's address,
// one it took while off leaves not at all, and no flow left untranslated
// across a stop leaves untranslated after the start.
func (r *running) crossings(t *testing.T, network Network, class Class, arm Arm) {
	if last := leafCrossingPort + 2*2*arm.Crossings*crossingBurst; last > leafEphemeralLow {
		t.Fatalf("the step's flows would take the leaf's ports up to %d, past %d where its kernel's own begin", last, leafEphemeralLow)
	}
	r.awaitReady(t)
	var leaves []netip.Addr
	var tos []netip.AddrPort
	var servers []*net.UDPConn
	for _, v6 := range []bool{false, true} {
		family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
		if r.cfg.ClassOf(family.family.Leaf).To.None {
			t.Fatalf("the leaf's address %s is under no class that translates under %s", family.family.Leaf, class)
		}
		to := netip.AddrPortFrom(family.family.Server, crossingPort)
		leaves, tos, servers = append(leaves, family.family.Leaf), append(tos, to), append(servers, family.listenUDP(t, to))
	}
	// arrived is each datagram the server read by where it came from, until
	// quiet is closed
	var mu sync.Mutex
	arrived := map[netip.Addr]int{}
	quiet := make(chan struct{})
	var reading sync.WaitGroup
	for _, server := range servers {
		reading.Go(func() {
			read, buf := udpReader(server), make([]byte, readSize)
			for {
				_, from, err := read(buf, time.Now().Add(pollInterval))
				select {
				case <-quiet:
					return
				default:
				}
				if err == nil {
					mu.Lock()
					arrived[from.Addr()]++
					mu.Unlock()
				}
			}
		})
	}
	flows := 0
	hand := func(flow int) {
		frames := make([][]byte, 0, len(leaves))
		for i, leaf := range leaves {
			from := netip.AddrPortFrom(leaf, uint16(leafCrossingPort+flow))
			frames = append(frames, slices.Concat(make([]byte, netstack.TUNHeadroom), datagram(from, tos[i], leafTTL, fmt.Appendf(nil, "across a stop from %s", from))))
		}
		r.Egress(frames, nil)
	}
	across := func(transition func(*testing.T)) {
		done, handed := make(chan struct{}), make(chan int, 1)
		go func() {
			n := 0
			for ; n < crossingBurst; n++ {
				select {
				case <-done:
					handed <- n
					return
				default:
				}
				hand(flows + n)
				time.Sleep(crossingPace)
			}
			handed <- n
		}()
		transition(t)
		close(done)
		flows += <-handed
	}
	cross := func() {
		for range arm.Crossings {
			across(r.off)
			across(r.on)
		}
	}
	cross()
	if arm.Untranslating != nil {
		undo, err := arm.Untranslating(r.host)
		if err != nil {
			t.Fatalf("have another writer hold a chain that translates nothing: %v", err)
		}
		cross()
		if err := undo(); err != nil {
			t.Errorf("take another writer's chain away: %v", err)
		}
	}
	for flow := range flows {
		hand(flow)
		if flow%crossingBurst == crossingBurst-1 {
			time.Sleep(crossingPace)
		}
	}
	time.Sleep(quietPeriod)
	close(quiet)
	reading.Wait()
	mu.Lock()
	defer mu.Unlock()
	for _, leaf := range leaves {
		if arrived[leaf] != 0 {
			t.Errorf("the server read %d datagrams of the %d flows handed across the stops from the leaf's own address %s", arrived[leaf], flows, leaf)
		}
	}
	if len(arrived) == 0 {
		t.Errorf("the server read none of the %d flows handed across the stops", flows)
	}
}

// awaitStatus waits for Status to read as ok, which the backend's own goroutine
// stores after the hooks it calls
func (r *running) awaitStatus(t *testing.T, what string, ok func(egress.Status) bool) {
	t.Helper()
	for deadline := time.Now().Add(stepBudget); !ok(r.Status()); time.Sleep(pollInterval) {
		if time.Now().After(deadline) {
			s := r.Status()
			t.Fatalf("%s, Status reads ready %v in IPv4 and %v in IPv6, unready %q and announced %v", what, s.Ready4, s.Ready6, s.Unready, s.Announced)
		}
	}
}

// overwritten has another writer take the backend's translation away in one
// transaction. The backend says each family is not ready once, the leaf's
// datagram of each sent before Ready returns reaches the server not at all,
// and once the backend has its translation back the same flow reaches the
// server from the class's address. A datagram egressed in that window would
// leave untranslated and pin its flow untranslated after the translation came
// back. A second not-ready for the one change would drop every frame of the
// family for a pass and withdraw its prefixes for nothing.
func (r *running) overwritten(t *testing.T, network Network, class Class, remove func(Host) error) {
	type flow struct {
		family   *rows
		datagram []byte
		data     []byte
		server   *net.UDPConn
	}
	var flows [2]flow
	for i, v6 := range []bool{false, true} {
		family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
		to := netip.AddrPortFrom(family.family.Server, windowPort)
		data := []byte("sent in the window over " + family.family.Name)
		flows[i] = flow{family, datagram(netip.AddrPortFrom(family.family.Leaf, leafWindowPort), to, leafTTL, data), data, family.listenUDP(t, to)}
	}
	var mu sync.Mutex
	var drops [2]int
	var leaked []string
	r.mu.Lock()
	r.dropped = func(v4, v6 bool) {
		// the backend's goroutine waits here, which holds the window open while each datagram is looked for
		var looking sync.WaitGroup
		for i, went := range []bool{v4, v6} {
			if !went {
				continue
			}
			mu.Lock()
			drops[i]++
			again := drops[i] > 1
			mu.Unlock()
			// a second drop opens no window, so no two readers take the server's socket
			if again {
				continue
			}
			r.hand([][]byte{flows[i].datagram})
			looking.Go(func() {
				if from, ok := readOnce(flows[i].server, flows[i].data, quietPeriod); ok {
					mu.Lock()
					leaked = append(leaked, from.String())
					mu.Unlock()
				}
			})
		}
		looking.Wait()
	}
	r.mu.Unlock()
	t.Cleanup(func() {
		r.mu.Lock()
		r.dropped = nil
		r.mu.Unlock()
	})
	counted := func() [2]int {
		mu.Lock()
		defer mu.Unlock()
		return drops
	}
	if err := remove(r.host); err != nil {
		t.Fatalf("take the backend's translation away as another writer: %v", err)
	}
	for deadline := time.Now().Add(stepBudget); ; time.Sleep(pollInterval) {
		if n := counted(); n[0] != 0 && n[1] != 0 {
			break
		}
		if time.Now().After(deadline) {
			n := counted()
			t.Fatalf("within %s of another writer taking its translation the backend told Ready of %d losses of %s and %d of %s, want one each", stepBudget, n[0], flows[0].family.family.Name, n[1], flows[1].family.family.Name)
		}
	}
	r.awaitReady(t)
	mu.Lock()
	if len(leaked) != 0 {
		t.Errorf("the server read the leaf's datagram from %v while Ready held its family not ready", leaked)
	}
	mu.Unlock()
	for _, f := range flows {
		from := receiveFrom(t, udpReader(f.server), f.data, func() { r.hand([][]byte{f.datagram}) })
		if from.Addr() != f.family.seen() {
			t.Errorf("once the backend had its translation back the server read the window's flow from %s, want %s", from, f.family.seen())
		}
	}
	// a second loss for the one change is waited for as an answer that must not come
	for deadline := time.Now().Add(quietPeriod); time.Now().Before(deadline); time.Sleep(pollInterval) {
		if n := counted(); n[0] > 1 || n[1] > 1 {
			break
		}
	}
	for i, n := range counted() {
		if n > 1 {
			t.Errorf("the backend told Ready of %d losses of %s for another writer's one change, want one", n, flows[i].family.family.Name)
		}
	}
}

// reloaded starts a second owner of the backend's table and, once both read
// back ready, has another writer reload the host's whole ruleset. The backend
// says each family is not ready once, the second owner says it is not ready
// once, and both read back ready again. Whichever owner makes the table again
// first takes nothing of the other's, so a second not-ready of either for the
// one reload would drop every frame of a family, or withdraw what the second
// owner holds, for a pass and for nothing.
func (r *running) reloaded(t *testing.T, network Network, beside func(*testing.T, Network) Owner, reload func(Host) error) {
	owner := beside(t, network)
	both := func() bool {
		return r.carries4.Load() && r.carries6.Load() && announcesDefaults(r.Announce()) && owner.Ready()
	}
	for deadline := time.Now().Add(readyBudget); !both(); time.Sleep(pollInterval) {
		if time.Now().After(deadline) {
			t.Fatalf("within %s the backend and the second owner did not both read back ready", readyBudget)
		}
	}
	var mu sync.Mutex
	var drops [2]int
	r.mu.Lock()
	r.dropped = func(v4, v6 bool) {
		mu.Lock()
		defer mu.Unlock()
		for i, went := range []bool{v4, v6} {
			if went {
				drops[i]++
			}
		}
	}
	r.mu.Unlock()
	t.Cleanup(func() {
		r.mu.Lock()
		r.dropped = nil
		r.mu.Unlock()
	})
	before := owner.Unready()
	counted := func() (backend [2]int, second int) {
		mu.Lock()
		defer mu.Unlock()
		return drops, owner.Unready() - before
	}
	if err := reload(r.host); err != nil {
		t.Fatalf("reload the host's ruleset as another writer: %v", err)
	}
	for deadline := time.Now().Add(stepBudget); ; time.Sleep(pollInterval) {
		if n, second := counted(); n[0] != 0 && n[1] != 0 && second != 0 {
			break
		}
		if time.Now().After(deadline) {
			n, second := counted()
			t.Fatalf("within %s of another writer's reload the backend told Ready of %d losses of %s and %d of %s, and the second owner reported itself not ready %d times, want one each", stepBudget, n[0], network.Family(false).Name, n[1], network.Family(true).Name, second)
		}
	}
	for deadline := time.Now().Add(readyBudget); !both(); time.Sleep(pollInterval) {
		if time.Now().After(deadline) {
			t.Fatalf("within %s of another writer's reload the backend and the second owner did not both read back ready", readyBudget)
		}
	}
	// a second not-ready for the one reload is waited for as an answer that must not come
	for deadline := time.Now().Add(quietPeriod); time.Now().Before(deadline); time.Sleep(pollInterval) {
		if n, second := counted(); n[0] > 1 || n[1] > 1 || second > 1 {
			break
		}
	}
	n, second := counted()
	for i, v6 := range []bool{false, true} {
		if n[i] > 1 {
			t.Errorf("the backend told Ready of %d losses of %s for another writer's one reload, want one", n[i], network.Family(v6).Name)
		}
	}
	if second > 1 {
		t.Errorf("the second owner reported itself not ready %d times for another writer's one reload, want once", second)
	}
}

// masqueraded has another writer masquerade every packet, where the host's own
// source translation runs and made after the backend's translation, then ahead
// of it. At the host's own place, a new flow of the leaf's reaches the server
// from the class's address, the leaf's own under none, since the first
// translation to bind a connection is the one it keeps. Ahead of it, the
// server reads the other writer's, the exit's uplink address. Where
// Arm.Stopped is set, once the backend is taken off beside either, the first
// datagram of a new flow of the leaf's, which the dataplane judged before the
// stop and hands meanwhile, reaches the server not at all under a class that
// translates, whatever the other writer's masquerade would make of it, and
// under none from where it did before.
func (r *running) masqueraded(t *testing.T, network Network, class Class, masquerade func(Host, bool) (func() error, error)) {
	// leafOffPort is the port the datagram handed while off leaves the leaf from
	const leafOffPort = 40804
	for _, step := range []struct {
		where string
		ahead bool
		port  uint16
	}{{"at the host's own place made after", false, behindPort}, {"ahead of", true, aheadPort}} {
		undo, err := masquerade(r.host, step.ahead)
		if err != nil {
			t.Fatalf("masquerade as another writer %s the backend's translation: %v", step.where, err)
		}
		var servers [2]*net.UDPConn
		var wants [2]netip.Addr
		for i, v6 := range []bool{false, true} {
			family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
			want := family.seen()
			if step.ahead {
				want = family.family.Uplink
			}
			to := netip.AddrPortFrom(family.family.Server, step.port)
			server, leaf := family.listenUDP(t, to), family.dialUDP(t, to)
			servers[i], wants[i] = server, want
			sent := []byte("a datagram " + step.where + " another writer's masquerade over " + family.family.Name)
			if from := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) }); from.Addr() != want {
				t.Errorf("with another writer's masquerade %s the backend's translation the server read the datagram from %s, want %s", step.where, from, want)
			}
		}
		if r.stopped != nil {
			r.off(t)
			for i, v6 := range []bool{false, true} {
				family := network.Family(v6)
				from, to := netip.AddrPortFrom(family.Leaf, leafOffPort), netip.AddrPortFrom(family.Server, step.port)
				data := fmt.Appendf(nil, "a datagram from %s while off with another writer's masquerade %s the backend's translation", from, step.where)
				frame := slices.Concat(make([]byte, netstack.TUNHeadroom), datagram(from, to, leafTTL, data))
				// past the hand-off, whose judgment the stop moved
				hand := func() { r.Egress([][]byte{slices.Clone(frame)}, nil) }
				if class == None {
					if got := receiveFrom(t, udpReader(servers[i]), data, hand); got.Addr() != wants[i] {
						t.Errorf("the datagram from %s under none handed while off reached the server from %s, want %s", from, got, wants[i])
					}
					continue
				}
				hand()
				if got, ok := readOnce(servers[i], data, quietPeriod); ok {
					t.Errorf("once taken off the backend let the datagram from %s with another writer's masquerade %s its translation reach the server from %s, want it dropped", from, step.where, got)
				}
			}
			r.on(t)
		}
		if err := undo(); err != nil {
			t.Fatalf("take another writer's masquerade away: %v", err)
		}
	}
}
