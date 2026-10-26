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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
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
)

func (c Class) String() string {
	switch c {
	case Address:
		return "address"
	case None:
		return "none"
	}
	return "auto"
}

// classes is the capability's translate under c: no class for Auto, an
// address from every source of each family for Address, and none from the
// leaf's overlay prefix of each family for None
func (c Class) classes(families ...Family) []egress.Class {
	var out []egress.Class
	for _, family := range families {
		switch c {
		case Address:
			out = append(out, egress.Class{From: schema.PrefixFrom(every(family.Overlay)), To: egress.Translation{Addr: family.Class}})
		case None:
			out = append(out, egress.Class{From: schema.PrefixFrom(family.Overlay), To: egress.Translation{None: true}})
		}
	}
	return out
}

// seen is the address the server reads family's packets from under c
func (c Class) seen(family Family) netip.Addr {
	switch c {
	case Address:
		return family.Class
	case None:
		return family.Leaf
	}
	return family.Uplink
}

// Family is a network's addresses and links in one address family
type Family struct {
	// Name names the family in a test's name
	Name string
	// Leaf is the leaf's address, inside the mesh's Overlay, and Exit every
	// address the exit holds. Spare is a second address of the leaf's inside
	// Overlay, which no socket of the leaf's takes as its source unless it binds
	// to it and no row but the limit's sends from, so a backend counts none of
	// its flows when that row begins.
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
	Write func(frames [][]byte)
	// Mesh is the exit's addresses on the mesh, and Members the prefixes its
	// mesh routes to other nodes, the leaf's
	Mesh    []netip.Addr
	Members func() []netip.Prefix
}

// Network is a leaf, an exit's host and a server beyond the exit's uplink,
// built anew for each class so that no class meets another's state. The
// server reads what the exit sends from any source, the leaf's own among
// them, so a packet the exit leaves untranslated reaches it.
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
)

func (l Limit) String() string {
	switch l {
	case PortDependentFiltering:
		return "port dependent filtering"
	case NoHairpinning:
		return "no hairpinning"
	}
	return fmt.Sprintf("limit %d", int(l))
}

// Declared is a limit's reason on its platform, and the row of the deviations
// page that records it, named as the page's first column names it
type Declared struct{ Reason, Row string }

// Arm is a backend as the suite runs it. The suite holds every arm to all
// six rows in both families, to carrying every protocol, to Egress from
// several sessions at once, to filtering and hairpinning as RFC 4787 asks or
// as its arm declares it does instead, to a withdrawal and a restore by
// SetEnabled, and to the share of flows its capability names, and an arm that
// reads its flows to the idle timers it keeps them to.
type Arm struct {
	// Classes are the source classes the backend carries, at least one
	Classes []Class
	// Limits names each behavior the backend lacks by its nature, with its
	// reason and deviations row
	Limits map[Limit]Declared
	// Terminates is set for a backend that ends the leaf's TCP at the exit and
	// opens its own toward the server, which forwards none of the leaf's
	// segments and so owes no too big for them
	Terminates bool
	// New builds the backend on host for cfg, reporting through hooks
	New func(t testing.TB, host Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit
	// Holds names what the backend holds on host, nothing once it has withdrawn
	Holds func(host Host) ([]string, error)
	// Remove takes what carries the backend's translation off host as another
	// writer would, nil for a backend nothing else on the host can change
	Remove func(host Host) error
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

func (a Arm) check() error {
	if len(a.Classes) == 0 {
		return errors.New("the arm names no class it carries, so no row would run")
	}
	for limit, declared := range a.Limits {
		if declared.Reason == "" || declared.Row == "" {
			return fmt.Errorf("the arm declares %s without its reason and its deviations row", limit)
		}
	}
	return nil
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
// under its first class at a share its capability names. Row 6 comes last in a
// family, since it leaves the spare address at its limit.
func Run(t *testing.T, build func(t testing.TB) Network, arm Arm) {
	if err := arm.check(); err != nil {
		t.Fatal(err)
	}
	for _, class := range arm.Classes {
		t.Run(class.String(), func(t *testing.T) {
			network := build(t)
			exit := start(t, network, arm, class, 0)
			for _, v6 := range []bool{false, true} {
				r := &rows{network: network, family: network.Family(v6), class: class, exit: exit, terminates: arm.Terminates, flows: arm.Flows, limits: arm.Limits}
				t.Run(r.family.Name, func(t *testing.T) {
					t.Run("what the server sees", r.serverSees)
					t.Run("errors toward the leaf", r.errorsTowardTheLeaf)
					t.Run("path mtu", r.pathMTU)
					t.Run("hop limits", r.hopLimits)
					t.Run("port reuse", r.portReuse)
					t.Run("egress from several sessions at once", r.sessions)
					t.Run("packets no flow is tracked for", r.untracked)
					t.Run("packets into the mesh no flow is tracked for", r.untrackedInto)
					if arm.Flows != nil {
						t.Run("idle timers", r.timers)
					}
					if class != None {
						t.Run("filtering", r.filtering)
						t.Run("hairpinning", r.hairpinning)
					}
					t.Run("the limit on a source's flows", r.sourceLimit)
				})
			}
			t.Run("disabled and enabled", func(t *testing.T) { exit.disable(t, network, class) })
			if arm.Remove != nil {
				t.Run("another writer", func(t *testing.T) { exit.overwritten(t, network, class, arm.Remove) })
			}
			if arm.Masquerade != nil {
				t.Run("another writer's translation", func(t *testing.T) { exit.masqueraded(t, network, class, arm.Masquerade) })
			}
			t.Run("stop", exit.stop)
		})
	}
	t.Run("a share the capability names", func(t *testing.T) {
		class := arm.Classes[0]
		network := build(t)
		exit := start(t, network, arm, class, namedLimit)
		for _, v6 := range []bool{false, true} {
			r := &rows{network: network, family: network.Family(v6), class: class, exit: exit, terminates: arm.Terminates, flows: arm.Flows, limits: arm.Limits}
			t.Run(r.family.Name, r.sourceLimit)
		}
		t.Run("stop", exit.stop)
	})
}

// running is a backend under test, built for cfg, with what its hooks were
// told
type running struct {
	egress.Exit
	cfg    egress.Egress
	host   Host
	holds  func(Host) ([]string, error)
	cancel context.CancelFunc
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
	// subnet router's LAN's are, which the idle timers read
	cfg.Return = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the capability is refused: %v", err)
	}
	r := &running{cfg: cfg, host: network.Exit(), holds: arm.Holds, done: make(chan struct{})}
	r.Exit = arm.New(t, r.host, cfg, egress.Hooks{Ready: r.ready, Republish: r.republish})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		r.err = r.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	network.Carry(r.hand)
	r.awaitReady(t)
	return r
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
	r.Egress(frames)
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
// held what carries them, then nothing held and nothing announced
func (r *running) withdrew(t *testing.T, w *withdrawal) {
	t.Helper()
	held, err := r.holds(r.host)
	if err != nil {
		t.Fatalf("read what the backend holds: %v", err)
	}
	if len(held) != 0 {
		t.Errorf("once withdrawn the backend held %v, want nothing", held)
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
	r.withdrew(t, w)
}

// disable takes the backend off with SetEnabled and puts it back, as down and
// up do: it withdraws as the stop does, Status reads neither family ready and
// nothing announced, and once enabled again both families are ready and
// announced in Status and the leaf's datagrams reach the server
func (r *running) disable(t *testing.T, network Network, class Class) {
	w := r.record()
	r.SetEnabled(false)
	for deadline := time.Now().Add(stopBudget); ; time.Sleep(pollInterval) {
		r.mu.Lock()
		toldNone, republishedNone := w.toldNone, w.republishedNone
		r.mu.Unlock()
		held, err := r.holds(r.host)
		if toldNone && republishedNone && err == nil && len(held) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within %s of SetEnabled(false) the backend held %v (%v), told Ready neither family %v and published nothing %v", stopBudget, held, err, toldNone, republishedNone)
		}
	}
	r.withdrew(t, w)
	r.awaitStatus(t, "disabled", func(s egress.Status) bool { return !s.Ready4 && !s.Ready6 && len(s.Announced) == 0 })
	r.SetEnabled(true)
	r.awaitReady(t)
	r.awaitStatus(t, "enabled again", func(s egress.Status) bool {
		return s.Ready4 && s.Ready6 && s.Unready == "" && announcesDefaults(s.Announced)
	})
	for _, v6 := range []bool{false, true} {
		family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
		family.udp(t, netip.AddrPortFrom(family.family.Server, enabledPort))
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

// overwritten has another writer take the backend's translation away. The
// backend says the families it lost are not ready, the leaf's datagram of each
// sent before Ready returns reaches the server not at all, and once the
// backend has its translation back the same flow reaches the server from the
// class's address. A datagram egressed in that window would leave untranslated
// and pin its flow untranslated after the translation came back.
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
	var windows int
	var leaked []string
	r.mu.Lock()
	r.dropped = func(v4, v6 bool) {
		// the backend's goroutine waits here, which holds the window open while each datagram is looked for
		var looking sync.WaitGroup
		for i, went := range []bool{v4, v6} {
			if !went {
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
		mu.Lock()
		windows++
		mu.Unlock()
	}
	r.mu.Unlock()
	t.Cleanup(func() {
		r.mu.Lock()
		r.dropped = nil
		r.mu.Unlock()
	})
	if err := remove(r.host); err != nil {
		t.Fatalf("take the backend's translation away as another writer: %v", err)
	}
	for deadline := time.Now().Add(stepBudget); ; time.Sleep(pollInterval) {
		mu.Lock()
		opened := windows
		mu.Unlock()
		if opened != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within %s of another writer taking its translation the backend told Ready of no family it lost", stepBudget)
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
}

// masqueraded has another writer masquerade every packet, where the host's own
// source translation runs and made after the backend's translation, then ahead
// of it. At the host's own place, a new flow of the leaf's reaches the server
// from the class's address, the leaf's own under none, since the first
// translation to bind a connection is the one it keeps. Ahead of it, the
// server reads the other writer's, the exit's uplink address.
func (r *running) masqueraded(t *testing.T, network Network, class Class, masquerade func(Host, bool) (func() error, error)) {
	for _, step := range []struct {
		where string
		ahead bool
		port  uint16
	}{{"at the host's own place made after", false, behindPort}, {"ahead of", true, aheadPort}} {
		undo, err := masquerade(r.host, step.ahead)
		if err != nil {
			t.Fatalf("masquerade as another writer %s the backend's translation: %v", step.where, err)
		}
		for _, v6 := range []bool{false, true} {
			family := &rows{network: network, family: network.Family(v6), class: class, exit: r}
			want := family.seen()
			if step.ahead {
				want = family.family.Uplink
			}
			to := netip.AddrPortFrom(family.family.Server, step.port)
			server, leaf := family.listenUDP(t, to), family.dialUDP(t, to)
			sent := []byte("a datagram " + step.where + " another writer's masquerade over " + family.family.Name)
			if from := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) }); from.Addr() != want {
				t.Errorf("with another writer's masquerade %s the backend's translation the server read the datagram from %s, want %s", step.where, from, want)
			}
		}
		if err := undo(); err != nil {
			t.Fatalf("take another writer's masquerade away: %v", err)
		}
	}
}
