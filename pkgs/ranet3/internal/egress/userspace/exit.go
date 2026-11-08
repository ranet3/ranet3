// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package userspace is the exit that carries other nodes' traffic out of the
// mesh with the host's ordinary sockets rather than the kernel's translation:
// it ends each leaf's TCP connection in gVisor's stack and dials the server
// itself, relays UDP and echo through sockets of its own, and sends what it
// answers back into the mesh through lanes of the outbound path. Each socket
// it opens passes the platform's Prepare, so none leaves inside the mesh, and
// it holds what it holds within limits its caller sizes from the process's
// memory.
package userspace

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/schema"
)

// Runtime carries the parts of the node and of its platform the exit takes
type Runtime struct {
	// Mesh is the mesh the exit's packets toward the leaves enter
	Mesh Lanes
	// Platform keeps the exit's sockets out of the mesh
	Platform Platform
	// Limits bounds what the exit holds
	Limits Limits
	// MeshAddresses is this node's own mesh addresses, and Overlay the
	// overlay's prefixes, inside which an advertised prefix counts as no
	// default
	MeshAddresses []netip.Addr
	Overlay       []schema.Prefix
	// Steered is whether a segment of this node delivers to egress
	Steered bool
	egress.Hooks
}

// Platform is how the exit's sockets stay out of the mesh on this platform
type Platform struct {
	// Prepare readies each socket the exit opens before it binds or
	// connects. Its error refuses the flow.
	Prepare underlay.Prepare
	// Route is the link a prepared socket reaches address by, with the link's
	// MTU, false where only the mesh would carry it. Readiness reads it.
	Route func(address netip.Addr) (link Link, ok bool, err error)
	// Held reports an address this host holds on any of its links
	Held func(address netip.Addr) bool
	// Raw is the raw ICMP socket the leaves' own errors are sent to a server
	// through, nil where the process may open none
	Raw Raw
}

// Link is a link of the host's, by name, and the largest packet it carries
type Link struct {
	Name string
	MTU  int
}

// Raw sends the leaf's own ICMP errors toward a server, in both families
type Raw interface {
	// Send sends an ICMP error from a mapping's external address
	Send(packet []byte) error
	Close() error
}

// Exit is the userspace exit
type Exit struct {
	cfg egress.Egress
	rt  Runtime

	link     *link
	stack    *stack.Stack
	seed     maphash.Seed
	workers  []*worker
	pump     *pump
	counts   counts
	tcp      *tcpRelay
	udp      *udpRelay
	flows    *flows
	timeWait *timeWait
	// answers is the pump's lane, which answers a new flow past a limit, set
	// at Run's start before any packet is taken
	answers Lane
	// ttl and hopLimit hold the TTL and the hop limit of the IPv4 and IPv6
	// packets the exit builds, relayedTTL until SetHopLimits gives the host's
	ttl, hopLimit atomic.Uint32

	// taking is whether Egress queues what it takes, from Run's start while
	// the exit is enabled, and laneHeld the bytes queued to the workers
	taking   atomic.Bool
	laneHeld atomic.Int64
	// stop is closed at Run's end, which stops the workers and the pump, and
	// running counts them
	stop    chan struct{}
	running sync.WaitGroup
	// closeOnce closes the stack, the link and Raw once, at Run's end or in
	// Close
	closeOnce sync.Once

	// enabled is whether the exit carries at all, and wake carries a change of
	// it to the run goroutine
	enabled atomic.Bool
	wake    chan struct{}

	// stats is the last pass as a reader takes it, and announced the prefixes
	// Announce answers, each stored whole
	stats     atomic.Pointer[passStats]
	announced atomic.Pointer[[]netip.Prefix]

	// trigger names what woke the run goroutine, withdrawn is its record of
	// having acted on a stop, and the rest what Ready was last given, each
	// family's route and why a family is not ready, all the run goroutine's
	trigger                string
	withdrawn              bool
	ready4, ready6, serves bool
	routed4, routed6       bool
	unready                string
}

var _ egress.Exit = (*Exit)(nil)

// passStats is one readiness pass as Status reads it
type passStats struct {
	At             time.Time
	Ready4, Ready6 bool
	Unready        string
	Announced      []netip.Prefix
}

// counts holds the exit's counters by reason: the packets the lanes dropped
// past their bound, those the pump could lay into no batch, the endpoints in
// TIME_WAIT a new connection reused and those closed past Limits.TimeWait,
// the packets a lane's judgment answered and the flows refused, and the
// packets a judgment or a relay dropped
type counts struct {
	laneDropped, unlaid atomic.Uint64
	reused, closed      atomic.Uint64

	mu               sync.Mutex
	refused, dropped map[string]uint64
}

func (c *counts) refuse(reason string) { c.add(&c.refused, reason) }
func (c *counts) drop(reason string)   { c.add(&c.dropped, reason) }

func (c *counts) add(into *map[string]uint64, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if *into == nil {
		*into = map[string]uint64{}
	}
	(*into)[reason]++
}

// New builds the userspace exit for cfg. It refuses what this exit cannot
// carry: a class of none, return, and an advertised prefix that does not
// count as a default.
func New(cfg egress.Egress, rt Runtime) (*Exit, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Serves(rt.Steered); err != nil {
		return nil, err
	}
	switch {
	case rt.Mesh == nil:
		return nil, errors.New("egress: the userspace exit was given no mesh to send its packets into")
	case rt.Platform.Prepare == nil:
		return nil, errors.New("egress: the userspace exit was given no Prepare, so its sockets could leave inside the mesh")
	case rt.Platform.Route == nil || rt.Platform.Held == nil:
		return nil, errors.New("egress: the userspace exit was given no route or held address lookup")
	}
	if err := rt.Limits.check(); err != nil {
		return nil, err
	}
	for _, class := range cfg.Translate {
		if class.To.None {
			return nil, fmt.Errorf("egress: cap.egress translates %s with none, and the exit this build carries opens its own sockets, which send from this host's addresses and never from a leaf's", class.From)
		}
	}
	if cfg.Return {
		return nil, errors.New("egress: cap.egress return is set, and the exit this build carries ends each connection a leaf opens and opens its own toward the server, so no connection comes in from an advertised prefix for it to translate")
	}
	for _, prefix := range cfg.Advertise {
		if !schema.CapturesTheMachine(prefix.Prefix, rt.Overlay) {
			return nil, fmt.Errorf("egress: cap.egress advertises %s, a subnet, and this build's exit carries only defaults, the routes that count as one (outside cap.border.overlay and shorter than /%d or /%d), and egress segments: advertise those alone here, and route the subnet from a node whose exit forwards it",
				prefix, schema.MinSubnetBits4, schema.MinSubnetBits6)
		}
	}
	x := &Exit{cfg: cfg, rt: rt, link: newLink(rt.Limits.Link), seed: maphash.MakeSeed(), stop: make(chan struct{}), wake: make(chan struct{}, 1)}
	x.pump = &pump{link: x.link, unlaid: func() { x.counts.unlaid.Add(1) }}
	s, err := newStack(x.link, rt.Limits.Window, stackHandlers{udp: x.takeUDP, icmp: x.takeICMP})
	if err != nil {
		return nil, err
	}
	x.stack = s
	x.flows = newFlows(cfg.SourceLimit(), rt.Limits.Flows)
	x.tcp = newTCPRelay(x)
	x.udp = newUDPRelay(x)
	x.timeWait = newTimeWait(rt.Limits.TimeWait)
	for range min(max(1, runtime.GOMAXPROCS(0)), maxWorkers) {
		x.workers = append(x.workers, &worker{queue: make(chan *[]byte, workerQueuePackets)})
	}
	x.enabled.Store(true)
	x.SetHopLimits(relayedTTL, relayedTTL)
	return x, nil
}

// takeICMP drops each ICMP message the stack hands its ICMP transport,
// counted as a protocol the exit does not carry
func (x *Exit) takeICMP(stack.TransportEndpointID, *stack.PacketBuffer) {
	x.counts.refuse(reasonProtocol)
}

// sourceFor is the address a flow from leaf leaves under: the address its
// class names, and the zero Addr under auto, where the host's route to the
// server picks the address of the link it leaves by
func (x *Exit) sourceFor(leaf netip.Addr) netip.Addr {
	return x.cfg.ClassOf(leaf).To.Addr
}

// SetEnabled withdraws everything while Run runs, in the order Run's end
// takes, and restores it. The work runs on the run goroutine, so a caller
// returns before it has caught up, which Status then reports.
func (x *Exit) SetEnabled(on bool) {
	x.enabled.Store(on)
	select {
	case x.wake <- struct{}{}:
	default:
	}
}

// Announce is the advertised prefixes of the families ready at the last pass,
// and nothing before the first
func (x *Exit) Announce() []netip.Prefix {
	if prefixes := x.announced.Load(); prefixes != nil {
		return slices.Clone(*prefixes)
	}
	return nil
}

// Status is the last pass and the capability the exit carries
func (x *Exit) Status() egress.Status {
	pass := x.lastPass()
	advertise := make([]netip.Prefix, 0, len(x.cfg.Advertise))
	for _, entry := range x.cfg.Advertise {
		advertise = append(advertise, entry.Prefix)
	}
	return egress.Status{
		Backend: "userspace",
		Ready4:  pass.Ready4, Ready6: pass.Ready6, Unready: pass.Unready,
		Advertise: advertise, Announced: pass.Announced,
		Translate: x.cfg.Translate, FlowsPerSource: x.cfg.SourceLimit(),
		PassAt: pass.At,
	}
}

func (x *Exit) lastPass() passStats {
	if s := x.stats.Load(); s != nil {
		return *s
	}
	return passStats{}
}

// Run starts the lanes, judges each family's readiness at the start, at each
// sweep and on each wake, and once ctx ends withdraws the families, the
// announcement and the flows and closes the stack. It is called once.
func (x *Exit) Run(ctx context.Context) error {
	slog.Info("egress userspace exit started", "steered", x.rt.Steered, "advertise", len(x.cfg.Advertise),
		"lanes", len(x.workers), "window", x.rt.Limits.Window, "flows", x.rt.Limits.Flows)
	for _, w := range x.workers {
		x.running.Add(1)
		go func(w *worker, lane Lane) {
			defer x.running.Done()
			x.work(w, lane)
		}(w, x.rt.Mesh.OpenLane())
	}
	x.answers = x.rt.Mesh.OpenLane()
	x.running.Add(2)
	go func() {
		defer x.running.Done()
		x.pump.run(x.answers, x.stop)
	}()
	go func() {
		defer x.running.Done()
		x.sweep()
	}()
	ticker := time.NewTicker(x.cfg.SweepInterval())
	defer ticker.Stop()

	x.trigger = "start"
	for ctx.Err() == nil {
		if !x.enabled.Load() {
			if !x.withdrawn {
				x.withdraw("the exit is stopped")
				x.withdrawn = true
			}
		} else {
			if x.withdrawn {
				x.withdrawn = false
				x.tcp.resume()
				x.udp.resume()
				slog.Info("egress userspace exit started again")
			}
			x.taking.Store(true)
			x.pass()
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			x.trigger = "sweep"
		case <-x.wake:
			x.trigger = "disable"
			if x.enabled.Load() {
				x.trigger = "enable"
			}
		}
	}
	x.withdraw("the exit is stopping")
	close(x.stop)
	x.running.Wait()
	return x.Close()
}

// withdraw takes nothing more from the sessions, reports both families not
// ready, so the mesh hands the exit nothing more, publishes an empty
// announcement, and then ends each dial, resets each connection and ends each
// mapping
func (x *Exit) withdraw(why string) {
	x.taking.Store(false)
	x.setReady(false, false, why, why)
	x.publish(nil)
	x.stats.Store(&passStats{At: time.Now(), Unready: x.unready})
	x.tcp.withdraw()
	x.udp.withdraw()
}

// sweep ends the mappings past their time until the exit stops
func (x *Exit) sweep() {
	ticker := time.NewTicker(mappingSweep)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			x.udp.expire(now)
		case <-x.stop:
			return
		}
	}
}

// Close closes the link, the stack, once each request the forwarder handed
// over has ended and each mapping's readers have, and Raw, once. Run's end
// calls it last, and it closes an exit whose Run never ran.
func (x *Exit) Close() error {
	var err error
	x.closeOnce.Do(func() {
		x.link.Close()
		x.stack.Close()
		x.tcp.withdraw()
		x.udp.withdraw()
		x.tcp.running.Wait()
		x.udp.readers.Wait()
		x.stack.Wait()
		if x.rt.Platform.Raw != nil {
			err = x.rt.Platform.Raw.Close()
		}
	})
	return err
}

// pass judges each family the capability translates, reports it, and
// announces the advertised prefixes of the families ready
func (x *Exit) pass() {
	ready := map[uint8]bool{}
	why := map[uint8]string{}
	routed := map[uint8]bool{}
	for _, family := range x.cfg.Translated(x.rt.Steered) {
		ready[family], routed[family], why[family] = x.readiness(family)
	}
	announced := make([]netip.Prefix, 0, len(x.cfg.Advertise))
	for _, entry := range x.cfg.Advertise {
		if ready[egress.AddressFamily(entry.Addr())] {
			announced = append(announced, entry.Prefix)
		}
	}
	x.routed4, x.routed6 = routed[egress.FamilyIPv4], routed[egress.FamilyIPv6]
	v4, v6 := ready[egress.FamilyIPv4], ready[egress.FamilyIPv6]
	x.setReady(v4, v6, why[egress.FamilyIPv4], why[egress.FamilyIPv6])
	moved := x.publish(announced)
	x.stats.Store(&passStats{At: time.Now(), Ready4: v4, Ready6: v6, Unready: x.unready, Announced: announced})
	if moved {
		x.rt.Events.Emit("egress.pass", "", slog.String("trigger", x.trigger), slog.Int("announced", len(announced)))
	}
}

// readiness is whether family is ready, whether a link outside the mesh
// reaches any of its prefixes, and why it is not ready: the host must route
// each prefix the family advertises, or its default where it advertises none,
// over a link outside the mesh, and hold each address its classes name
func (x *Exit) readiness(family uint8) (ready, routed bool, why string) {
	for _, prefix := range readPrefixes(x.cfg, family) {
		address, ok := readAddress(prefix)
		if !ok {
			return false, routed, "cap.egress advertises " + prefix.String() + ", which holds no unicast address to look its route up for"
		}
		_, found, err := x.rt.Platform.Route(address)
		switch {
		case err != nil:
			return false, routed, "the route lookup of " + address.String() + " for " + prefix.String() + " failed: " + err.Error()
		case !found:
			return false, routed, "no link outside the mesh reaches " + address.String() + " for " + prefix.String()
		}
		routed = true
	}
	for _, class := range x.cfg.Classes(family) {
		if class.To.Addr.IsValid() && !x.rt.Platform.Held(class.To.Addr) {
			return false, routed, "this host does not hold " + class.To.Addr.String() + ", an address cap.egress translate names"
		}
	}
	return true, routed, ""
}

// readPrefixes is the prefixes a family's lookups read, those it advertises,
// or its default where it advertises none, which only a family translated
// beside an egress segment does
func readPrefixes(cfg egress.Egress, family uint8) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range cfg.Advertise {
		if egress.AddressFamily(entry.Addr()) == family {
			prefixes = append(prefixes, entry.Prefix)
		}
	}
	if len(prefixes) == 0 {
		unspecified := netip.IPv6Unspecified()
		if family == egress.FamilyIPv4 {
			unspecified = netip.IPv4Unspecified()
		}
		prefixes = []netip.Prefix{netip.PrefixFrom(unspecified, 0)}
	}
	return prefixes
}

// readAddress is the address a readiness lookup reads for prefix: its middle
// address, then its base plus one, then its last less one, the first a server
// may hold. The middle alone falls short, since 192.0.0.0/2's is the group
// 224.0.0.0.
func readAddress(prefix netip.Prefix) (netip.Addr, bool) {
	prefix = prefix.Masked()
	base := prefix.Addr()
	candidates := []netip.Addr{base}
	if !prefix.IsSingleIP() {
		middle, last := base.AsSlice(), base.AsSlice()
		middle[prefix.Bits()/8] |= 0x80 >> (prefix.Bits() % 8)
		for bit := prefix.Bits(); bit < base.BitLen(); bit++ {
			last[bit/8] |= 0x80 >> (bit % 8)
		}
		mid, _ := netip.AddrFromSlice(middle)
		end, _ := netip.AddrFromSlice(last)
		candidates = []netip.Addr{mid, base.Next(), end.Prev()}
	}
	for _, address := range candidates {
		if !packet.InvalidSource(address) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

// publish stores prefixes for Announce and calls Republish where they moved,
// and reports whether they did
func (x *Exit) publish(prefixes []netip.Prefix) bool {
	previous := x.announced.Load()
	if previous != nil && slices.Equal(*previous, prefixes) {
		return false
	}
	stored := slices.Clone(prefixes)
	x.announced.Store(&stored)
	if previous != nil {
		slog.Warn("egress advertisement changed", "prefixes", len(prefixes), "was", len(*previous),
			"detail", "a family is advertised only while it is ready, as ranet3 status says")
	}
	if x.rt.Republish != nil {
		x.rt.Republish()
	}
	return true
}

// setReady records each family's readiness and why a family is not ready.
// Ready is told when either family or whether the egress SIDs are served
// moves, and egress.ready is recorded then. The SIDs are served while a
// family is ready and every family a link outside the mesh routes is.
func (x *Exit) setReady(v4, v6 bool, why4, why6 string) {
	x.unready = unreadyText(v4, v6, why4, why6)
	serves := (v4 || v6) && (v4 || !x.routed4) && (v6 || !x.routed6)
	if v4 == x.ready4 && v6 == x.ready6 && serves == x.serves {
		return
	}
	for _, family := range []struct {
		family     uint8
		was, ready bool
		why        string
	}{{egress.FamilyIPv4, x.ready4, v4, why4}, {egress.FamilyIPv6, x.ready6, v6, why6}} {
		switch {
		case family.was == family.ready:
		case family.ready:
			slog.Info("egress ready", "family", egress.FamilyName(family.family))
		default:
			slog.Warn("egress not ready", "family", egress.FamilyName(family.family), "detail", family.why)
		}
	}
	x.ready4, x.ready6, x.serves = v4, v6, serves
	if x.rt.Ready != nil {
		x.rt.Ready(v4, v6, serves)
	}
	x.rt.Events.Emit("egress.ready", "", slog.Bool("ipv4", v4), slog.Bool("ipv6", v6), slog.Bool("sid", serves),
		slog.String("reason", x.unready))
}

// unreadyText is why the families not ready are not, a family the exit does
// not translate giving no reason, and each reason named by its family where
// both families are not ready
func unreadyText(v4, v6 bool, why4, why6 string) string {
	switch {
	case v4 && v6:
		return ""
	case v6:
		return why4
	case v4:
		return why6
	case why4 == why6:
		return why4
	case why6 == "":
		return "ipv4 " + why4
	case why4 == "":
		return "ipv6 " + why6
	}
	return "ipv4 " + why4 + ", ipv6 " + why6
}
