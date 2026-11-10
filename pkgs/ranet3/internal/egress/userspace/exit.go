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
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/egress"
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
	// Held reports an address this host holds that a socket scoped to link
	// sends from: on link itself where the platform sends from no other
	// link's, and on any of its links where it does or link is empty
	Held func(address netip.Addr, link string) bool
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

	link    *link
	stack   *stack.Stack
	seed    maphash.Seed
	workers []*worker
	pump    *pump
	counts  counts
	tcp     *tcpRelay
	udp     *udpRelay
	echo    *echoRelay
	// icmp is the ICMP sockets the platform shares among the echo mappings
	// and reads the errors about the exit's sockets through, none on Linux
	icmp  *icmpSockets
	flows *flows
	// ident numbers the packets the exit builds toward a leaf, an IPv4
	// identification or an IPv6 fragment's
	ident    atomic.Uint32
	timeWait *timeWait
	// refusals spaces the egress.refused records on reportClock, the
	// nanoseconds since New on the monotonic clock
	refusals    spaced
	reportClock func() int64
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

	*egress.Shell
	// stats is the last pass as a reader takes it, stored whole
	stats atomic.Pointer[passStats]

	// trigger names what woke the run goroutine, and withdrawn is its record
	// of having acted on a stop, both the run goroutine's
	trigger   string
	withdrawn bool
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
	// share counts the flows refused past their source's share, by family,
	// and untracked a leaf's packets dropped for want of a flow to take them
	share, untracked [2]atomic.Uint64

	mu               sync.Mutex
	refused, dropped map[string]uint64
}

func (c *counts) refuse(reason string) { c.add(&c.refused, reason) }
func (c *counts) drop(reason string)   { c.add(&c.dropped, reason) }

// dropUntracked counts a leaf's packet of the family ipv6 names dropped for
// reason, which is that no flow takes it
func (c *counts) dropUntracked(ipv6 bool, reason string) {
	c.drop(reason)
	c.untracked[family(ipv6)].Add(1)
}

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
	x := &Exit{cfg: cfg, rt: rt, link: newLink(rt.Limits.Link), seed: maphash.MakeSeed(), stop: make(chan struct{})}
	x.Shell = egress.NewShell(&x.rt.Hooks)
	started := time.Now()
	x.reportClock = func() int64 { return int64(time.Since(started)) }
	x.pump = &pump{link: x.link, unlaid: func() { x.counts.unlaid.Add(1) }}
	s, err := newStack(x.link, rt.Limits.Window, stackHandlers{udp: x.takeUDP, icmp: x.takeICMP})
	if err != nil {
		return nil, err
	}
	x.stack = s
	x.flows = newFlows(cfg.SourceLimit(), rt.Limits.Flows)
	x.tcp = newTCPRelay(x)
	x.udp = newUDPRelay(x)
	x.echo = newEchoRelay(x)
	x.icmp = openICMP(x)
	x.timeWait = newTimeWait(rt.Limits.TimeWait)
	for range min(max(1, runtime.GOMAXPROCS(0)), maxWorkers) {
		x.workers = append(x.workers, &worker{queue: make(chan *[]byte, workerQueuePackets)})
	}
	x.SetHopLimits(relayedTTL, relayedTTL)
	return x, nil
}

// takeICMP hands the echo relay each ICMP or ICMPv6 message the stack hands
// its ICMP transport as one packet with no fragment or extension header, an
// echo request it reassembled or parsed among them, and the relay drops and
// counts the rest
func (x *Exit) takeICMP(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	protocol := byte(1)
	if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		protocol = 58
	}
	raw, ok := reassembled(pkt, protocol)
	if !ok {
		x.counts.drop(reasonMalformed)
		return
	}
	x.echo.take(raw)
}

// sourceFor is the address a flow from leaf leaves under: the address its
// class names, and the zero Addr under auto, where the host's route to the
// server picks the address of the link it leaves by
func (x *Exit) sourceFor(leaf netip.Addr) netip.Addr {
	return x.cfg.ClassOf(leaf).To.Addr
}

// Status is the last pass, the capability the exit carries, the flows
// refused past a source's share in each family, and the exit's detail
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
		Refused4: x.counts.share[0].Load(), Refused6: x.counts.share[1].Load(),
		Dropped4: x.counts.untracked[0].Load(), Dropped6: x.counts.untracked[1].Load(),
		PassAt: pass.At,
		Flows:  x.flowsStatus(),
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
	x.link.mtu = x.answers.MTU
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
		if !x.Enabled.Load() {
			if !x.withdrawn {
				x.withdraw("the exit is stopped")
				x.withdrawn = true
			}
		} else {
			if x.withdrawn {
				x.withdrawn = false
				x.tcp.resume()
				x.udp.resume()
				x.echo.resume()
				slog.Info("egress userspace exit started again")
			}
			x.taking.Store(true)
			x.pass()
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			x.trigger = "sweep"
		case <-x.Wake():
			x.trigger = "disable"
			if x.Enabled.Load() {
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
	x.SetUnready(why)
	x.Publish(nil)
	x.stats.Store(&passStats{At: time.Now(), Unready: x.Unready()})
	x.tcp.withdraw()
	x.udp.withdraw()
	x.echo.withdraw()
}

// sweep ends the mappings past their time until the exit stops
func (x *Exit) sweep() {
	ticker := time.NewTicker(mappingSweep)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			x.expire(now)
		case <-x.stop:
			return
		}
	}
}

// expire ends each UDP and echo mapping past its time at now
func (x *Exit) expire(now time.Time) {
	x.udp.expire(now)
	x.echo.expire(now)
}

// Close closes the link, the stack, once each request the forwarder handed
// over has ended and each mapping's readers have, the platform's ICMP
// sockets, and Raw, once. Run's end calls it last, and it closes an exit
// whose Run never ran.
func (x *Exit) Close() error {
	var err error
	x.closeOnce.Do(func() {
		x.link.Close()
		x.stack.Close()
		x.tcp.withdraw()
		x.udp.withdraw()
		x.echo.withdraw()
		x.tcp.running.Wait()
		x.udp.readers.Wait()
		x.echo.readers.Wait()
		x.icmp.close()
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
	v4, v6 := ready[egress.FamilyIPv4], ready[egress.FamilyIPv6]
	x.SetReady(egress.Readiness{Ready4: v4, Ready6: v6, Why4: why[egress.FamilyIPv4], Why6: why[egress.FamilyIPv6],
		Carries4: routed[egress.FamilyIPv4], Carries6: routed[egress.FamilyIPv6]})
	moved := x.Publish(announced)
	x.stats.Store(&passStats{At: time.Now(), Ready4: v4, Ready6: v6, Unready: x.Unready(), Announced: announced})
	if moved {
		x.rt.Events.Emit("egress.pass", "", slog.String("trigger", x.trigger), slog.Int("announced", len(announced)))
	}
}

// readiness is whether family is ready, routed, whether the host carries it
// out, which holds where a link outside the mesh reaches any prefix the family
// reads or the lookup of any of them failed, judged over all of them whichever
// fails first, and why it is not ready, the first failure in the prefixes'
// order and then the classes': the host must route the read address of each
// prefix the family advertises, or of its default where it advertises none,
// over a link outside the mesh, and hold each address its classes name where a
// socket scoped to each such link sends from it. A failed lookup counts as
// carried, since an unknown route is not a known absence, so the family
// withdraws the egress SIDs while it is not ready.
func (x *Exit) readiness(family uint8) (ready, routed bool, why string) {
	type read struct {
		prefix netip.Prefix
		link   string
	}
	var reads []read
	for _, prefix := range x.cfg.ReadPrefixes(family) {
		failed := ""
		address, _ := egress.ReadAddress(prefix)
		if link, found, err := x.rt.Platform.Route(address); err != nil {
			routed = true
			failed = "the route lookup of " + address.String() + " for " + prefix.String() + " failed: " + err.Error()
		} else if !found {
			failed = "no link outside the mesh reaches " + address.String() + " for " + prefix.String()
		} else {
			routed = true
			reads = append(reads, read{prefix, link.Name})
		}
		if why == "" {
			why = failed
		}
	}
	if why != "" {
		return false, routed, why
	}
	for _, class := range x.cfg.Classes(family) {
		named := class.To.Addr
		if !named.IsValid() {
			continue
		}
		if !x.rt.Platform.Held(named, "") {
			return false, routed, "this host does not hold " + named.String() + ", an address cap.egress translate names"
		}
		for _, r := range reads {
			if !x.rt.Platform.Held(named, r.link) {
				return false, routed, "this host does not hold " + named.String() + ", an address cap.egress translate names, on " + r.link + ", the link this host reaches " + r.prefix.String() + " by"
			}
		}
	}
	return true, routed, ""
}
