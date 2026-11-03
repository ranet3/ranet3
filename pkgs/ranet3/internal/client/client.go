// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package client owns the mesh runtime: peer reconnection, IKE/ESP lifetimes,
// Babel registration, reload, down and up, and the readiness the exit and the
// antispoof filter hand it. cmd/ranet3 builds the antispoof filter, the route
// reconciler, the exit and the listeners around it, and orders their start and
// stop.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

type Client struct {
	Mesh *netstack.Mesh

	// cfg and registryIndex are replaced wholesale by a reload, never mutated, so a reader never sees one half written
	cfg           atomic.Pointer[config.Config]
	registryIndex atomic.Pointer[registry.Index]
	privateKey    ed25519.PrivateKey
	speaker       *babel.Speaker
	hub           *transport.Hub
	// closeUnderlay releases whatever the transport's underlay had to open,
	// which on darwin is the selection and the watcher it shares with the
	// network watch. Nil on a Client built by hand in a test.
	closeUnderlay func()
	// underlayRoutes is the selection the transport names each underlay
	// datagram's interface from, as the rules view reads it, nil where the
	// transport selects none
	underlayRoutes underlayRoutes
	// selection is the same selection as the route reconciler reads it, nil where the transport selects none
	selection kernel.UnderlaySelection
	// host is the machine the underlay and the route reconciler read and
	// write, nil for the one this process is running on. It is kept so the
	// reconciler this client hands the command is built against the same
	// machine the underlay was opened on.
	host     kernel.Host
	sessions *sessionSet
	workers  int
	ctx      context.Context
	cancel   context.CancelFunc

	// dialers is one cancel per running peer loop, keyed by the same path name
	// sessions uses, so a reload can start and stop them individually.
	dialersMu sync.Mutex
	dialers   map[string]*dialer
	// dialRetry overrides defaultReconnectDelay, and zero means the default.
	dialRetry time.Duration
	// probeTimeout overrides defaultProbeTimeout and confirmEvery confirmInterval, and zero means the default
	probeTimeout, confirmEvery time.Duration
	// stopped closes the door on new dialers. Run sets it under dialersMu
	// before waiting, so a reload arriving at the same moment cannot add to
	// the WaitGroup after the wait has begun, which panics.
	stopped bool
	peers   sync.WaitGroup
	// responder is the running acceptPeers, nil while link.listen is off, guarded by dialersMu so it is started and stopped against stopped as dialers are
	responder *responderRun
	// speakerRun is the running speaker, nil while it is stopped, guarded by dialersMu as responder is
	speakerRun *speakerRun
	// stateDir is where the down flag lives, set before the socket or Run can read it
	// a client nobody gave one refuses down and up
	stateDir string
	// downSince is when the node went off the mesh, nil while it is on it
	// down and up move it under reloadMu, and nothing of the mesh starts while it is set
	downSince atomic.Pointer[time.Time]
	// lastMove is the last move between up and down, nil before the first
	lastMove atomic.Pointer[control.UpDownChange]

	// regReadAt is when the registry now installed was read, in unix
	// nanoseconds, so a diagnostic can tell a registry that reloaded from one
	// that has been the same since startup.
	regReadAt atomic.Int64
	// reconciler is the route reconciler SetReconciler took, nil until then
	// and nil forever on a node whose routes are configured externally
	reconciler atomic.Pointer[Reconciler]
	// exit carries cap.egress, handed over by the command that built it and
	// nil on a node with no cap.egress. Its announcement is read on every
	// republication rather than captured, because an exit withholds a family
	// whenever it is not ready and the set it may announce changes under a
	// running node.
	exit atomic.Pointer[egress.Exit]
	// egressServes is the translator's last word on whether the egress SIDs are served
	egressServes atomic.Bool
	// republishMu runs one republish at a time, each reading the stored
	// configuration and egressServes once it holds it, so the last to finish
	// reads the last of both
	// it is taken after reloadMu and before egressMu and the speaker's own
	republishMu sync.Mutex
	// egressMu orders the mesh's moves of egress readiness, each computed from
	// the translator's pair and the families the last republish found
	// advertised, so the mesh holds the last of both
	// it never wraps a republish
	egressMu                 sync.Mutex
	translator4, translator6 bool
	advertised4, advertised6 bool
	// border is the antispoof filter, handed over by the command that built it
	// and nil where the platform runs none
	border atomic.Pointer[borderFilter]
	// borderNetwork carries one coalesced wake to the antispoof filter per change
	// of the host's network, which moves the carve-outs. A reload wakes the
	// filter through its SetConfig.
	borderNetwork chan struct{}
	// borderRefusal refuses an exemption's interface name that the antispoof
	// filter's backend cannot write, and nil means kernelexit.RefuseBorder
	borderRefusal func(*egress.Border) error
	// ruleDump reads every policy rule the host holds, and nil means kernel.DumpRules
	ruleDump func() ([]kernel.DumpedRule, error)
	// routeGet asks the kernel for one packet's route, and nil means kernel.RouteGet
	routeGet func(src, dst netip.Addr, iif string) (kernel.MatchedRoute, error)
	// sysctl reads a setting by its path under /proc/sys, the empty string
	// where it cannot, and nil means Sysctl
	sysctl func(path string) string
	// fallbackRead reads the table ranet3_fallback, and nil means kernel.ReadFallback
	fallbackRead func() (kernel.FallbackDebug, error)
	// unresolved is each endpoint name whose last lookup failed
	unresolved names
	// dialed is each running dialer's last resolved address
	dialed dialedAddresses

	// running is the control socket's write path state: whether each named
	// subsystem is acting. It is the record rather than the mechanism, since
	// each subsystem keeps its own flag where its hot path can read it. A
	// status reports this map and a second write compares against it.
	runningMu sync.Mutex
	running   map[control.Subsystem]bool
	// configPath is where the daemon read this node's configuration, so the
	// reload verb re-reads the same file SIGHUP does. Empty on a client a test
	// built by hand, where the verb says so rather than guessing at a path.
	configPath atomic.Pointer[string]
	// reloadMu runs one reload at a time, so the reconciler takes each cap.table in the order the node stores the files
	reloadMu sync.Mutex
	// stopBegun is set once the daemon's stop has begun, ahead of reloadMu, and up, reload, redial and Run's first dial each
	// read it once they hold reloadMu
	stopBegun atomic.Bool

	// events is the daemon's bus, nil on a Client a test built by hand
	events *events.Bus
	// network is the host's network watch, which Run follows and Close closes
	// nil on a platform without one and on a Client a test built by hand
	network networkSource

	inboundPackets atomic.Uint64
	inboundDropped atomic.Uint64
	// inboundCE counts the packets the decapsulation set to CE from an ECT inner field, inboundECNUnused those of an ECN combination no tunnel sends, the dropped ones among them
	inboundCE        atomic.Uint64
	inboundECNUnused atomic.Uint64
	probes           probeTotals
	// dropReported is nanoseconds since started, read through time.Since so it
	// comes off the monotonic clock, and primed one interval in the past so
	// the first refused batch is still said out loud. See noteInboundDropped.
	dropReported atomic.Int64
	started      time.Time
}

func (c *Client) config() *config.Config { return c.cfg.Load() }
func (c *Client) index() *registry.Index { return c.registryIndex.Load() }

// suites is the cap.crypto lists in force
// each exchange of every session reads them
// so a reload reaches the next one
func (c *Client) suites() ike.Suites {
	// the configuration in force passed Validate
	// and Validate resolves the lists
	suites, _ := c.config().Crypto().Suites()
	return suites
}

func (c *Client) storeIndex(x *registry.Index) {
	c.registryIndex.Store(x)
	c.regReadAt.Store(time.Now().UnixNano())
}

// Underlay is every literal endpoint address in the registry this node could
// have to reach and each running dialer's last resolved address, a name's
// among them
func (c *Client) Underlay() []netip.Addr {
	var out []netip.Addr
	if x := c.index(); x != nil {
		out = slices.Clone(x.Underlay())
	}
	return append(out, c.dialed.list()...)
}

// readsOwnedOnly is the mesh's ownedOnly for this build
const readsOwnedOnly = !kernelexit.EntryRuns

// New builds the node from its configuration, recording what it does on bus
func New(cfg *config.Config, bus *events.Bus) (_ *Client, err error) {
	privateKey, err := registry.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		return nil, err
	}
	x, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeConfig(cfg, privateKey, x); err != nil {
		return nil, err
	}
	warnUnbordered(cfg.Border(), hostForwarding)
	warnForwardedUnderExit(cfg, hostForwarding, bus)
	warnCountedAdvertisements(cfg)
	// Before the tun exists, so a segment this node could not answer for
	// refuses the startup without a device to clean up.
	segments, steering, err := cfg.SegmentTables()
	if err != nil {
		return nil, err
	}
	// Every steered packet carries its segment list inside the tunnel, so the
	// device has to hand over packets small enough to still fit once it is
	// there. Taking it off the MTU is ordinary tunnel behavior, and the
	// alternative is a large packet arriving that cannot be encapsulated and
	// going out unsteered, which is a silent hole in the steering rather than
	// a smaller MSS.
	largest := cfg.Link.SessionMTU()
	mtu, err := steeredMTU(largest, steering)
	if err != nil {
		return nil, err
	}
	mesh, err := netstack.NewNamed(mtu, cfg.Link.TUN, readsOwnedOnly, bus.Emit)
	if err != nil {
		return nil, err
	}
	mesh.SetSegments(segments)
	mesh.SetSteering(steering)
	defer func() {
		if err != nil {
			mesh.Close()
		}
	}()
	return newClient(cfg, privateKey, x, mesh, nil, bus)
}

// steeredMTU is the device MTU for sessions carrying packets of up to largest bytes
// the longest configured segment list comes off it
// a node that steers nothing runs the device at largest
// the arithmetic and the refusal are the capability's own
// config.Validate makes the same call with link.mtu, so a file the loader took is a file this starts on
func steeredMTU(largest int, steering *srv6.SteerTable) (int, error) {
	if steering.Overhead() == 0 {
		return largest, nil
	}
	return steering.CheckMTU(largest)
}

// newClient is New with the loading done, so a test can stand up a client
// around a mesh it built itself rather than a privileged TUN. host is the
// machine the underlay reads and writes, nil for the one this process is
// running on, as New passes and as a deployment gets.
func newClient(cfg *config.Config, privateKey ed25519.PrivateKey, x *registry.Index, mesh *netstack.Mesh, host kernel.Host, bus *events.Bus) (_ *Client, err error) {
	ttl, err := defaultTTL()
	if err != nil {
		return nil, err
	}
	mesh.SetAnswerTTL(ttl)
	underlay, watcher, closeUnderlay, err := underlayRuntime(mesh.Name, host)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			closeUnderlay()
		}
	}()
	underlay.Events = func(kind string, attrs ...slog.Attr) { bus.Emit(kind, "", attrs...) }
	hub, err := transport.NewHub(cfg.Link.Port, underlay)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = hub.Close()
		}
	}()
	sessions := newSessionSet()
	organization, _ := cfg.Node.NodeParts()
	speaker, err := babel.New(cfg.Babel(), cfg.Routes(), babel.Runtime{Events: bus, ProbeAcked: sessions.probeAcked, NoTransit: !cfg.Transits(), Organization: organization}, mesh)
	if err != nil {
		return nil, err
	}
	assigned := assignedAddresses(cfg)
	speaker.SetAssigned(assigned)
	mesh.SetTunAddresses(assigned)
	network, err := openNetwork(host, mesh.Name, watcher)
	if err != nil {
		return nil, err
	}
	if err := refuseForwardedHere(cfg, mesh.Name, network); err != nil {
		_ = network.Close()
		return nil, err
	}
	routes, _ := underlay.Selection.(underlayRoutes)
	selection, _ := underlay.Selection.(kernel.UnderlaySelection)
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		Mesh: mesh, privateKey: privateKey,
		speaker: speaker, hub: hub, closeUnderlay: closeUnderlay, underlayRoutes: routes, selection: selection,
		host:     host,
		sessions: sessions,
		workers:  max(1, runtime.GOMAXPROCS(0)),
		ctx:      ctx, cancel: cancel,
		dialers: make(map[string]*dialer),
		running: startedSubsystems(),
		started: time.Now(),
		events:  bus,
		network: network,

		borderNetwork: make(chan struct{}, 1),
	}
	c.sessions.events = bus
	c.sessions.trust = liveTrust{c}
	c.sessions.steering = mesh.Steering()
	c.dropReported.Store(-int64(espDropReportInterval))
	c.cfg.Store(cfg)
	c.storeIndex(x)
	mesh.SetAnswerSources(answerSources(cfg))
	startDecision(mesh, cfg)
	return c, nil
}

// startDecision hands mesh what its forwarding decision reads of cfg from the start
func startDecision(mesh *netstack.Mesh, cfg *config.Config) {
	// a reload that changes cap.transit is refused, so the decision reads the start's
	mesh.SetTransit(cfg.Transits())
	mesh.SetOverlay(cfg.Overlay)
	// a reload that changes cap.egress is refused, so the start's prefixes hold
	mesh.SetEgressPrefixes(cfg.Advertised())
}

// Run is called once, and runs until ctx ends or Close is called. It returns
// only after peer handshakes, IKE sessions, ESP workers and Babel timers have
// stopped, including cancellation during dialing.
func (c *Client) Run(ctx context.Context) {
	// Tell every peer before the sessions go, rather than leaving each of them
	// sending ESP into an SPI we no longer accept until its own dead peer
	// detection expires. It runs before c.cancel because a canceled session
	// has no loop left to carry the Delete.
	stop := context.AfterFunc(ctx, func() {
		c.stopDialers()
		c.leave()
		c.cancel()
	})
	defer stop()
	defer c.Close()
	if ctx.Err() != nil {
		c.cancel()
	}
	if c.network != nil {
		c.peers.Go(func() { c.followNetwork(c.ctx) })
	}
	c.firstDial()
	<-c.ctx.Done()
	// Done before the hub closes, so a dialer reads the session ending as
	// this node stopping. See stopping.
	_ = c.hub.Close()
	c.stopDialers()
	c.peers.Wait()
}

// firstDial puts the node on the mesh as up does, under reloadMu, and dials
// nothing once the stop has begun
func (c *Client) firstDial() {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	if c.refuseWhileStopping("dial") == nil {
		c.syncMesh()
	}
}

// MarkStopping refuses up, reload and redial from here on and returns at
// once, for the cancel that ends the daemon's run, which must not wait on a
// verb
func (c *Client) MarkStopping() { c.stopBegun.Store(true) }

// BeginStop refuses up, reload and redial from here on, then returns once one
// that held reloadMu as the stop began has returned
func (c *Client) BeginStop() {
	c.stopBegun.Store(true)
	// a verb that takes the lock after this one reads the flag set above
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
}

// refuseWhileStopping is the answer up, reload and redial get once the daemon's stop has begun, and nil before
// c.reloadMu is held
func (c *Client) refuseWhileStopping(verb string) error {
	if !c.stopBegun.Load() {
		return nil
	}
	return fmt.Errorf("control: this node is stopping, so it cannot %s", verb)
}

// leave closes every session, then stops the loops and waits for them
// it reports the paths of the sessions it closed
func (c *Client) leave() []string {
	closed := c.sessions.closeAll()
	c.syncMesh()
	return closed
}

// syncMesh brings the dialers, the responder and the speaker to what the node's place on the mesh asks for
// that is everything the file names while the node is on it and nothing once it is off
// it waits for each loop it stops to end
func (c *Client) syncMesh() {
	for _, stopped := range c.syncPeers() {
		<-stopped.done
	}
	c.syncResponder()
	c.syncSpeaker()
}

// onMeshLocked reports whether this node dials, answers and speaks Babel
// it does until the shutdown starts or somebody takes it down, and c.dialersMu is held
func (c *Client) onMeshLocked() bool {
	return !c.stopped && c.downSince.Load() == nil && c.ctx.Err() == nil
}

// speakerRun is one run of the speaker, with the cancel that ends it and done closed once it has
type speakerRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// syncSpeaker runs the speaker while the node is on the mesh and stops it once it is not, waiting for it to return
// nothing starts it again behind the flag that stopped it, so two runs of the one speaker never overlap
func (c *Client) syncSpeaker() {
	c.dialersMu.Lock()
	run, want := c.speakerRun, c.onMeshLocked()
	if want && run == nil {
		ctx, cancel := context.WithCancel(c.ctx)
		started := &speakerRun{cancel: cancel, done: make(chan struct{})}
		c.speakerRun = started
		c.peers.Go(func() {
			defer close(started.done)
			_ = c.speaker.Run(ctx)
		})
	}
	if want || run == nil {
		c.dialersMu.Unlock()
		return
	}
	c.speakerRun = nil
	c.dialersMu.Unlock()
	run.cancel()
	<-run.done
}

// Close is idempotent and can interrupt Run.
// The network watch closes before the underlay, so on darwin both readers of
// the shared watcher are gone before the watcher closes.
func (c *Client) Close() {
	c.cancel()
	_ = c.hub.Close()
	if c.network != nil {
		_ = c.network.Close()
	}
	if c.closeUnderlay != nil {
		c.closeUnderlay()
	}
	c.Mesh.Close()
}

// SetExit hands the node and the mesh the exit the command built, before the
// sessions start and before the exit's first pass. The mesh reads the exit only
// once a readiness word names a family ready, and the exit's hooks set those
// words after SetExit, so a session that delivers earlier finds no family ready
// and leaves the exit unread. The mesh hands it both egress verdicts' batches,
// Republish reads its announcement, the status renders its Status, and down and
// up reach its SetEnabled, a node that starts down handing it its stop here.
func (c *Client) SetExit(exit egress.Exit) {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	c.Mesh.SetExit(exit)
	c.exit.Store(&exit)
	if c.downSince.Load() != nil {
		exit.SetEnabled(false)
	}
}

// SetEgressReady takes the translator's readiness per family, which egress
// through the egress segments and through the prefixes it advertises both wait
// on, and its word on whether the egress SIDs are served. The mesh learns
// it before a SID's /128 or an advertised prefix is originated or retracted: a
// packet either attracts finds the mesh handing it to the exit, and a packet
// arriving after the translation went is dropped before the retraction reaches
// anyone.
func (c *Client) SetEgressReady(v4, v6, serves bool) {
	c.egressMu.Lock()
	c.translator4, c.translator6 = v4, v6
	c.moveMeshEgressLocked()
	c.egressMu.Unlock()
	c.egressServes.Store(serves)
	c.Republish()
}

// moveMeshEgressLocked runs with c.egressMu held. The advertised prefixes'
// word takes the translator's pair as well as the families the last republish
// found advertised, since an exit whose translation another writer took goes
// on announcing until its next pass, and a frame egressed then leaves
// untranslated.
func (c *Client) moveMeshEgressLocked() {
	c.Mesh.SetEgressReady(c.translator4, c.translator6)
	c.Mesh.SetAdvertisedReady(c.translator4 && c.advertised4, c.translator6 && c.advertised6)
}

// borderFilter is the antispoof filter as the node reloads and reports it. The
// command builds it, since it owns a table in the host's packet filter and
// this owns the mesh.
type borderFilter interface {
	SetConfig(egress.Border) error
	Capability() egress.Border
	Inside() []string
	Where() string
	Stats() egress.BorderStats
	Debug() egress.BorderDebug
}

// SetBorder hands the node the antispoof filter the command built, which a
// reload hands the overlay, the exemptions and this node's own prefixes and
// addresses, and the status reads
func (c *Client) SetBorder(f borderFilter) { c.border.Store(&f) }

// BorderInside is the devices the antispoof filter accepts whatever they carry:
// the mesh tun and the loopback link, through which a packet this host sends to its own
// address meets prerouting. A reload moves neither of them.
func (c *Client) BorderInside() []string {
	return []string{c.Mesh.Name, kernel.Loopback}
}

// BorderRuntime hands the antispoof filter what the node resolves at startup: the
// mesh tun, the devices inside the mesh, the bus, the sets as the mesh's table
// and the host's network give them now, a wake for each of those two, and the
// state directory, which SetStateDir names first. It takes a reader of the
// mesh's table, so the command calls it once.
func (c *Client) BorderRuntime() egress.BorderRuntime {
	return egress.BorderRuntime{
		Tun:      c.Mesh.Name,
		Inside:   c.BorderInside(),
		Events:   c.events,
		Sets:     c.borderSets,
		Routes:   c.Mesh.Routes.Changes(),
		Network:  c.borderNetwork,
		StateDir: c.stateDir,
	}
}

// borderSets is the antispoof filter's sets now, which it derives on each pass
// from the configuration the filter holds, border, and from the mesh's table
// and the host's links. Only cap.egress's classes are read from the file
// stored, and a reload refuses to move them.
func (c *Client) borderSets(border *egress.Border) egress.BorderSets {
	var overlay []schema.Prefix
	if border != nil {
		overlay = border.Overlay
	}
	snapshot := c.Mesh.Routes.Snapshot()
	var classes []egress.Class
	if exit := c.config().Egress(); exit != nil {
		classes = exit.Translate
	}
	sets := egress.BorderSets{
		Owned: kernel.OwnedSources(snapshot, overlay),
		None:  kernel.NoneDestinations(classes, snapshot, overlay),
	}
	if border != nil {
		network := c.networkState()
		for _, family := range []kernel.NetworkFamily{network.IPv4, network.IPv6} {
			for _, link := range family.Links {
				sets.Links = append(sets.Links, link.Name)
			}
		}
		slices.Sort(sets.Links)
		sets.Links = slices.Compact(sets.Links)
		sets.CarveOuts = kernel.CarveOuts(network, overlay)
		carved, conflicts := kernel.CarvedSets(border, sets.CarveOuts, snapshot)
		sets.Carved = carved
		if c.speaker != nil {
			for i, conflict := range conflicts {
				if origin, ok := c.speaker.SelectedOrigin(conflict.Prefix); ok {
					conflicts[i].RouterID = hex.EncodeToString(origin[:])
				}
			}
			conflicts = append(conflicts, kernel.OwnCopies(border.Exemptions(), border.Own, func(prefix netip.Prefix) (string, bool) {
				origin, ok := c.speaker.OfferedOrigin(prefix)
				return hex.EncodeToString(origin[:]), ok
			})...)
		}
		sets.Conflicts = conflicts
	}
	return sets
}

// KernelRuntime assembles what cap.table's reconciler reads from outside the
// capability: the device the mesh actually got and the addresses the
// transport has to keep reaching, which only a running node knows, and what
// other capabilities write, the prefixes cap.route announces and the overlay.
//
// It is assembled here rather than in the command because most of it is this
// client's own and the rest is the configuration it runs. The command builds
// the reconciler from it. See kernel.Runtime for what each field decides.
func (c *Client) KernelRuntime() kernel.Runtime {
	cfg := c.config()
	return kernel.Runtime{
		Interface:     c.Mesh.Name,
		Underlay:      c.Underlay,
		Announced:     cfg.Routes().Announced(),
		Overlay:       cfg.Overlay,
		Advertised:    cfg.Advertised(),
		EgressSegment: len(cfg.Segments().Egress()) > 0,
		Sessions:      c.LiveSessions,
		Sends:         c.liveSends,
		Host:          c.host,
		Events:        c.events,
		Network:       c.networkState,
		Resolvers:     kernel.ResolvedLinkServers,
		Selection:     c.selection,
	}
}

// LiveSessions is how many of this node's sessions have recently proved their
// peer is there. The route reconciler reads it before it hands this machine's
// own traffic to the mesh, so the answer is deliberately the narrow one: a
// session that is merely installed proves nothing, and a peer that rebooted
// leaves one looking established for over a minute.
func (c *Client) LiveSessions() int {
	return c.sessions.liveCount()
}

func (c *Client) liveSends() []kernel.Send {
	if c.sessions == nil {
		return nil
	}
	live := c.sessions.snapshot()
	out := make([]kernel.Send, 0, len(live))
	for _, session := range live {
		if send := session.session.Mux().Sends(); send.Destination.IsValid() {
			out = append(out, kernel.Send(send))
		}
	}
	return out
}

// dialer is one running peer loop. It is a pointer so an entry has an identity
// a later goroutine can compare against, which a func value cannot provide.
//
// wake cuts short the wait before the next dial, and is buffered so a redial
// arriving while the loop is dialing rather than waiting is not lost and does
// not block the caller. One place is enough: two asks that land before the
// loop comes round are one attempt either way.
//
// done is closed once the loop has returned, session and all. A sweep that
// stops the loop waits on it.
type dialer struct {
	cancel context.CancelFunc
	wake   chan struct{}
	done   chan struct{}
}

// stopDialers refuses any further dialer before the wait below begins. It is
// the write half of the check syncPeers makes under the same lock: without it
// a SIGHUP that reaches syncPeers as Run is shutting down can call Go on a
// WaitGroup whose counter has already reached zero and whose Wait has already
// started, which is a panic rather than a race the scheduler smooths over.
func (c *Client) stopDialers() {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	c.stopped = true
}

// stopping lets a dialer tell this node going down from a peer worth retrying.
// The context does not: closeAll runs before c.cancel, deliberately, so a
// Delete still has a loop to carry it, and every dialer whose session ends in
// that window would otherwise say "reconnecting in 10s" at the one moment none
// of them will.
// down sweeps the same way before it cancels the dialers, so it counts as well
func (c *Client) stopping() bool {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return c.stopped || c.downSince.Load() != nil
}
