// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package client owns the mesh runtime: peer reconnection, IKE/ESP lifetimes,
// and Babel registration. The command only handles flags, signals and logging.
package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
	"ranet3.com/pkgs/wireguard/tun"
)

type Client struct {
	Mesh *netstack.Mesh

	// cfg and registryIndex are replaced wholesale by a reload, never mutated, so a reader never sees one half written
	cfg           atomic.Pointer[config.Config]
	registryIndex atomic.Pointer[registry.Index]
	privateKey    ed25519.PrivateKey
	speaker       *babel.Speaker
	hub           *transport.Hub
	// closeUnderlay releases whatever the transport's underlay setting had to
	// open, which on darwin is the route socket the binding follows. Nil on a
	// Client built by hand in a test.
	closeUnderlay func()
	// capture holds whatever the route reconciler needs in the kernel before
	// it hands this machine's own traffic to the mesh, nil where the platform
	// needs nothing. It lives here rather than in main because it shares the
	// link watcher the transport binds through, and the two have to agree
	// about which interface the underlay is on.
	capture kernel.CaptureRoutes
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
	// kernelStatus is the route reconciler's own view, supplied by the command
	// that built it. Nil until then, and nil forever on a node whose routes
	// are configured externally.
	kernelStatus atomic.Pointer[func() control.KernelStatus]
	// egressStatus and egressAnnounce are the egress capability's, supplied
	// the same way. The second is read on every republication rather than
	// captured, because an exit withholds its advertisement whenever its chain
	// does not read back as written and the set it may announce changes under
	// a running node.
	egressStatus   atomic.Pointer[func() control.EgressStatus]
	egressAnnounce atomic.Pointer[func() []netip.Prefix]
	// egressDevice is set once by New and empty on a node with no egress device
	egressDevice string
	// egressWithdrawn makes Close report the device's removal once
	egressWithdrawn atomic.Bool
	// egressServes is the translator's last word on whether the egress SIDs are served
	egressServes atomic.Bool
	// borderHeld is a cap.border whose chain is not read back, which holds
	// both families of the egress device and the egress SIDs back
	borderHeld atomic.Bool
	// republishMu runs one republish at a time, each reading the stored
	// configuration, egressServes and borderHeld once it holds it, so the last
	// to finish reads the last of all three
	// it is taken after reloadMu and before the speaker's own
	republishMu sync.Mutex
	// egressMu orders the mesh's moves of egress readiness, each computed from
	// the translator's pair and borderHeld, so the mesh holds the last of both
	// it never wraps a republish
	egressMu                 sync.Mutex
	translator4, translator6 bool
	// border is the border filter, handed over by the command that built it
	// and nil on a node with no cap.border
	border atomic.Pointer[borderFilter]
	// ruleDump reads every policy rule the host holds, and nil means kernel.DumpRules
	ruleDump func() ([]kernel.DumpedRule, error)

	// running is the control socket's write path state: whether each named
	// subsystem is acting. It is the record rather than the mechanism, since
	// each subsystem keeps its own flag where its hot path can read it. A
	// status reports this map and a second write compares against it.
	runningMu sync.Mutex
	running   map[control.Subsystem]bool
	// reconcilerEnable stops and starts the route reconciler, supplied by the
	// command that built it as SetKernelStatus is. Nil on a node with no
	// cap.table, where the verb is refused by name rather than reported as
	// having stopped something.
	reconcilerEnable atomic.Pointer[func(bool)]
	// reconcilerTable hands the route reconciler a reloaded cap.table and cap.border overlay, supplied as reconcilerEnable is
	reconcilerTable atomic.Pointer[func(kernel.Table, []schema.Prefix, []netip.Prefix) error]
	// egressEnable stops and starts the egress translator, supplied as reconcilerEnable is and nil on a node with no cap.egress
	egressEnable atomic.Pointer[func(bool)]
	// configPath is where the daemon read this node's configuration, so the
	// reload verb re-reads the same file SIGHUP does. Empty on a client a test
	// built by hand, where the verb says so rather than guessing at a path.
	configPath atomic.Pointer[string]
	// reloadMu runs one reload at a time, so the reconciler takes each cap.table in the order the node stores the files
	reloadMu sync.Mutex

	// events is the daemon's bus, nil on a Client a test built by hand
	events *events.Bus
	// network is the host's network watch, which Run follows and Close closes
	// nil on a platform without one and on a Client a test built by hand
	network networkSource

	inboundPackets atomic.Uint64
	inboundDropped atomic.Uint64
	probes         probeTotals
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

// Underlay is every endpoint address in the registry this node could have to
// reach, which the route reconciler consults so that a route covering one is
// not installed where the transport would then follow it into its own tunnel.
// A hostname endpoint is not in it, because resolving one is a network call.
func (c *Client) Underlay() []netip.Addr {
	if x := c.index(); x != nil {
		return x.Underlay()
	}
	return nil
}

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
	warnUnbordered(cfg, forwardingEnabled)
	warnVRFWithoutL3mdev(cfg)
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
	// before the mesh tun, so a platform with no egress device refuses with nothing made
	egressName, egressDevice, err := newEgressDevice(cfg, mtu)
	if err != nil {
		return nil, err
	}
	mesh, err := netstack.NewNamed(mtu, cfg.Link.TUN, bus.Emit)
	if err != nil {
		if egressDevice != nil {
			_ = egressDevice.Close()
		}
		return nil, err
	}
	mesh.SetSegments(segments)
	mesh.SetSteering(steering)
	defer func() {
		if err != nil {
			mesh.Close()
		}
	}()
	if egressDevice != nil {
		// the mesh owns the device from here and closes it with itself, which removes the link
		mesh.SetEgress(egressDevice)
		slog.Info("egress device created", "name", egressName, "mtu", mtu)
		bus.Emit("egress.device", "", slog.String("name", egressName), slog.String("action", "created"))
	}
	c, err := newClient(cfg, privateKey, x, mesh, nil, bus)
	if err != nil {
		return nil, err
	}
	c.egressDevice = egressName
	return c, nil
}

func newEgressDevice(cfg *config.Config, mtu int) (string, tun.Device, error) {
	segments := cfg.Segments().Egress()
	if len(segments) == 0 {
		return "", nil, nil
	}
	name, err := netstack.EgressName(cfg.Link.TUN)
	if err != nil {
		return "", nil, fmt.Errorf("config: %w", err)
	}
	device, err := netstack.NewEgressDevice(name, mtu)
	return name, device, egressDeviceRefusal(segments[0], err)
}

func egressDeviceRefusal(segment srv6.Segment, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("cap.segment local %s delivers to egress: %w", segment.SID, err)
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
	underlay, capture, closeUnderlay, err := underlayRuntime(cfg.Link.Underlay, mesh.Name, host)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			closeUnderlay()
		}
	}()
	underlay.Events = func(kind string, attrs ...slog.Attr) { bus.Emit(kind, "", attrs...) }
	hub, err := transport.NewHub(fmt.Sprintf(":%d", cfg.Link.Port), cfg.Link.Underlay, underlay)
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
	speaker.SetAssigned(assignedAddresses(cfg))
	network, err := openNetwork(host, mesh.Name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		Mesh: mesh, privateKey: privateKey,
		speaker: speaker, hub: hub, closeUnderlay: closeUnderlay, capture: capture,
		host:     host,
		sessions: sessions,
		workers:  max(1, runtime.GOMAXPROCS(0)),
		ctx:      ctx, cancel: cancel,
		dialers: make(map[string]*dialer),
		running: startedSubsystems(),
		started: time.Now(),
		events:  bus,
		network: network,
	}
	// the border's first pass reports it ready before main hands the filter over
	c.borderHeld.Store(cfg.Cap.Border != nil)
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
	mesh.SetOverlay(cfg.Overlay())
	// a reload that changes cap.egress is refused, so the start's prefixes hold
	mesh.SetEgressPrefixes(egressPrefixes(cfg))
}

// Run is called once. It returns only after peer handshakes, IKE sessions, ESP
// workers and Babel timers have stopped, including cancellation during dialing.
func (c *Client) Run(ctx context.Context) error {
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
	c.syncMesh()
	<-c.ctx.Done()
	// Done before the hub closes, so a dialer reads the session ending as
	// this node stopping. See stopping.
	_ = c.hub.Close()
	c.stopDialers()
	c.peers.Wait()
	return c.ctx.Err()
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
func (c *Client) Close() {
	c.cancel()
	_ = c.hub.Close()
	if c.closeUnderlay != nil {
		c.closeUnderlay()
	}
	if c.network != nil {
		_ = c.network.Close()
	}
	c.Mesh.Close()
	if c.egressDevice != "" && c.egressWithdrawn.CompareAndSwap(false, true) {
		slog.Info("egress device withdrawn", "name", c.egressDevice)
		c.events.Emit("egress.device", "", slog.String("name", c.egressDevice), slog.String("action", "withdrawn"))
	}
}

func (c *Client) EgressDevice() string { return c.egressDevice }

// EgressDeviceReader is nil on a node with no egress device
func (c *Client) EgressDeviceReader() func() (v4, v6 error) {
	if c.egressDevice == "" {
		return nil
	}
	return egressDeviceReader(c.egressDevice)
}

// SetEgressReady takes the translator's readiness of the egress device per
// family and its word on whether the egress SIDs are served. The mesh learns
// it before the SID's /128 is originated or retracted: a packet the /128
// attracts finds the mesh writing, and a packet arriving after the
// translation went is dropped before the retraction reaches anyone.
func (c *Client) SetEgressReady(v4, v6, serves bool) {
	c.egressMu.Lock()
	c.translator4, c.translator6 = v4, v6
	c.moveMeshEgressLocked()
	c.egressMu.Unlock()
	c.egressServes.Store(serves)
	c.Republish()
}

// SetBorderReady takes whether the border filter's chain reads back as the
// configuration asks. Neither family of the egress device is ready, and no
// egress SID is served, while it does not, in the order SetEgressReady keeps.
func (c *Client) SetBorderReady(ok bool) {
	c.egressMu.Lock()
	c.borderHeld.Store(!ok)
	c.moveMeshEgressLocked()
	c.egressMu.Unlock()
	c.Republish()
}

// moveMeshEgressLocked hands the mesh each family the translator and the
// border both hold ready, with c.egressMu held
func (c *Client) moveMeshEgressLocked() {
	held := c.borderHeld.Load()
	c.Mesh.SetEgressReady(c.translator4 && !held, c.translator6 && !held)
}

// borderFilter is the border filter as the node reloads and reports it. The
// command builds it, since it owns a table in the host's packet filter and
// this owns the mesh.
type borderFilter interface {
	SetConfig(egress.Border, []netip.Addr) error
	Capability() egress.Border
	SIDs() []netip.Addr
	Inside() []string
	Where() string
	Stats() egress.BorderStats
	Debug() egress.BorderDebug
}

// SetBorder hands the node the border filter the command built, which a
// reload hands the overlay and the SIDs and the status reads
func (c *Client) SetBorder(f borderFilter) { c.border.Store(&f) }

// BorderInside is the devices the border filter accepts whatever they carry:
// the mesh tun, the egress device where one exists, lo, through which a packet
// this host sends to its own address meets prerouting, and the VRF master the
// tun is enslaved to, as which a packet arriving on the tun meets prerouting a
// second time. A reload moves none of them.
func (c *Client) BorderInside() []string {
	inside := []string{c.Mesh.Name}
	if c.egressDevice != "" {
		inside = append(inside, c.egressDevice)
	}
	inside = append(inside, "lo")
	if table := c.config().Cap.Table; table != nil && table.Name() != "" {
		inside = append(inside, table.Name())
	}
	return inside
}

// BorderRuntime hands the border filter what the node resolves at startup: the
// devices inside the mesh, the SIDs of the configuration in force, the
// readiness the egress device's families wait for and the bus
func (c *Client) BorderRuntime() egress.BorderRuntime {
	return egress.BorderRuntime{Inside: c.BorderInside(), SIDs: borderSIDs(c.config()), Ready: c.SetBorderReady, Events: c.events}
}

// borderSIDs is the SID of every local segment cfg writes, whatever its
// behavior, each of which the border drops as a destination arriving from
// outside the mesh
func borderSIDs(cfg *config.Config) []netip.Addr {
	local := cfg.Segments().Local
	sids := make([]netip.Addr, 0, len(local))
	for _, segment := range local {
		sids = append(sids, segment.SID.Addr)
	}
	return sids
}

// CaptureRoutes holds the routing the reconciler needs while the mesh carries
// this machine's own traffic, or nil where the platform needs nothing. The
// command that builds the reconciler hands it to kernel.Config.
func (c *Client) CaptureRoutes() kernel.CaptureRoutes { return c.capture }

// KernelRuntime assembles what cap.table's reconciler reads from outside the
// capability: the device the mesh actually got, the addresses the transport
// has to keep reaching and the two halves of link.underlay, which only a
// running node knows, and what other capabilities write, the prefixes
// cap.route announces and cap.border's overlay.
//
// It is assembled here rather than in the command because most of it is this
// client's own and the rest is the configuration it runs. The command builds
// the reconciler from it. See kernel.Runtime for what each field decides.
func (c *Client) KernelRuntime() kernel.Runtime {
	cfg := c.config()
	return kernel.Runtime{
		Interface: c.Mesh.Name,
		Underlay:  c.Underlay,
		Announced: cfg.Routes().Announced(),
		Overlay:   cfg.Overlay(),
		Sessions:  c.LiveSessions,
		// One setting decides both halves, so they cannot be set against each
		// other: the transport binds its socket off the forwarding table, and
		// the reconciler stops hiding an announced default from every socket
		// that did not ask for the tun by name.
		BoundUnderlay: cfg.Link.Underlay.Bind,
		Capture:       c.CaptureRoutes(),
		Host:          c.host,
		Events:        c.events,
	}
}

// LiveSessions is how many of this node's sessions have recently proved their
// peer is there. The route reconciler reads it before it hands this machine's
// own traffic to the mesh, so the answer is deliberately the narrow one: a
// session that is merely installed proves nothing, and a peer that rebooted
// leaves one looking established for over a minute.
//
// A node whose underlay socket is not where its configuration says it should
// be reports none, whatever its sessions are doing. On darwin the socket is
// bound to the interface the host's own default leaves by, and a default route
// out of the tun over an unbound socket is the tunnel inside itself that the
// binding exists to prevent.
func (c *Client) LiveSessions() int {
	if !c.hub.UnderlayReady() {
		return 0
	}
	return c.sessions.liveCount()
}

// dialer is one running peer loop. It is a pointer so an entry has an identity
// a later goroutine can compare against, which a func value cannot provide.
//
// wake cuts short the reconnect delay, and is buffered so a redial arriving
// while the loop is dialing rather than waiting is not lost and does not block
// the caller. One place is enough: two asks that land before the loop comes
// round are one attempt either way.
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
