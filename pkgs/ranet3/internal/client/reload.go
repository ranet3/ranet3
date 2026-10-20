// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/srv6"
)

// syncPeers starts a dialer for every pair dials names and stops the rest, and off the mesh stops every one
// it reports the dialers it stopped, which a reload leaves to end on their own and a sweep waits for
func (c *Client) syncPeers() (stopped []*dialer) {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	// read under the lock, since Run and every SIGHUP may call this at once and a set read before it may be stale when installed
	cfg := c.config()
	if !c.onMeshLocked() {
		for path, running := range c.dialers {
			running.cancel()
			delete(c.dialers, path)
			stopped = append(stopped, running)
		}
		return stopped
	}
	wanted := make(map[string]struct{})
	for _, d := range dials(cfg, c.index()) {
		wanted[d.path] = struct{}{}
		if _, running := c.dialers[d.path]; running {
			continue
		}
		ctx, cancel := context.WithCancel(c.ctx)
		running := &dialer{cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
		c.dialers[d.path] = running
		c.peers.Go(func() {
			defer close(running.done)
			defer cancel()
			// a dialer that gives up on its own leaves the map, or every later reload would skip it
			defer c.forgetDialer(d.path, running)
			c.runPeer(ctx, d, running.wake)
		})
	}
	for path, running := range c.dialers {
		if _, keep := wanted[path]; keep {
			continue
		}
		log.Printf("peer %s: no longer configured", path)
		running.cancel()
		delete(c.dialers, path)
		stopped = append(stopped, running)
	}
	return stopped
}

// ReloadFrom applies the configuration at path and the trust document it names, keeping every tunnel this node carries that the two still admit
// a tunnel goes where the trust document no longer admits its peer
// one also goes where cap.crypto ike prf no longer holds its IKE SA's PRF
// and a new handshake replaces that one
// it refuses a change to what peers already authenticated or what the dataplane is attached to
// so no reload applies by half
func (c *Client) ReloadFrom(path string) (err error) {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	var applied []string
	defer func() {
		attrs := []slog.Attr{slog.String("path", path)}
		if len(applied) > 0 {
			attrs = append(attrs, slog.String("applied", strings.Join(applied, ",")))
		}
		if err != nil {
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		c.events.Emit("daemon.reload", "", attrs...)
	}()
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	x, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		return err
	}
	if err := c.sameIdentityKey(cfg.Auth.Key); err != nil {
		return err
	}
	families, err := validateLocalConfig(cfg, c.privateKey, x)
	if err != nil {
		return err
	}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err != nil {
		return err
	}
	old := c.config()
	if err := reloadable(old, cfg); err != nil {
		return err
	}
	tun, err := c.planTUN(old, cfg)
	if err != nil {
		return err
	}
	// the last refusal
	// the reconciler takes a table it accepts at once
	if !sameTable(old, cfg) {
		if err := c.retable(cfg); err != nil {
			return err
		}
	}
	// a peer the trust document cannot support is skipped rather than refused
	// or one stale entry would block every later reload
	peers := effectivePeers(cfg, x)
	refuse, skip := validatePeers(peers, x, families)
	for _, problems := range [][]error{refuse, skip} {
		for _, problem := range problems {
			log.Printf("reload: %v, so nothing will dial it", problem)
		}
	}
	for _, problem := range validateAliases(cfg.Auth.Aliases, x) {
		log.Printf("reload: %v, so no handshake can use it", problem)
	}

	c.storeIndex(x)
	c.cfg.Store(cfg)
	// the trust document decides who may connect
	// so it decides who may stay
	c.sessions.revoke()
	// every exchange from here reads the cap.crypto lists just stored
	// and every live session checks the SAs it holds against them
	c.sessions.resuite()
	c.Republish()
	c.syncPeers()
	c.speaker.SetConfig(cfg.Babel())
	if old.Link.Listen != cfg.Link.Listen {
		closed := c.syncResponder()
		c.events.Emit("responder.changed", "", slog.Bool("listen", cfg.Link.Listen), slog.Int("closed", closed))
	}
	if tun.tables {
		c.Mesh.SetSegments(tun.segments)
	}
	var tunErr error
	switch {
	case tun.to != tun.from:
		tunErr = c.Mesh.SetMTU(tun.to, tun.steering)
	case tun.tables:
		// the device keeps its MTU
		// so swapping the table is the whole change
		c.Mesh.SetSteering(tun.steering)
	}
	// every live session's search takes the new link.mtu and the steering table in force
	// each session made from here on takes them too
	c.sessions.relink(cfg.Link.SessionMTU(), tun.tables, tun.steering)
	// SetMTU fails only for a device that is gone
	// and by then everything else here has applied
	if tunErr != nil {
		return tunErr
	}
	_, nodes := x.Size()
	applied = changedCapabilities(old, cfg)
	log.Printf("reloaded %s: %d peers, %d nodes in the trust document", path, len(peers), nodes)
	return nil
}

// SetReconcilerTable hands the reload path the route reconciler's SetTable, as SetReconcilerEnable hands the write path its stop and start
func (c *Client) SetReconcilerTable(set func(kernel.Table, []netip.Prefix) error) {
	c.reconcilerTable.Store(&set)
}

// retable hands the running reconciler the cap.table next carries, with the prefixes its cap.route announces
func (c *Client) retable(next *config.Config) error {
	set := c.reconcilerTable.Load()
	if set == nil {
		return errors.New("config: cap.table changed and no reconciler is running to take it, restart to apply")
	}
	return (*set)(*next.Cap.Table, next.Routes().Announced())
}

// changedCapabilities names each capability a reload from old to next applied in place
func changedCapabilities(old, next *config.Config) []string {
	var out []string
	// each table reaches the handshakes after the reload, and a session already up keeps the peer its handshake resolved
	if !maps.Equal(old.Auth.Aliases.Local, next.Auth.Aliases.Local) {
		out = append(out, "auth.aliases.local")
	}
	if !old.Auth.Aliases.Remote.Equal(next.Auth.Aliases.Remote) {
		out = append(out, "auth.aliases.remote")
	}
	if old.Babel().Effective() != next.Babel().Effective() || !old.Babel().Cost.Extra.Equal(next.Babel().Cost.Extra) {
		out = append(out, "cap.babel")
	}
	// both configurations passed Validate
	// and Validate resolves the lists
	was, _ := old.Crypto().Suites()
	is, _ := next.Crypto().Suites()
	out = append(out, was.Changed(is)...)
	if !reflect.DeepEqual(old.Routes(), next.Routes()) {
		out = append(out, "cap.route")
	}
	if !sameSegments(old, next) {
		out = append(out, "cap.segment")
	}
	if !sameTable(old, next) {
		out = append(out, "cap.table")
	}
	if old.Link.Listen != next.Link.Listen {
		out = append(out, "link.listen")
	}
	if old.Link.SessionMTU() != next.Link.SessionMTU() {
		out = append(out, "link.mtu")
	}
	return out
}

// tunPlan holds the changes a reload makes to the tun
type tunPlan struct {
	// tables is set where cap.segment changed, and segments and steering are then the tables New would build from it
	// steering is otherwise the table in force
	tables   bool
	segments *srv6.LocalTable
	steering *srv6.SteerTable
	// from and to are the device MTU before and after, link.mtu less the longest steering list
	from, to int
}

// planTUN builds what a reload from old to next changes on the tun, nothing where cap.segment and link.mtu stay
// a move of the device's MTU is refused on a platform that sets the MTU only at the open
func (c *Client) planTUN(old, next *config.Config) (tunPlan, error) {
	plan := tunPlan{tables: !sameSegments(old, next)}
	if !plan.tables && old.Link.SessionMTU() == next.Link.SessionMTU() {
		return plan, nil
	}
	plan.steering = c.Mesh.Steering()
	if plan.tables {
		segments, steering, err := next.Segments().Tables()
		if err != nil {
			return tunPlan{}, err
		}
		plan.segments, plan.steering = segments, steering
	}
	var err error
	if plan.from, err = steeredMTU(old.Link.SessionMTU(), c.Mesh.Steering()); err != nil {
		return tunPlan{}, err
	}
	if plan.to, err = steeredMTU(next.Link.SessionMTU(), plan.steering); err != nil {
		return tunPlan{}, err
	}
	if plan.to != plan.from {
		if err := c.Mesh.CheckMTU(); err != nil {
			return tunPlan{}, fmt.Errorf("config: tun mtu %d to %d: %w", plan.from, plan.to, err)
		}
	}
	return plan, nil
}

// sameSegments compares cap.segment as the tables are built from it
func sameSegments(old, next *config.Config) bool {
	return reflect.DeepEqual(old.Segments().Normalized(), next.Segments().Normalized())
}

// responderRun is one acceptPeers a responder start began, with what it reports once done is closed
type responderRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	closed int
}

// syncResponder starts the responder where link.listen is on and none runs, and stops the running one where it is off
// it reads the configuration under dialersMu, as syncPeers does, so a start in Run and a stop in a reload cannot cross
// and off the mesh it stops the responder and starts none, so c.peers.Go never races the wait in Run
// it reports how many answered sessions the stop closed
func (c *Client) syncResponder() int {
	c.dialersMu.Lock()
	run := c.responder
	listen := c.config().Link.Listen && c.onMeshLocked()
	if listen && run == nil {
		ctx, cancel := context.WithCancel(c.ctx)
		started := &responderRun{cancel: cancel, done: make(chan struct{})}
		c.responder = started
		c.peers.Go(func() {
			defer close(started.done)
			defer cancel()
			closed, err := c.acceptPeers(ctx)
			started.closed = closed
			if err != nil && ctx.Err() == nil {
				log.Printf("responder: %v", err)
			}
		})
	}
	if listen || run == nil {
		c.dialersMu.Unlock()
		return 0
	}
	c.responder = nil
	c.dialersMu.Unlock()
	run.cancel()
	<-run.done
	// only once the responder is gone, since a Serve it had not yet reached would Listen again
	// a responder started later answers nothing that arrived while this one was off
	c.hub.StopListening()
	// a peer this node also dials comes back now rather than after the reconnect delay
	c.dialersMu.Lock()
	paths := slices.Collect(maps.Keys(c.dialers))
	c.dialersMu.Unlock()
	c.wakeDialers(paths)
	return run.closed
}

// sameIdentityKey refuses a reload that would change the key this node signs
// with. LoadPrivateKey runs once, in New, and the listener captured the
// result when Run built it, so a new key here would reach the dialers and
// leave every accepted session signing with the old one. The file is read
// rather than the path compared, because a rotation is staged by writing the
// new key where the old one was.
func (c *Client) sameIdentityKey(path string) error {
	key, err := registry.LoadPrivateKey(path)
	if err != nil {
		return err
	}
	if !key.Public().(ed25519.PublicKey).Equal(c.privateKey.Public()) {
		return fmt.Errorf("config: auth.key changed, restart to apply")
	}
	return nil
}

// reloadable reports why a change cannot be applied in place, or nil
// a block this node reads once at startup is compared whole
// so a capability that grows a field grows no check here
// cap.crypto is the one block split
// its lists reload
// the timers and the window a session captures at its start do not
func reloadable(old, next *config.Config) error {
	switch moved := tableMoved(old.Cap.Table, next.Cap.Table); {
	case old.Node != next.Node:
		return fmt.Errorf("config: node changed, restart to apply")
	case old.Link.Underlay != next.Link.Underlay:
		// both spellings apply to the listener when it opens
		// and a socket connected to one peer takes them from the listener
		// so a change here would reach nothing
		// the interface a bound socket sits on follows the host's own routing
		// and this file never wrote that routing
		return fmt.Errorf("config: link.underlay changed, restart to apply")
	case old.Link.Port != next.Link.Port:
		return fmt.Errorf("config: link.port changed, restart to apply")
	case old.Link.TUN != next.Link.TUN:
		return fmt.Errorf("config: link.tun changed, restart to apply")
	case !slices.Equal(sortedEndpoints(old.Link.Endpoints), sortedEndpoints(next.Link.Endpoints)):
		// the listener answers to one identity per local endpoint and builds that set once
		// each endpoint runs its own dialers
		// every reader of the list builds a set from it
		// so two lines swapped are no change
		return fmt.Errorf("config: link.endpoints changed, restart to apply")
	case old.Transits() != next.Transits():
		return fmt.Errorf("config: cap.transit enable changed, restart to apply")
	case moved != "":
		return fmt.Errorf("config: cap.table %s, restart to apply", moved)
	case !sameCrypto(old, next):
		// accepted sessions take the timers and the window from the listener built at startup
		// so a change dialed sessions alone took would run two policies at once
		return fmt.Errorf("config: cap.crypto rekey or replay changed, restart to apply")
	case !sameEgress(old, next):
		// the translator is built once in main and owns the tables it made under the families it translated at startup
		// a new block applied here would leave the host holding rules from a configuration nothing runs any more
		return fmt.Errorf("config: cap.egress changed, restart to apply")
	case len(old.Segments().Egress()) == 0 && len(next.Segments().Egress()) > 0:
		// the egress device, the translator's rule keyed on it and its readiness are made at startup
		return fmt.Errorf("config: cap.segment adds the first egress segment, restart to apply")
	case len(old.Segments().Egress()) > 0 && len(next.Segments().Egress()) == 0:
		return fmt.Errorf("config: cap.segment removes the last egress segment, restart to apply")
	}
	return sameReturnSources(old, next)
}

// sameReturnSources refuses a reload whose mesh addresses resolve another return source than the running translator's, or fail to resolve one
// the translator resolved an auto source of each family it advertises among the mesh addresses once, at startup
// the capability itself is unchanged, since sameEgress refuses a reload that changes it
func sameReturnSources(old, next *config.Config) error {
	exit := next.Egress()
	if exit == nil {
		return nil
	}
	running, err := exit.ReturnSources(MeshAddresses(old))
	if err != nil {
		return err
	}
	sources, err := exit.ReturnSources(MeshAddresses(next))
	if err != nil {
		return err
	}
	if !slices.Equal(running, sources) {
		return errors.New("config: cap.route or cap.table moved the mesh address cap.egress return translates to, restart to apply")
	}
	return nil
}

// sameEgress compares the capability by what it was given rather than by how
// the file was written, as sameTable does. The capability itself says what
// that means, so a field that grows a default does not also have to be
// remembered here.
func sameEgress(old, next *config.Config) bool {
	normalize := func(e *egress.Egress) *egress.Egress {
		if e == nil {
			return nil
		}
		normalized := e.Normalized()
		return &normalized
	}
	return reflect.DeepEqual(normalize(old.Egress()), normalize(next.Egress()))
}

// sameCrypto compares the timers and the window a session captures when it is created
// as a session reads them
// so an omitted interval and one spelled out as its own default are no change
// the lists reload in place
// so it leaves them out
func sameCrypto(old, next *config.Config) bool {
	a, b := old.Crypto(), next.Crypto()
	return a.ChildInterval() == b.ChildInterval() &&
		a.IKEInterval() == b.IKEInterval() &&
		a.Margin() == b.Margin() &&
		a.Jitter() == b.Jitter() &&
		a.RetryFirst() == b.RetryFirst() &&
		a.RetryMax() == b.RetryMax() &&
		a.ReplayWindow() == b.ReplayWindow()
}

// tableMoved says what of cap.table only a restart applies, or is empty
// main builds the reconciler for the block written at startup
// and kernel.Table.Unreloadable names what that reconciler keeps for its life
func tableMoved(old, next *kernel.Table) string {
	switch {
	case old == nil && next != nil:
		return "added"
	case old != nil && next == nil:
		return "removed"
	case old == nil:
		return ""
	}
	if setting := old.Unreloadable(*next); setting != "" {
		return setting + " changed"
	}
	return ""
}

// sameTable reports that next gives the reconciler the capability it runs
// the two are compared as New resolves one, so a field spelled out as its own default is no change
// the addresses are compared as assign_announced expands cap.route into them
func sameTable(old, next *config.Config) bool {
	if (old.Cap.Table == nil) != (next.Cap.Table == nil) {
		return false
	}
	if old.Cap.Table == nil {
		return true
	}
	if !reflect.DeepEqual(old.Cap.Table.Normalized(), next.Cap.Table.Normalized()) {
		return false
	}
	return slices.Equal(
		sortedPrefixes(old.Cap.Table.Assigned(old.Routes().Announced())),
		sortedPrefixes(next.Cap.Table.Assigned(next.Routes().Announced())))
}

// sortedEndpoints puts the local endpoints in one order, for the same reason
// sortedPrefixes does. The serial alone decides it, since two endpoints
// sharing one are refused where the file is read.
func sortedEndpoints(endpoints []config.Endpoint) []config.Endpoint {
	out := slices.Clone(endpoints)
	slices.SortFunc(out, func(a, b config.Endpoint) int { return cmp.Compare(a.Serial, b.Serial) })
	return out
}

// sortedPrefixes puts an address set in one order, so two of them compare as
// sets rather than as the lists two files happened to write.
func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := slices.Clone(prefixes)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// announced is every prefix this node is putting into the mesh right now: the
// ones cap.route asks for unconditionally, plus the ones cap.egress is
// currently willing to stand behind, plus the /128 of each egress SID while
// the translator's last word says the SIDs are served. The second and third
// sets are read from the translator on every call rather than from the file,
// because an exit withholds a prefix whose rule is not installed and that
// answer changes under a running node.
func (c *Client) announced(cfg *config.Config) []babel.OriginatedRoute {
	serves := c.egressServes.Load()
	routes := cfg.Routes().Originated()
	for _, prefix := range c.egressAdvertised() {
		routes = append(routes, babel.OriginatedRoute{Destination: prefix})
	}
	if !serves {
		return routes
	}
	for _, segment := range cfg.Segments().Egress() {
		routes = append(routes, babel.OriginatedRoute{Destination: netip.PrefixFrom(segment.SID.Addr, segment.SID.BitLen())})
	}
	return routes
}

// SetEgressAnnounce hands the runtime cap.egress's own view of what it may
// advertise. See announced.
func (c *Client) SetEgressAnnounce(read func() []netip.Prefix) {
	c.egressAnnounce.Store(&read)
}

func (c *Client) egressAdvertised() []netip.Prefix {
	if read := c.egressAnnounce.Load(); read != nil {
		return (*read)()
	}
	return nil
}

// Republish rebuilds the announcement set and hands it to the speaker.
// cap.egress calls it whenever the prefixes it may advertise change, which is
// how an exit whose rule stopped being installed retracts rather than going on
// attracting traffic it would have to drop.
func (c *Client) Republish() {
	c.republishMu.Lock()
	defer c.republishMu.Unlock()
	c.speaker.SetOriginated(c.announced(c.config()))
}

// forgetDialer drops a dialer that ended by itself, and only if the map still
// holds this one, so a dialer stopped and immediately restarted by a reload
// cannot delete its own replacement.
func (c *Client) forgetDialer(path string, running *dialer) {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	if c.dialers[path] == running {
		delete(c.dialers, path)
	}
}
