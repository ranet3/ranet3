// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
)

// reconnectDelay is how long a dialer waits between attempts. A test that has
// to see the loop come round again overrides it, and zero means the default.
func (c *Client) reconnectDelay() time.Duration {
	if c.dialRetry > 0 {
		return c.dialRetry
	}
	return defaultReconnectDelay
}

// unroutedDelay is the wait after a dial that ended because the host had no route for it, and zero for any other end
func (c *Client) unroutedDelay(err error, last time.Duration) time.Duration {
	if !errors.Is(err, syscall.ENETUNREACH) {
		return 0
	}
	if last == 0 {
		return c.reconnectDelay()
	}
	return min(2*last, max(unroutedDelayCap, c.reconnectDelay()))
}

// errNoEndpointInFamily is refuseDial's answer for a node with no dialable endpoint in d's family
// a dual-stack node runs a dialer per local endpoint, so a peer without an endpoint of this one's family is ordinary
var errNoEndpointInFamily = errors.New("no endpoint carrying an address in this address family")

// refuseDial is why runPeer sends d no IKE_SA_INIT under the trust document x, and nil where it dials
func refuseDial(x *registry.Index, d dial) error {
	if _, err := x.Key(d.peer.Node()); err != nil {
		return errors.New("node not found")
	}
	targets := x.Targets(d.peer)
	if d.peer == d.peer.Node() {
		if !slices.ContainsFunc(targets, func(target registry.Target) bool {
			return target.AddressFamily == d.local.Family && target.Dialable()
		}) {
			return errNoEndpointInFamily
		}
		return nil
	}
	switch {
	case len(targets) == 0:
		return fmt.Errorf("endpoint %s not found", d.peer)
	case targets[0].AddressFamily != d.local.Family:
		return fmt.Errorf("endpoint %s is %s, not %s", d.peer, targets[0].AddressFamily, d.local.Family)
	case !targets[0].Dialable():
		return fmt.Errorf("endpoint %s carries no address", d.peer)
	}
	return nil
}

// runPeer dials d again whenever its session ends, at once when wake fires and otherwise after the reconnect delay, or after unroutedDelay where the host had no route for the dial
// a dial after one that failed is said at debug, since only a change of outcome tells an operator anything
func (c *Client) runPeer(ctx context.Context, d dial, wake <-chan struct{}) {
	switch err := refuseDial(c.index(), d); {
	case errors.Is(err, errNoEndpointInFamily):
		slog.Debug("peer has no endpoint carrying an address in this address family", "peer", d.path, "family", d.local.Family)
		return
	case err != nil:
		slog.Warn(fmt.Sprintf("peer %s: %v", d.path, err))
		return
	}
	defer c.forgetDialed(ctx)
	var failure repeatedFailure
	var unrouted time.Duration
	for {
		if ctx.Err() != nil {
			return
		}
		// a reload may remove the node while this dialer runs
		if _, err := c.index().Key(d.peer.Node()); err != nil {
			slog.Info(fmt.Sprintf("peer %s: no longer in the registry, giving up", d.path))
			return
		}
		// a dial is said at info until a failure is said, and again once a session has held the path
		level := slog.LevelDebug
		if failure.said.IsZero() {
			level = slog.LevelInfo
		}
		err := c.connectPeer(ctx, d, level)
		if ctx.Err() != nil || c.stopping() {
			return
		}
		end, _ := errors.AsType[*servedEnd](err)
		held := end != nil && end.held
		// a session another end opened holds the path, and this dialer takes over once it ends
		standing := errors.Is(err, errSessionEstablished)
		if held || standing {
			failure = repeatedFailure{}
		}
		unrouted = c.unroutedDelay(err, unrouted)
		wait := cmp.Or(unrouted, c.reconnectDelay())
		switch {
		case errors.Is(err, ike.ErrPRFUnlisted):
			// the session deleted its IKE SA for a new handshake under the lists in force
			// and the new handshake goes out at once
			slog.Info(fmt.Sprintf("peer %s: %v, dialing again now", d.path, err))
			continue
		case standing:
		case !held && failure.alreadySaid(err):
			slog.Debug("peer dial failed again", "peer", d.path, "err", err)
		default:
			slog.Log(ctx, endLevel(err), fmt.Sprintf("peer %s: %v, reconnecting in %s", d.path, err, wait))
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			c.events.Emit("dial.woken", d.path)
		case <-time.After(wait):
		}
	}
}

// repeatedFailure spaces one dialer's repeats. A peer it cannot reach fails on
// every attempt, and the ones it cannot refuse outright are the names, since
// only a resolver can answer for one: 250 lines in 93 seconds from 25 of them,
// measured. A changed reason is said as soon as the floor allows, and the
// floor is there because a reason is not a category, a resolver failure
// carrying the ephemeral source port of its own query.
type repeatedFailure struct {
	reason string
	said   time.Time
}

// alreadySaid reports whether an equivalent failure has been said recently
// enough to keep this one at debug, and records the one it says. What it
// records is the reason last said out loud, not the reason last seen, so a
// reason that changed under the floor is said when the floor passes rather
// than waiting out the interval against itself.
func (f *repeatedFailure) alreadySaid(err error) bool {
	reason, since := err.Error(), time.Since(f.said)
	if since >= dialFailureInterval || (reason != f.reason && since >= dialFailureFloor) {
		f.reason, f.said = reason, time.Now()
		return false
	}
	return true
}

// resolveEndpoint returns the address it resolved with the endpoint, since
// resolving a name again costs a resolver round trip, and notes in failed
// whether each name it looked up failed
func resolveEndpoint(ctx context.Context, x *registry.Index, overlay []schema.Prefix, peer identity.Identity, family string, failed *names) (registry.Target, net.IP, error) {
	resolve := func(target registry.Target) (net.IP, error) {
		address, err := target.ResolveRemote(ctx, overlay)
		if target.Address != nil && net.ParseIP(*target.Address) == nil && ctx.Err() == nil {
			failed.note(*target.Address, err != nil)
		}
		return address, err
	}
	targets := x.Targets(peer)
	if peer != peer.Node() {
		if len(targets) == 0 {
			return registry.Target{}, nil, fmt.Errorf("no endpoint %s", peer)
		}
		if targets[0].AddressFamily != family {
			return registry.Target{}, nil, fmt.Errorf("endpoint %s is %s, want %s", peer, targets[0].AddressFamily, family)
		}
		address, err := resolve(targets[0])
		if err != nil {
			return registry.Target{}, nil, err
		}
		return targets[0], address, nil
	}
	for _, target := range targets {
		if target.AddressFamily != family || !target.Dialable() {
			continue
		}
		if address, err := resolve(target); err == nil {
			return target, address, nil
		}
	}
	return registry.Target{}, nil, fmt.Errorf("no endpoint currently resolves to an address")
}

// names is a set of endpoint names, safe for concurrent use
type names struct {
	mu  sync.Mutex
	set map[string]bool
}

// note puts name in the set where in is true and takes it out where it is false
func (n *names) note(name string, in bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !in {
		delete(n.set, name)
		return
	}
	if n.set == nil {
		n.set = make(map[string]bool)
	}
	n.set[name] = true
}

// list is the set's names in order
func (n *names) list() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Sorted(maps.Keys(n.set))
}

// dialedAddresses is each running dialer's last resolved address, safe for concurrent use
// it is keyed by the context the dialer runs under, which is its own, so a dialer that ends drops its record and never that of the dialer replacing it
type dialedAddresses struct {
	mu sync.Mutex
	by map[context.Context]netip.Addr
}

// set records address as the dialer's last, and reports whether its record changed
func (d *dialedAddresses) set(dialer context.Context, address netip.Addr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.by == nil {
		d.by = make(map[context.Context]netip.Addr)
	}
	last, ok := d.by[dialer]
	d.by[dialer] = address
	return !ok || last != address
}

// drop forgets the dialer's record, and reports whether it held one
func (d *dialedAddresses) drop(dialer context.Context) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.by[dialer]
	delete(d.by, dialer)
	return ok
}

func (d *dialedAddresses) list() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Collect(maps.Values(d.by))
}

// noteDialed records address as the last the dialer running under dialer resolved, and wakes the reconciler where that changed its record
func (c *Client) noteDialed(dialer context.Context, address net.IP) {
	resolved, ok := netip.AddrFromSlice(address)
	if !ok {
		return
	}
	if c.dialed.set(dialer, resolved.Unmap()) {
		c.endpointsChanged()
	}
}

// forgetDialed drops the record of the dialer running under dialer, and wakes the reconciler where there was one
func (c *Client) forgetDialed(dialer context.Context) {
	if c.dialed.drop(dialer) {
		c.endpointsChanged()
	}
}

// endpointsChanged wakes the reconciler for a pass over the addresses the underlay sends to, which may have changed
func (c *Client) endpointsChanged() {
	if wake := c.reconcilerNow().Endpoints; wake != nil {
		wake()
	}
}

// connectPeer dials d once, saying so at level, and serves the session until it ends
func (c *Client) connectPeer(ctx context.Context, d dial, level slog.Level) (err error) {
	// events go under the dialer's path until the endpoint resolves and under the session's after
	path := d.path
	established := false
	defer func() {
		// a dial that ended short of a session
		// neither another session holding the path nor a node going down is one
		if !established && err != nil && !errors.Is(err, errSessionEstablished) && ctx.Err() == nil {
			c.events.Emit("dial.failed", path, slog.String("err", err.Error()))
		}
	}()
	cfg, x := c.config(), c.index()
	crypto := cfg.Crypto()
	ep, remoteIP, err := resolveEndpoint(ctx, x, cfg.Overlay, d.peer, d.local.Family, &c.unresolved)
	if err != nil {
		return err
	}
	c.noteDialed(ctx, remoteIP)
	remotePub, err := x.Key(ep.ID)
	if err != nil {
		return err
	}
	sessionName := identity.Path(ep.ID, d.localID)
	path = sessionName
	if c.sessions.holds(sessionName, preferInitiator(d.localID, ep.ID)) {
		// a second SA over this pair of endpoints would only be resolved away
		return errSessionEstablished
	}
	remote := net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(ep.Port)))
	slog.Log(ctx, level, fmt.Sprintf("peer %s: dialing %s", sessionName, remote))
	c.events.Emit("dial.attempt", sessionName, slog.String("remote", remote))

	ikeCfg := ike.PeerConfig{
		Local:           d.localID,
		LocalPrivateKey: c.privateKey,
		Remote:          ep.ID,
		RemotePublicKey: remotePub,
		RemoteAddr:      remoteIP,
		RemotePort:      int(ep.Port),
		Aliases:         cfg.Auth.Aliases,
		Hub:             c.hub,
		RekeyTiming:     crypto.Timing(),
		Suites:          c.suites,
		Events:          c.ikeEvent,
		InitialContact:  c.sessions.contact,
	}
	sess, err := ike.InitiateContext(ctx, ikeCfg)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	established = true
	return c.serveSession(ctx, sess, sess.Child(), d.localID, ep.ID, remotePub, true)
}

// endLevel is the level a session's or a dial's end err is said at, warn for a session that ended before it held its path and info for any other
func endLevel(err error) slog.Level {
	if end, _ := errors.AsType[*servedEnd](err); end != nil && !end.held {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// errSessionEstablished means this peer is already reachable over a session
// the other end opened, so there is nothing to dial and nothing wrong.
var errSessionEstablished = errors.New("a session for this endpoint pair is already established")
