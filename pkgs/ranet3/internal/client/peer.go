// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// reconnectDelay is how long a dialer waits between attempts. A test that has
// to see the loop come round again overrides it, and zero means the default.
func (c *Client) reconnectDelay() time.Duration {
	if c.dialRetry > 0 {
		return c.dialRetry
	}
	return defaultReconnectDelay
}

// runPeer dials d again whenever its session ends, at once when wake fires and otherwise after the reconnect delay
func (c *Client) runPeer(ctx context.Context, d dial, wake <-chan struct{}) {
	x := c.index()
	if _, err := x.Key(d.peer.Node()); err != nil {
		log.Printf("peer %s: node not found", d.path)
		return
	}
	// a dual-stack node runs a dialer per local endpoint
	// so a peer without an endpoint of this one's family is ordinary
	targets := x.Targets(d.peer)
	if d.peer != d.peer.Node() {
		if len(targets) == 0 {
			log.Printf("peer %s: endpoint %s not found", d.path, d.peer)
			return
		}
		if targets[0].AddressFamily != d.local.Family {
			log.Printf("peer %s: endpoint %s is %s, not %s", d.path, d.peer, targets[0].AddressFamily, d.local.Family)
			return
		}
		if !targets[0].Dialable() {
			log.Printf("peer %s: endpoint %s carries no address", d.path, d.peer)
			return
		}
	} else if !slices.ContainsFunc(targets, func(target registry.Target) bool {
		return target.AddressFamily == d.local.Family && target.Dialable()
	}) {
		slog.Debug("peer has no endpoint carrying an address in this address family", "peer", d.path, "family", d.local.Family)
		return
	}
	var failure repeatedFailure
	for {
		if ctx.Err() != nil {
			return
		}
		// a reload may remove the node while this dialer runs
		if _, err := c.index().Key(d.peer.Node()); err != nil {
			log.Printf("peer %s: no longer in the registry, giving up", d.path)
			return
		}
		err := c.connectPeer(ctx, d)
		if ctx.Err() != nil || c.stopping() {
			return
		}
		switch {
		case err == nil:
		case errors.Is(err, errSessionEstablished):
			// not a failure
			// this dialer takes over once the peer's session ends
		case replacedByHandshake(err):
			// the session deleted its IKE SA for a new handshake under the lists in force
			// and the new handshake goes out at once
			log.Printf("peer %s: %v, dialing again now", d.path, err)
			continue
		case failure.alreadySaid(err):
			slog.Debug("peer dial failed again", "peer", d.path, "err", err)
		default:
			log.Printf("peer %s: %v, reconnecting in %s", d.path, err, c.reconnectDelay())
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			c.events.Emit("dial.woken", d.path)
		case <-time.After(c.reconnectDelay()):
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

// resolveEndpoint returns the address it resolved with the endpoint, since resolving a name again costs a resolver round trip
func resolveEndpoint(ctx context.Context, x *registry.Index, peer identity.Identity, family string) (registry.Target, net.IP, error) {
	targets := x.Targets(peer)
	if peer != peer.Node() {
		if len(targets) == 0 {
			return registry.Target{}, nil, fmt.Errorf("no endpoint %s", peer)
		}
		if targets[0].AddressFamily != family {
			return registry.Target{}, nil, fmt.Errorf("endpoint %s is %s, want %s", peer, targets[0].AddressFamily, family)
		}
		address, err := targets[0].ResolveRemote(ctx)
		if err != nil {
			return registry.Target{}, nil, err
		}
		return targets[0], address, nil
	}
	for _, target := range targets {
		if target.AddressFamily != family || !target.Dialable() {
			continue
		}
		if address, err := target.ResolveRemote(ctx); err == nil {
			return target, address, nil
		}
	}
	return registry.Target{}, nil, fmt.Errorf("no endpoint currently resolves to an address")
}

// connectPeer dials d once and serves the session until it ends
func (c *Client) connectPeer(ctx context.Context, d dial) (err error) {
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
	ep, remoteIP, err := resolveEndpoint(ctx, x, d.peer, d.local.Family)
	if err != nil {
		return err
	}
	remotePub, err := x.Key(ep.ID)
	if err != nil {
		return err
	}
	sessionName := identity.Path(ep.ID, d.localID)
	path = sessionName
	if c.sessions.holds(sessionName) {
		// a second SA over this pair of endpoints would only be resolved away
		return errSessionEstablished
	}
	log.Printf("peer %s: dialing %s:%d", sessionName, remoteIP, ep.Port)
	c.events.Emit("dial.attempt", sessionName, slog.String("remote", net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(ep.Port)))))

	ikeCfg := ike.PeerConfig{
		Local:              d.localID,
		LocalPrivateKey:    c.privateKey,
		Remote:             ep.ID,
		RemotePublicKey:    remotePub,
		RemoteAddr:         remoteIP,
		RemotePort:         int(ep.Port),
		Aliases:            cfg.Auth.Aliases,
		Hub:                c.hub,
		ChildRekeyInterval: crypto.ChildInterval(),
		IKERekeyInterval:   crypto.IKEInterval(),
		RekeyMargin:        crypto.Margin(),
		RekeyJitter:        crypto.Jitter(),
		RekeyRetryInitial:  crypto.RetryFirst(),
		RekeyRetryMax:      crypto.RetryMax(),
		Suites:             c.suites,
		Events:             c.ikeEvent,
	}
	sess, err := ike.InitiateContext(ctx, ikeCfg)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	established = true
	return c.serveSession(ctx, sess, d.localID, ep.ID, remotePub, true)
}

// errSessionEstablished means this peer is already reachable over a session
// the other end opened, so there is nothing to dial and nothing wrong.
var errSessionEstablished = errors.New("a session for this endpoint pair is already established")
