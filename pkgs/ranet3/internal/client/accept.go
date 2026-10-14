// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
)

// acceptPeers answers peers that dial us, as a full mesh needs and
// what a node behind no reachable address cannot do without. It returns when
// ctx ends or the hub's socket is gone.
// the count is the answered sessions ctx ended while the node kept running, each closed with a Delete
func (c *Client) acceptPeers(ctx context.Context) (int, error) {
	cfg := c.config()
	crypto := cfg.Crypto()
	ids, err := configIdentities(cfg)
	if err != nil {
		return 0, err
	}
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub:                c.hub,
		Local:              ids.endpoints,
		LocalPrivateKey:    c.privateKey,
		Lookup:             c.lookupPeerKey,
		ChildRekeyInterval: crypto.ChildInterval(),
		IKERekeyInterval:   crypto.IKEInterval(),
		RekeyMargin:        crypto.Margin(),
		RekeyJitter:        crypto.Jitter(),
		RekeyRetryInitial:  crypto.RetryFirst(),
		RekeyRetryMax:      crypto.RetryMax(),
		Events:             c.ikeEvent,
	})
	if err != nil {
		return 0, err
	}
	var serving sync.WaitGroup
	var closed atomic.Int64
	err = responder.Serve(ctx, func(sess *ike.Session, accepted ike.Accepted) {
		// a handshake finished after a reload turned link.listen off gets the same answer
		if ctx.Err() != nil || !c.subsystemRunning(control.SubsystemResponder) {
			// Stopped over the control socket. The handshake has already
			// finished, which is the cost of gating here rather than in the
			// responder, and the peer is told the SA is gone rather than left
			// to carry one nothing on this side will serve until its own dead
			// peer detection expires. The Delete runs under serving because it
			// waits out its own grace.
			serving.Go(func() { closeSession(sess) })
			return
		}
		serving.Go(func() {
			err := c.serveSession(ctx, sess, accepted.Local, accepted.Peer, false)
			// serveSession ends a session its ctx ended with a Delete, as it does for a dialer a reload dropped
			if errors.Is(err, context.Canceled) && c.ctx.Err() == nil {
				closed.Add(1)
			}
			// losing to a session the other end also prefers is ordinary on a full mesh
			if err != nil && !errors.Is(err, errSessionEstablished) && ctx.Err() == nil {
				log.Printf("peer %s: %v", identity.Path(accepted.Peer, accepted.Local), err)
			}
		})
	})
	serving.Wait()
	if ctx.Err() != nil {
		return int(closed.Load()), ctx.Err()
	}
	return int(closed.Load()), err
}

// lookupPeerKey resolves an identity to the key that must verify its AUTH
// the registry is the trust root, as it is for ranet's own reconcile, so any node in it may dial us, and the config's peers list says only who we dial
// an endpoint has to be one the node registers, since it is the initiator's own claim about which of its endpoints it calls from
func (c *Client) lookupPeerKey(peer identity.Identity) (ed25519.PublicKey, bool) {
	ids, err := configIdentities(c.config())
	// our own name in another node's IDi is a misconfiguration or an attempt to reuse the organization key under our identity
	if err != nil || peer.Node() == ids.node {
		return nil, false
	}
	key, err := c.index().Key(peer)
	return key, err == nil
}

// stillTrusted reports whether the registry still stands behind a peer this node already authenticated, which a reload asks of every live session
// it asks about the node alone: the serial selects which endpoint a dial uses, and renumbering one is a registry edit rather than a revocation
func (c *Client) stillTrusted(peer identity.Identity) bool {
	_, ok := c.lookupPeerKey(peer.Node())
	return ok
}
