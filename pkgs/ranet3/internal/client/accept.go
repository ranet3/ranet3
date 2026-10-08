// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// acceptPeers answers peers that dial us, as a full mesh needs and
// what a node behind no reachable address cannot do without. It returns when
// ctx ends or the hub's socket is gone.
// the count is the answered sessions ctx ended while the node kept running, each closed with a Delete
func (c *Client) acceptPeers(ctx context.Context) (int, error) {
	cfg := c.config()
	crypto := cfg.Crypto()
	local := make([]ike.Identity, 0, len(cfg.Link.Endpoints))
	for _, endpoint := range cfg.Link.Endpoints {
		local = append(local, ike.Identity{
			Organization: cfg.Node.Org,
			CommonName:   cfg.Node.Name,
			SerialNumber: endpoint.Serial,
		})
	}
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub:                c.hub,
		Local:              local,
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
			peer := accepted.Peer
			name := fmt.Sprintf("%s/%s@%s", peer.Organization, peer.CommonName, accepted.Local.SerialNumber)
			// The same shape a dialed session uses, so one path through the
			// mesh has one name whichever end opened it and the replace rule
			// in sessionSet applies across both directions.
			sessionName := sessionPath(peer, accepted.Local)
			// We answered, so the peer is this SA's initiator and we are its
			// responder. Losing to a session the other end also prefers is
			// ordinary on a full mesh and is not worth a line in the log.
			err := c.serveSession(ctx, sess, name, sessionName, peer, accepted.Local, peer)
			// serveSession ends a session its ctx ended with a Delete, as it does for a dialer a reload dropped
			if errors.Is(err, context.Canceled) && c.ctx.Err() == nil {
				closed.Add(1)
			}
			if err != nil && !errors.Is(err, errSessionEstablished) && ctx.Err() == nil {
				log.Printf("peer %s: %v", name, err)
			}
		})
	})
	serving.Wait()
	if ctx.Err() != nil {
		return int(closed.Load()), ctx.Err()
	}
	return int(closed.Load()), err
}

// lookupPeerKey resolves an authenticated identity to the key that must verify
// its AUTH. The registry is the trust root, exactly as it is for ranet's own
// reconcile, so any node in it may dial us; the config's peers list says who
// we dial, not who we answer.
//
// The serial number has to name one of that node's registered endpoints. It
// is the initiator's own claim about which of its endpoints it is calling
// from, so a value the registry does not know means the registry and the peer
// disagree about what exists.
func (c *Client) lookupPeerKey(peer ike.Identity) (ed25519.PublicKey, bool) {
	key, node, ok := c.peerKey(peer)
	if !ok {
		return nil, false
	}
	if _, named := node.FindEndpoint(peer.SerialNumber); !named {
		return nil, false
	}
	return key, true
}

// stillTrusted reports whether the registry still stands behind a peer this
// node has already authenticated, which a reload asks of every live session.
// The endpoint serial is left out: it selects which endpoint a dial uses, and
// renumbering one is a registry edit rather than a revocation, so asking for it
// here closes a session whose peer has done nothing to lose it.
func (c *Client) stillTrusted(peer ike.Identity) bool {
	_, _, ok := c.peerKey(peer)
	return ok
}

// peerKey is the organization key that must verify a peer's AUTH, with the
// node the registry holds for it, and whether the registry stands behind the
// identity at all.
func (c *Client) peerKey(peer ike.Identity) (ed25519.PublicKey, registry.Node, bool) {
	cfg := c.config()
	organization, node, ok := c.registry().FindNode(peer.Organization, peer.CommonName)
	if !ok {
		return nil, registry.Node{}, false
	}
	if peer.Organization == cfg.Node.Org && peer.CommonName == cfg.Node.Name {
		// Our own name in another node's IDi is either a misconfiguration or
		// an attempt to reuse the organization key under our identity.
		return nil, registry.Node{}, false
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return nil, registry.Node{}, false
	}
	return publicKey, node, true
}
