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
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// acceptPeers answers peers that dial us until ctx ends or the hub's socket is gone
// the count is the answered sessions ctx ended while the node kept running, each closed with a Delete
func (c *Client) acceptPeers(ctx context.Context) (int, error) {
	cfg := c.config()
	crypto := cfg.Crypto()
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub:                c.hub,
		Local:              cfg.LocalFamilies(),
		LocalPrivateKey:    c.privateKey,
		Trust:              liveTrust{c},
		Aliases:            func() ike.Aliases { return c.config().Auth.Aliases },
		ChildRekeyInterval: crypto.ChildInterval(),
		IKERekeyInterval:   crypto.IKEInterval(),
		RekeyMargin:        crypto.Margin(),
		RekeyJitter:        crypto.Jitter(),
		RekeyRetryInitial:  crypto.RetryFirst(),
		RekeyRetryMax:      crypto.RetryMax(),
		Suites:             c.suites,
		Events:             c.ikeEvent,
	})
	if err != nil {
		return 0, err
	}
	var serving sync.WaitGroup
	var closed atomic.Int64
	err = responder.Serve(ctx, func(sess *ike.Session, accepted ike.Accepted) {
		// a handshake that finished after link.listen went off or the responder was stopped is told the SA is gone
		if ctx.Err() != nil || !c.subsystemRunning(control.SubsystemResponder) {
			// under serving
			// the Delete waits out its own grace
			serving.Go(func() { closeSession(sess) })
			return
		}
		serving.Go(func() {
			err := c.serveSession(ctx, sess, accepted.Local, accepted.Peer, accepted.Key, false)
			// serveSession ends a session its ctx ended with a Delete
			// it does the same for a dialer a reload dropped
			if errors.Is(err, context.Canceled) && c.ctx.Err() == nil {
				closed.Add(1)
			}
			// a dialer of this node's that stood down behind the session dials again at once under the lists in force
			if replacedByHandshake(err) {
				c.wakeDialers(c.matchingDialers(identity.Path(accepted.Peer, accepted.Local), false))
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

// liveTrust is the trust document in force, read on each question so the next handshake after a reload answers to the document it stored
// any node in it may dial us, as in ranet's own reconcile, and the config's peers list says only who we dial
type liveTrust struct{ c *Client }

func (t liveTrust) Key(id identity.Identity) (ed25519.PublicKey, ike.Family, error) {
	return indexTrust{t.c.index()}.Key(id)
}

// indexTrust is one version of the trust document
type indexTrust struct{ x *registry.Index }

func (t indexTrust) Key(id identity.Identity) (ed25519.PublicKey, ike.Family, error) {
	key, err := t.x.Key(id)
	if err != nil || id == id.Node() {
		return key, 0, err
	}
	return key, config.Family(t.x.Targets(id)[0].AddressFamily), nil
}
