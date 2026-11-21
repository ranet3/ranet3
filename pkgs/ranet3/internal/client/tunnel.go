// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// Each socket batch captures one immutable SA set. Changes publish a new set
// without holding a lock through crypto. In-flight batches retain the old keys, while
// new batches see only the SAs that are still installed, and send on outbound alone.
type tunnelSAs struct {
	outbound    *esp.OutboundSA
	outboundSPI uint32
	// replacement is the outbound SA of the Child SA a peer's rekey made, named by its inbound SPI, which takes outbound's place when outbound traffic moves to it
	replacement    *esp.OutboundSA
	replacementSPI uint32
	inbound        map[uint32]*esp.InboundSA
}

type tunnel struct {
	mu           sync.Mutex // writers only
	sas          atomic.Pointer[tunnelSAs]
	replayWindow uint32
	rekeying     atomic.Bool
	rekey        func()
	// spent tells the session the outbound SA named by its inbound SPI has run out of sequence numbers
	spent func(uint32)
	// failed tells the session a reservation was refused for a reason that ends it
	failed func(error)
	// askedAt is nanoseconds since started, read through time.Since so it
	// comes off the monotonic clock, and primed one interval in the past so
	// the first ask goes straight through. See requestRekey.
	askedAt atomic.Int64
	started time.Time
	// replacing marks the outbound SA gone as asked for, and install clears it
	replacing atomic.Bool
	// askJitter draws the first ask's delay past the sequence mark below its bound, and nil draws it at random
	askJitter func(bound time.Duration) time.Duration
	// launchAsk runs the body of an ask requestRekey started, and nil runs it on a goroutine of its own
	launchAsk func(ask func())
}

// rekeyAskInterval is the floor between two attempts to replace the Child SA.
// The one-at-a-time guard alone does not bound the rate: a rekey asked for
// while one already runs, or while a failed one waits out its retry delay,
// comes back at once without an exchange, and an outbound SA past
// ProactiveRekeySequence asks per batch, which on a routed tun is per packet.
// The ike session holds every exchange after a failed one to that delay, so
// the floor bounds how often a batch asks and not when a failed rekey is
// retried.
const rekeyAskInterval = 250 * time.Millisecond

// errNoChildSA means the peer deleted the Child SA and kept the IKE SA, which
// RFC 7296 section 1.4.1 allows, or the Child SA reached its lifetime. Sending
// resumes once a replacement is negotiated. The ike session itself closes the
// IKE SA when none can be, so a sender that meets this error closes nothing.
var errNoChildSA = errors.New("peer has no active Child SA")

// fatalReserveError reports whether a refusal from reserve is a reason to end
// the session, which deletes the IKE SA, ends Run, drops the babel peer and
// withdraws every route through it.
//
// Two refusals are not. A peer may delete the Child SA and keep the IKE SA
// (RFC 7296 section 1.4.1), and a non-ESN SA may run out of sequence numbers,
// which RFC 4303 section 3.3.3 makes a refusal to send rather than a failure
// of anything else. Both leave the IKE SA to the session with a replacement
// already asked for, and section 1.3.1 is explicit about the answer: "A failed
// attempt to create a Child SA SHOULD NOT tear down the IKE SA: there is no
// reason to lose the work done to set up the IKE SA." A spent SA no rekey
// replaces is past its lifetime, and the session closes the IKE SA for it as
// section 2.8 asks.
func fatalReserveError(err error) bool {
	return err != nil && !errors.Is(err, errNoChildSA) && !errors.Is(err, esp.ErrSequenceExhausted)
}

// dialerWasDropped reports whether a session is ending because the dialer that
// opened it was canceled while the node keeps running, which a reload that
// drops a peer does, and the sweep as well once closeAll has told every peer.
// tellDropped tells those two apart by whether the set still holds the session.
func dialerWasDropped(dial, node context.Context) bool {
	return dial.Err() != nil && node.Err() == nil
}

// requestRekey asks for a replacement Child SA, at most one attempt at a time,
// and reports whether it started one.
func (t *tunnel) requestRekey() bool {
	// a replacement already waits to take over, and the session refuses a rekey until the SA it replaces is deleted, so the ask is skipped before it uses the floor, which the ask made once the replacement is canceled needs
	if current := t.sas.Load(); t.rekey == nil || (current != nil && current.replacement != nil) || !t.rekeying.CompareAndSwap(false, true) {
		return false
	}
	now := int64(time.Since(t.started))
	previous := t.askedAt.Load()
	if now-previous < int64(rekeyAskInterval) || !t.askedAt.CompareAndSwap(previous, now) {
		t.rekeying.Store(false)
		return false
	}
	ask := func() {
		defer t.rekeying.Store(false)
		// a replacement held since the ask still waits, and the session would refuse the rekey and hold the next one for the retry delay, so the ask is skipped and gives the floor back, as the skip before it does
		if current := t.sas.Load(); current != nil && current.replacement != nil {
			t.askedAt.CompareAndSwap(now, previous)
			return
		}
		t.rekey()
	}
	if t.launchAsk != nil {
		t.launchAsk(ask)
	} else {
		go ask()
	}
	return true
}

// RFC 7296 section 2.8.1: "To reduce the probability of this happening, the timing of rekeying requests SHOULD be jittered (delayed by a random amount of time after the need for rekeying is noticed)."
func (t *tunnel) askPastTheMark() func() {
	// nanoseconds since started plus one, so that zero reads as the mark not yet reached
	var from atomic.Int64
	return func() {
		now := int64(time.Since(t.started))
		at := from.Load()
		if at == 0 {
			from.CompareAndSwap(0, now+int64(t.askDelay(proactiveRekeyJitter))+1)
			return
		}
		if now+1 >= at {
			t.requestRekey()
		}
	}
}

func (t *tunnel) askDelay(bound time.Duration) time.Duration {
	if t.askJitter != nil {
		return t.askJitter(bound)
	}
	return rand.N(bound)
}

// tunnelSession is the session whose Child SAs a tunnel carries, which the tunnel asks for rekeys and tells of spent and failed SAs, and which takes the tunnel's handlers for the Child SAs it installs, retires and holds
type tunnelSession interface {
	RekeyChildProactively() error
	ChildSequenceSpent(uint32)
	ChildFailed(error)
	SetChildHandler(func(esp.ChildSA) error)
	SetChildRetireHandler(func(uint32) error)
	SetChildReplacementHandler(func(esp.ChildSA) error, func(uint32), func(uint32) bool)
}

// sessionTunnel is the tunnel of sess with child, the Child SA its handshake established, installed, and every handler of sess set to it
// refused gets a proactive rekey's error
func sessionTunnel(sess tunnelSession, child esp.ChildSA, replayWindow uint32, refused func(error)) (*tunnel, error) {
	t := &tunnel{replayWindow: replayWindow, started: time.Now()}
	t.askedAt.Store(-int64(rekeyAskInterval))
	// requestRekey owns the goroutine and the one-at-a-time guard
	// so this may block
	// RFC 7296 section 1.3.1: "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA"
	// a failed rekey leaves the IKE SA up and the schedule retries
	t.rekey = func() {
		if err := sess.RekeyChildProactively(); err != nil {
			refused(err)
		}
	}
	t.spent = sess.ChildSequenceSpent
	t.failed = sess.ChildFailed
	if err := t.install(child); err != nil {
		return nil, err
	}
	sess.SetChildHandler(t.install)
	sess.SetChildRetireHandler(t.retire)
	sess.SetChildReplacementHandler(t.hold, t.take, t.cancel)
	return t, nil
}

func (t *tunnel) install(child esp.ChildSA) error { return t.place(child, false) }

// RFC 7296 section 2.8: "When rekeying an SA, the responder continues to send traffic on the old SA until one of those events occurs."
func (t *tunnel) hold(child esp.ChildSA) error { return t.place(child, true) }

func (t *tunnel) place(child esp.ChildSA, hold bool) error {
	out, err := esp.NewOutbound(child)
	if err != nil {
		return err
	}
	in, err := esp.NewInbound(child, esp.WithReplayWindow(t.replayWindow))
	if err != nil {
		return err
	}
	out.SetRekeyCallback(t.askPastTheMark())
	t.mu.Lock()
	defer t.mu.Unlock()
	inbound := make(map[uint32]*esp.InboundSA)
	current := t.sas.Load()
	if current != nil {
		maps.Copy(inbound, current.inbound)
	}
	if _, exists := inbound[child.LocalSPI]; exists {
		return fmt.Errorf("inbound ESP SPI %08x already installed", child.LocalSPI)
	}
	inbound[child.LocalSPI] = in
	next := &tunnelSAs{outbound: out, outboundSPI: child.LocalSPI, inbound: inbound}
	if hold && current != nil && current.outbound != nil {
		next.outbound, next.outboundSPI, next.replacement, next.replacementSPI = current.outbound, current.outboundSPI, out, child.LocalSPI
	}
	t.sas.Store(next)
	t.replacing.Store(false)
	return nil
}

// take moves outbound traffic to the replacement whose inbound SPI is spi, and changes nothing where none waits under it
func (t *tunnel) take(spi uint32) {
	if current := t.sas.Load(); current != nil && current.replacement != nil && current.replacementSPI == spi {
		t.promote(current.replacement)
	}
}

// promote moves outbound traffic to replacement while it is still the one held, so a packet or a reservation that met a replacement since canceled moves nothing
func (t *tunnel) promote(replacement *esp.OutboundSA) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current := t.sas.Load(); current != nil && current.replacement == replacement {
		next := *current
		next.outbound, next.outboundSPI, next.replacement, next.replacementSPI = current.replacement, current.replacementSPI, nil, 0
		t.sas.Store(&next)
	}
}

// cancel removes the replacement whose inbound SPI is spi with its inbound SA and reports whether one waited under it, and leaves an outbound SA that took its place
func (t *tunnel) cancel(spi uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.sas.Load()
	if current == nil || current.replacement == nil || current.replacementSPI != spi {
		return false
	}
	t.sas.Store(current.without(spi))
	return true
}

func (t *tunnel) retire(spi uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.sas.Load()
	if current == nil || current.inbound[spi] == nil {
		return fmt.Errorf("retiring inbound ESP SPI %08x was not installed", spi)
	}
	t.sas.Store(current.without(spi))
	return nil
}

func (s *tunnelSAs) without(spi uint32) *tunnelSAs {
	next := *s
	next.inbound = maps.Clone(s.inbound)
	delete(next.inbound, spi)
	switch spi {
	case s.replacementSPI:
		next.replacement, next.replacementSPI = nil, 0
	case s.outboundSPI:
		next.outbound, next.outboundSPI, next.replacement, next.replacementSPI = s.replacement, s.replacementSPI, nil, 0
	}
	return &next
}

func (t *tunnel) reserve(count int) (netstack.BatchSealer, error) {
	current := t.sas.Load()
	if current == nil || current.outbound == nil {
		// an SA past its lifetime is replaced only by a rekey already running
		if t.replacing.CompareAndSwap(false, true) && !t.requestRekey() {
			t.replacing.Store(false)
		}
		return nil, errNoChildSA
	}
	r, err := current.outbound.ReserveSequenceRange(count)
	if err != nil {
		// a second try ends, since it runs only on another outbound SA, which a replacement or a retirement put in the spent one's place
		if errors.Is(err, esp.ErrSequenceExhausted) && t.moveOffSpent(current) {
			return t.reserve(count)
		}
		if fatalReserveError(err) && t.failed != nil {
			t.failed(err)
		}
		return nil, err
	}
	return r.SealBatchInto, nil
}

// moveOffSpent moves outbound traffic off current's spent outbound SA to the replacement held for it, asks for a rekey where none took its place, tells the session the spent SA, and reports whether another outbound SA now carries outbound traffic
// a cancel can take the replacement first, and the spent SA left in place is still installed, so nothing else asks for its rekey
func (t *tunnel) moveOffSpent(current *tunnelSAs) bool {
	if current.replacement != nil {
		t.promote(current.replacement)
	}
	moved := false
	if now := t.sas.Load(); now != nil && now.outbound != current.outbound {
		moved = true
	} else {
		t.requestRekey()
	}
	if t.spent != nil {
		t.spent(current.outboundSPI)
	}
	return moved
}

var errUnknownSPI = errors.New("no matching inbound ESP SA")

// decryptBatch appends one result per packet in their order, an unknown SPI or
// a packet too short to name one included, which the receive path pairs with
// each datagram's outer ECN field
func (t *tunnel) decryptBatch(packets [][]byte, results []inboundDecrypted) []inboundDecrypted {
	current := t.sas.Load()
	for len(packets) > 0 {
		raw := packets[0]
		if current != nil && len(raw) >= 4 {
			spi := binary.BigEndian.Uint32(raw[:4])
			if sa := current.inbound[spi]; sa != nil {
				end := 1
				for end < len(packets) && len(packets[end]) >= 4 && binary.BigEndian.Uint32(packets[end][:4]) == spi {
					end++
				}
				results = sa.AuthenticateBatchInPlace(packets[:end], results)
				// RFC 7296 section 2.8: "The responder can be assured that the initiator is prepared to receive messages on an SA if either (1) it has received a cryptographically valid message on the other half of the SA pair"
				// so a packet that authenticates under the new SA's key takes it, whether or not the replay window then accepts it
				if spi == current.replacementSPI && slices.ContainsFunc(results[len(results)-end:], func(result inboundDecrypted) bool { return result.Err == nil }) {
					t.promote(current.replacement)
				}
				packets = packets[end:]
				continue
			}
		}
		results = append(results, inboundDecrypted{Err: errUnknownSPI})
		packets = packets[1:]
	}
	return results
}

// validateESPTunnelPayload returns the inner packet a decrypted ESP payload
// carries, trimmed to the length its own header declares. RFC 4303 section 2.7
// lets a sender append Traffic Flow Confidentiality padding after it in tunnel
// mode, which ESP cannot tell from the payload, so requiring the payload to be
// exactly one packet dropped every padded packet from such a peer and left the
// loss visible only as a drop count. The second result is false for a Next
// Header of 59, which carries no packet at all.
func validateESPTunnelPayload(plain []byte, nextHeader byte) ([]byte, bool, error) {
	if nextHeader == esp.NextHeaderNone {
		return nil, false, nil
	}
	inner, version := packet.Payload(plain)
	if (nextHeader == esp.NextHeaderIPv4 && version == 4) || (nextHeader == esp.NextHeaderIPv6 && version == 6) {
		return inner, true, nil
	}
	return nil, false, fmt.Errorf("invalid IP tunnel payload for ESP Next Header %d", nextHeader)
}
