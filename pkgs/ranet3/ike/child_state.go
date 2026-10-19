// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// SetChildHandler installs replacement ESP SAs before Run acknowledges a
// peer-initiated rekey, as required by RFC 7296 section 2.8.
func (s *Session) SetChildHandler(fn func(ChildSA) error) {
	s.handlerMu.Lock()
	s.onChild = fn
	s.handlerMu.Unlock()
}

// SetChildRetireHandler removes a Child SA's ESP keys, named by its inbound
// SPI: the inbound SA, and the outbound SA paired with it while that one is in
// use. Replaced SAs are removed after the overlap period, while an active SA
// deleted without replacement or reaching its lifetime is removed immediately.
func (s *Session) SetChildRetireHandler(fn func(uint32) error) {
	s.handlerMu.Lock()
	s.onRetire = fn
	s.handlerMu.Unlock()
}

// canReplaceChild reports why a replacement could not be installed, so a
// negotiation can refuse before it puts a proposal the peer will act on onto
// the wire.
func (s *Session) canReplaceChild(localSPI uint32) error {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.canReplaceChildLocked(localSPI)
}

func (s *Session) canReplaceChildLocked(localSPI uint32) error {
	if s.retiring.LocalSPI != 0 {
		return fmt.Errorf("ike: Child SA %08x is still awaiting retirement", s.retiring.LocalSPI)
	}
	if localSPI == s.Child.LocalSPI {
		return fmt.Errorf("ike: Child SA SPI %08x is already active", localSPI)
	}
	for _, retired := range s.retired {
		if localSPI == retired.spi {
			return fmt.Errorf("ike: Child SA SPI %08x is still draining", localSPI)
		}
	}
	if slices.Contains(s.halfClosed, localSPI) {
		return fmt.Errorf("ike: Child SA SPI %08x names a pair the peer refused to delete", localSPI)
	}
	return nil
}

// halfClosedBy reads the peer's answer to this end's Delete of the Child SA whose inbound SPI is spi, and reports whether the peer refused it
// RFC 7296 section 1.4.1 on the pair the peer then holds: "A node MAY refuse to accept incoming data on half-closed connections but MUST NOT unilaterally close them and reuse the SPIs."
// so this end keeps its SAs of the pair down, keeps spi from every later Child SA of the session, and does not ask again
func (s *Session) halfClosedBy(answer []RawPayload, spi uint32) bool {
	refused := refusal("INFORMATIONAL", answer)
	if refused == nil {
		return false
	}
	s.childMu.Lock()
	s.halfClosed = append(s.halfClosed, spi)
	s.childMu.Unlock()
	slog.Warn("ike the peer refused to delete a Child SA, whose pair stays half closed", "spi", spi, "err", refused)
	return true
}

func (s *Session) replaceChild(child ChildSA) error { return s.replaceKeyedChild(child, kexEntry{}) }

// replaceKeyedChild installs child keyed by the key exchanges of entry
// the zero entry is a Child SA SK_d alone keyed
func (s *Session) replaceKeyedChild(child ChildSA, entry kexEntry) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if err := s.canReplaceChildLocked(child.LocalSPI); err != nil {
		return err
	}
	if err := s.mux.RegisterESP(child.LocalSPI); err != nil {
		return err
	}
	s.handlerMu.RLock()
	fn := s.onChild
	s.handlerMu.RUnlock()
	if fn != nil {
		if err := fn(child); err != nil {
			s.mux.UnregisterESP(child.LocalSPI)
			return err
		}
	}
	old, oldEnds := s.Child, s.childEstablished.Add(s.childRekeyInterval)
	s.Child, s.childEstablished = child, time.Now()
	s.childKex = keyedEntry{spi: child.LocalSPI, entry: entry}
	if old.LocalSPI != 0 {
		s.retiring, s.retiringEnds = old, oldEnds
		// The peer owes a Delete for it, and a peer is free not to send one.
		// Nothing else bounds this, and while it is set every rekey in both
		// directions is refused, so it has a deadline of its own, past which
		// this end deletes the SA itself.
		s.retiringBy = time.Now().Add(retirementDeadline)
	}
	return nil
}

func (s *Session) currentChild() ChildSA {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.Child
}

func (s *Session) retiringChild() ChildSA {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.retiring
}

func (s *Session) retireChild(remoteSPI uint32) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	retiring := s.retiring
	if retiring.LocalSPI == 0 {
		// the peer's Delete crossed this end's, and deleteChildren already cleared the SA
		return nil
	}
	if retiring.RemoteSPI != remoteSPI {
		return fmt.Errorf("ike: no retiring Child SA with remote SPI %08x", remoteSPI)
	}
	if err := s.retireInboundLocked(retiring.LocalSPI, true); err != nil {
		return err
	}
	s.retiring, s.retiringDeleting = ChildSA{}, false
	return nil
}

// set before this end's Delete for the replaced SA goes out, so a crossing Delete never finds it unmarked
func (s *Session) deletingRetiring(remoteSPI uint32) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if s.retiring.LocalSPI != 0 && s.retiring.RemoteSPI == remoteSPI {
		s.retiringDeleting = true
	}
}

// the mark it sets keeps a second Delete for the same SA from following the first
func (s *Session) overdueRetiring(now time.Time) (ChildSA, bool) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if s.retiring.LocalSPI == 0 || s.retiringDeleting || now.Before(s.retiringBy) {
		return ChildSA{}, false
	}
	s.retiringDeleting = true
	return s.retiring, true
}

// RFC 7296 section 2.4: "If an IKE endpoint chooses to delete Child SAs, it MUST send Delete payloads to the other end notifying it of the deletion."
// section 2.25.1: "If a peer receives a request to close a Child SA that does not exist, it SHOULD reply without a Delete payload."
// so the SA retires whatever comes back, and a peer that does not answer leaves nothing to wait for
func (s *Session) deleteOverdueChild(child ChildSA) {
	slog.Warn("ike deleting a replaced Child SA the peer never deleted", "spi", child.LocalSPI, "after", retirementDeadline)
	spi := binary.BigEndian.AppendUint32(nil, child.LocalSPI)
	if answer, err := s.request(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})}}); err != nil {
		slog.Warn("ike could not delete a replaced Child SA the peer never deleted", "spi", child.LocalSPI, "err", err)
	} else {
		s.halfClosedBy(answer, child.LocalSPI)
	}
	if err := s.retireChild(child.RemoteSPI); err != nil {
		slog.Warn("ike could not retire a replaced Child SA", "spi", child.LocalSPI, "err", err)
		s.ChildFailed(err)
	}
}

// ChildFailed tells the session that its Child SA's dataplane refused a change, which closes the IKE SA with a Delete for it, and never blocks
func (s *Session) ChildFailed(err error) {
	select {
	case s.childFailed <- err:
	default:
	}
}

type childRetirement struct {
	spi       uint32
	expiresAt time.Time
}

// RFC 7296 section 1.4.1: "When an SA is closed, both members of the pair MUST be closed (that is, deleted). Each endpoint MUST close its incoming SAs and allow the other endpoint to close the other SA in each pair."
// the SA's keys leave the dataplane at its lifetime whatever exchange is outstanding, and its SPI stays registered until a Delete, its rekey's or the IKE SA's, closes the pair
// each SPI and the start of its lifetime are read under one lock, so a rekey's swap never pairs one SA's SPI with the other's start
func (s *Session) expireChild(now time.Time) error {
	if s.childRekeyInterval == 0 {
		return nil
	}
	s.childMu.Lock()
	defer s.childMu.Unlock()
	for _, sa := range []struct {
		child ChildSA
		ends  time.Time
	}{{s.Child, s.childEstablished.Add(s.childRekeyInterval)}, {s.retiring, s.retiringEnds}} {
		spi := sa.child.LocalSPI
		if spi == 0 || now.Before(sa.ends) || slices.Contains(s.withdrawn, spi) {
			continue
		}
		slog.Warn("ike stopping ESP on a Child SA past its lifetime", "spi", spi, "lifetime", s.childRekeyInterval)
		s.handlerMu.RLock()
		fn := s.onRetire
		s.handlerMu.RUnlock()
		if fn != nil {
			if err := fn(spi); err != nil {
				return fmt.Errorf("ike: withdraw the expired Child SA: %w", err)
			}
		}
		s.withdrawn = append(s.withdrawn, spi)
		s.emit("ike.sa.expired", slog.String("sa", "child"), slog.String("spi_in", fmt.Sprintf("%08x", spi)), slog.String("spi_out", fmt.Sprintf("%08x", sa.child.RemoteSPI)))
	}
	return nil
}

// ChildSequenceSpent tells the session that the outbound SA of the Child SA whose inbound SPI is spi has no sequence number left, and never blocks
// RFC 4303 section 3.3.3: "An attempt to transmit a packet that would result in sequence number overflow is an auditable event."
// the log line carries its own time, and an SA without ESN has spent its sequence space when a packet needs number 2^32
func (s *Session) ChildSequenceSpent(spi uint32) {
	if s.spentSPI.Swap(spi) == spi {
		return
	}
	var out uint32
	s.childMu.RLock()
	for _, child := range []ChildSA{s.Child, s.retiring} {
		if child.LocalSPI == spi {
			out = child.RemoteSPI
		}
	}
	s.childMu.RUnlock()
	slog.Warn("ike Child SA ran out of sequence numbers", "spi", fmt.Sprintf("%08x", out), "spi_in", fmt.Sprintf("%08x", spi),
		"local", s.local.String(), "remote", s.remote.String(), "src", s.mux.LocalAddr().String(), "dst", s.mux.Endpoint().String(), "seq", uint64(1)<<32)
	select {
	case s.childSpent <- struct{}{}:
	default:
	}
}

// RFC 7296 section 2.8: "IKE, ESP, and AH Security Associations use secret keys that should be used only for a limited amount of time and to protect a limited amount of data." and "This limits the lifetime of the entire Security Association."
// RFC 4303 section 3.3.3: "the sender MUST NOT send a packet on an SA if doing so would cause the sequence number to cycle."
// a Child SA whose sequence space is spent has reached the limit on its data, which ends its lifetime as its interval does
func (s *Session) currentChildSpent() bool {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.Child.LocalSPI != 0 && s.spentSPI.Load() == s.Child.LocalSPI
}

func (s *Session) childWithdrawn() bool {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return slices.Contains(s.withdrawn, s.Child.LocalSPI)
}

// childMu is held across the callback and registration change, so an SPI
// cannot be reused while removal of its previous keys is still in progress.
func (s *Session) retireInboundLocked(spi uint32, replaced bool) error {
	// its keys left at its lifetime, so there is nothing to drain and only the registration to drop
	if i := slices.Index(s.withdrawn, spi); i >= 0 {
		s.withdrawn = slices.Delete(s.withdrawn, i, i+1)
		s.mux.UnregisterESP(spi)
		return nil
	}
	// a replaced SA drains no longer than its lifetime, which the drains of later SAs end after, so the list stays in order
	if replaced && s.childRetireDelay > 0 {
		until := time.Now().Add(s.childRetireDelay)
		if s.childRekeyInterval > 0 && s.retiringEnds.Before(until) {
			until = s.retiringEnds
		}
		if time.Now().Before(until) {
			s.retired = append(s.retired, childRetirement{spi, until})
			return nil
		}
	}
	s.handlerMu.RLock()
	fn := s.onRetire
	s.handlerMu.RUnlock()
	if fn != nil {
		if err := fn(spi); err != nil {
			return err
		}
	}
	s.mux.UnregisterESP(spi)
	return nil
}

// nextRetirement is when the earliest replaced inbound SA may be dropped, so
// the control loop can wait for it rather than poll for it. The SA waiting for
// the peer's Delete counts too: nothing else would wake the loop to give up on
// a Delete that is not coming. Once this end's own Delete for it is out, the
// answer wakes the loop, and its deadline would only wake it to do nothing.
func (s *Session) nextRetirement() (time.Time, bool) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	var earliest time.Time
	sooner := func(at time.Time) {
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}
	if len(s.retired) > 0 {
		sooner(s.retired[0].expiresAt)
	}
	if s.retiring.LocalSPI != 0 && !s.retiringDeleting {
		sooner(s.retiringBy)
	}
	if s.retiring.LocalSPI != 0 && s.childRekeyInterval > 0 && !slices.Contains(s.withdrawn, s.retiring.LocalSPI) && time.Now().Before(s.retiringEnds) {
		sooner(s.retiringEnds)
	}
	return earliest, !earliest.IsZero()
}

func (s *Session) expireRetiredChildren(now time.Time) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	// one whose retirement is refused leaves the list too, or its deadline, already past, would wake the loop at once forever
	for len(s.retired) > 0 && !now.Before(s.retired[0].expiresAt) {
		spi := s.retired[0].spi
		s.retired = s.retired[1:]
		if err := s.retireInboundLocked(spi, false); err != nil {
			return fmt.Errorf("ike: expire retired Child SA: %w", err)
		}
	}
	return nil
}

func (s *Session) forgetChild(child ChildSA) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if s.Child.LocalSPI == 0 {
		return nil
	}
	if s.Child.LocalSPI != child.LocalSPI || s.Child.RemoteSPI != child.RemoteSPI {
		return fmt.Errorf("ike: Child SA changed while handling CHILD_SA_NOT_FOUND")
	}
	if err := s.retireInboundLocked(child.LocalSPI, false); err != nil {
		return err
	}
	s.Child = ChildSA{}
	return nil
}

// deleteChildren closes every locally known Child SA designated by the peer's
// inbound SPIs and returns our paired inbound SPIs for the Delete response
// (RFC 7296 section 1.4.1). Unknown SPIs are ignored, and so is a replaced SA
// this end's own Delete is out for. A refusal stops it, and it returns the
// SPIs of the SAs it closed before that one with the refusal.
func (s *Session) deleteChildren(remoteSPIs []uint32) ([]uint32, error) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	localSPIs := make([]uint32, 0, len(remoteSPIs))
	for _, remoteSPI := range remoteSPIs {
		var child *ChildSA
		switch {
		case s.Child.LocalSPI != 0 && s.Child.RemoteSPI == remoteSPI:
			child = &s.Child
		case s.retiring.LocalSPI != 0 && s.retiring.RemoteSPI == remoteSPI:
			// RFC 7296 section 1.4.1: "If a node receives a delete request for SAs for which it has already issued a delete request, it MUST delete the outgoing SAs while processing the request and the incoming SAs while processing the response. In that case, the responses MUST NOT include Delete payloads for the deleted SAs, since that would result in duplicate deletion and could in theory delete the wrong SA."
			// its outgoing half stopped carrying traffic when its replacement was installed, and its incoming half goes when this end's own Delete is answered
			if s.retiringDeleting {
				continue
			}
			child = &s.retiring
		default:
			continue
		}
		if err := s.retireInboundLocked(child.LocalSPI, child == &s.retiring); err != nil {
			return localSPIs, err
		}
		localSPIs = append(localSPIs, child.LocalSPI)
		*child = ChildSA{}
	}
	return localSPIs, nil
}
