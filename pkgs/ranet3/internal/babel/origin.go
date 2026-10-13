// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"encoding/hex"
	"log/slog"
)

// Origin carries this node's own routes from one process to the next
// Limit is a seqno that no seqno the speaker has sent passes, in the order of RFC 8966 section 3.2.1
type Origin struct {
	RouterID [8]byte
	Limit    uint16
}

// why this node's own seqno rose, as babel.seqno.raised names it
const (
	raisedByRequest = "request"
	raisedByStart   = "start"
)

// SetOrigin starts this node's own routes from what the process before it left, before Run sends anything
// a zero router id keeps the one New drew
// the seqno starts one past from.Limit, and persist saves a limit before any seqno past the last one saved is used
// persist runs under the speaker's lock and must not call back into it
// drawn says why the router id is a new one, empty where from carries the one the last process advertised
func (s *Speaker) SetOrigin(from Origin, persist func(Origin) error, drawn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from.RouterID != ([8]byte{}) {
		s.routerID = from.RouterID
	}
	s.originSeqno, s.seqnoLimit, s.persist = from.Limit, from.Limit, persist
	attrs := []slog.Attr{slog.String("router_id", hex.EncodeToString(s.routerID[:]))}
	if drawn != "" {
		attrs = append(attrs, slog.String("drawn", drawn))
	}
	s.raiseSeqnoLocked(raisedByStart, "", attrs...)
}

// Origin is this node's router id with the limit persist last saved, and the seqno its routes carry now
func (s *Speaker) Origin() (Origin, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Origin{RouterID: s.routerID, Limit: s.seqnoLimit}, s.originSeqno
}

// startRunLocked raises the seqno at every run but the speaker's first, which New or SetOrigin began
// a run after a down and an up then sends seqnos past every one the runs before it sent
func (s *Speaker) startRunLocked() {
	if s.ran {
		s.raiseSeqnoLocked(raisedByStart, "")
	}
	s.ran = true
}

// seqnoRequestedLocked takes a seqno request naming this node's own router id and records it
// one asking past the seqno of a prefix this node originates raises the seqno, RFC 8966 section 3.8.1.2
// the raise comes at most once per packet, since a peer chooses how many requests one carries and eighty fit
// and each raise owes every neighbor a triggered update of everything this node originates
func (s *Speaker) seqnoRequestedLocked(n *neighborState, key routeKey, asked uint16) {
	seqno := s.originSeqno
	_, local := s.originate[key]
	raise := local && seqnoGT(asked, seqno) && !s.raisedSeqno
	s.events.Emit("babel.seqno.requested", n.peer.ID, slog.String("route", describeRoute(key)),
		slog.Int("asked", int(asked)), slog.Int("seqno", int(seqno)), slog.Bool("raised", raise))
	if raise {
		s.raisedSeqno = true
		s.raiseSeqnoLocked(raisedByRequest, n.peer.ID)
	}
}

// raiseSeqnoLocked moves this node's own seqno on by one, which every prefix it originates then carries
// a seqno past the saved limit is used only once persist has saved a limit seqnoLimitAhead past it
// a save that fails is logged and recorded, and the seqno moves on, since a neighbor starved for it stays starved without the raise
// the next raise past the saved limit tries the save again
// peer is the neighbor whose request it answers, empty for a start
func (s *Speaker) raiseSeqnoLocked(cause, peer string, attrs ...slog.Attr) {
	from := s.originSeqno
	s.originSeqno++
	if s.persist != nil && seqnoGT(s.originSeqno, s.seqnoLimit) {
		limit := s.originSeqno + seqnoLimitAhead
		if err := s.persist(Origin{RouterID: s.routerID, Limit: limit}); err != nil {
			slog.Warn("babel seqno limit not saved, so a crash before the next save may restart this node at a seqno it has sent",
				"limit", limit, "seqno", s.originSeqno, "err", err)
			s.events.Emit("babel.state.unsaved", peer, slog.Int("limit", int(limit)), slog.Int("seqno", int(s.originSeqno)),
				slog.String("err", err.Error()))
		} else {
			s.seqnoLimit = limit
		}
	}
	for origin := range s.originate {
		s.routes.dirty[origin] = struct{}{}
	}
	attrs = append(attrs, slog.String("cause", cause), slog.Int("from", int(from)), slog.Int("to", int(s.originSeqno)))
	if s.persist != nil {
		attrs = append(attrs, slog.Int("limit", int(s.seqnoLimit)))
	}
	s.events.Emit("babel.seqno.raised", peer, attrs...)
}
