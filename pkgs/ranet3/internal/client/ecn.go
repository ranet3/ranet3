// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// errECNDropped is why a packet is dropped where RFC 6040 section 4.2's Figure 4 drops it
var errECNDropped = errors.New("an outer CE over an inner Not-ECT packet")

// sessionECN is one session's decapsulation of the outer ECN field, owned by the goroutine its emit runs on
type sessionECN struct {
	// marked and unused count the batch's packets set to CE from an ECT inner field and its currently unused combinations
	marked, unused uint64
	// pending counts the unused combinations since the last record, the first of which outer, inner and header hold
	pending      uint64
	outer, inner packet.ECN
	header       []byte
	recordedAt   time.Time
}

// decapsulate writes into inner, an IPv4 or IPv6 packet validateESPTunnelPayload passed, the ECN field Figure 4 gives its own and outer, the field of the datagram it arrived in
func (s *sessionECN) decapsulate(inner []byte, outer packet.ECN) (keep bool) {
	field := packet.ECNOf(inner)
	out, drop, unused := packet.Decapsulate(field, outer)
	if unused {
		s.unused++
		if s.pending == 0 {
			s.outer, s.inner = outer, field
			s.header = append(s.header[:0], inner[:ipHeaderLen(inner)]...)
		}
		s.pending++
	}
	if drop {
		return false
	}
	if out != field {
		packet.SetECN(inner, out)
		if out == packet.CE {
			s.marked++
		}
	}
	return true
}

func ipHeaderLen(p []byte) int {
	if p[0]>>4 == 4 {
		return int(p[0]&0x0f) * 4
	}
	return 40
}

// RFC 6040 section 4.2 asks such a combination logged and rate-limited, and RFC 3168 section 9.2.2 asks a record of them to hold one such packet's headers
func (c *Client) settleECN(s *sessionECN, path string) {
	if s.marked > 0 {
		c.inboundCE.Add(s.marked)
	}
	if s.unused > 0 {
		c.inboundECNUnused.Add(s.unused)
	}
	s.marked, s.unused = 0, 0
	if s.pending == 0 {
		return
	}
	now := time.Now()
	if !s.recordedAt.IsZero() && now.Sub(s.recordedAt) < espDropReportInterval {
		return
	}
	header := hex.EncodeToString(s.header)
	c.events.Emit("esp.ecn.unused", path, slog.String("outer", s.outer.String()), slog.String("inner", s.inner.String()),
		slog.Uint64("count", s.pending), slog.String("header", header))
	slog.Debug("esp packets arrived with an ecn combination no tunnel sends", "peer", path, "outer", s.outer, "inner", s.inner, "count", s.pending, "header", header)
	s.pending, s.recordedAt = 0, now
}
