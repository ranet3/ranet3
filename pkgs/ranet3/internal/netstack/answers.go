// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"log/slog"
	"net/netip"
	"sync/atomic"
)

// dummyIPv4 is the IPv4 dummy address of RFC 7600 section 4.8, which names no host and which Linux answers from where it holds no IPv4 address
var dummyIPv4 = netip.AddrFrom4([4]byte{192, 0, 0, 8})

// AnswerSources are the addresses that End's answers to a packet past its session and transit's errors come from, each invalid where the node holds none
// answerTooBig says where each answer to a packet past its session comes from, errorSource where transit's errors do, and every other answer comes from the packet it answers
type AnswerSources struct {
	// Router4 and Router6 are the router-id of each family, RFC 1812 section 2.2.7
	Router4, Router6 netip.Addr
	// SID is the one of this node's SIDs that transit's IPv6 errors come from where it holds no IPv6 router-id
	SID netip.Addr
}

// answerState holds the AnswerSources that End's answers to a packet past its session and transit's errors come from, and counts the errors it could not send for want of one
// with the TTL every ICMPv4 error the mesh builds carries
type answerState struct {
	answers atomic.Pointer[AnswerSources]
	// unanswered counts the errors not sent for want of an address of their family to come from
	unanswered atomic.Uint64
	answerTTL  atomic.Uint32
}

// SetAnswerTTL hands the mesh the TTL its ICMPv4 errors carry, the host's default, which RFC 1812 section 4.2.2.9 has be configurable
// a mesh holding none sends no ICMPv4 error, since the same section has no router originate a TTL of 0
func (m *Mesh) SetAnswerTTL(ttl uint8) { m.answerTTL.Store(uint32(ttl)) }

// AnswerTTL returns the TTL SetAnswerTTL last handed the mesh
func (m *Mesh) AnswerTTL() uint8 { return uint8(m.answerTTL.Load()) }

// SetAnswerSources hands the mesh the addresses that End's answers to a packet past its session and transit's errors come from, which AnswerSources names
// it records netstack.answer.source when they change, the first time where the node holds any
func (m *Mesh) SetAnswerSources(next AnswerSources) {
	previous := m.answers.Swap(&next)
	if previous == nil && next == (AnswerSources{}) || previous != nil && *previous == next || m.events == nil {
		return
	}
	var attrs []slog.Attr
	for _, source := range []struct {
		name    string
		address netip.Addr
	}{{"ipv4", next.Router4}, {"ipv6", next.Router6}, {"sid", next.SID}} {
		if source.address.IsValid() {
			attrs = append(attrs, slog.String(source.name, source.address.String()))
		}
	}
	m.events("netstack.answer.source", "", attrs...)
}

// AnswerSources returns the addresses SetAnswerSources last handed the mesh
func (m *Mesh) AnswerSources() AnswerSources {
	if sources := m.answers.Load(); sources != nil {
		return *sources
	}
	return AnswerSources{}
}

// errorSource is the address a time exceeded or destination unreachable for a packet of the family v6 names comes from
// the router-id, else the IPv4 dummy address or one of this node's SIDs, which is an IPv6 address of the node the mesh routes to it
// with neither it reports false and counts the error unanswered
func (m *Mesh) errorSource(v6 bool) (netip.Addr, bool) {
	sources := m.AnswerSources()
	switch {
	case !v6 && sources.Router4.IsValid():
		return sources.Router4, true
	case !v6:
		return dummyIPv4, true
	case sources.Router6.IsValid():
		return sources.Router6, true
	case sources.SID.IsValid():
		return sources.SID, true
	}
	m.unanswered.Add(1)
	return netip.Addr{}, false
}
