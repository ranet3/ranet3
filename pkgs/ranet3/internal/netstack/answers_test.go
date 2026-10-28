// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"log/slog"
	"maps"
	"net/netip"
	"testing"
)

// a time exceeded or destination unreachable comes from the router-id of its family
// else over IPv4 from 192.0.0.8 and over IPv6 from one of the node's SIDs
// and over IPv6 with neither it is not sent, and counted
func TestErrorsComeFromTheRouterIDElseTheirFallback(t *testing.T) {
	router4, router6, sid := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("3fff:c::1"), netip.MustParseAddr("3fff:b:0:106::1")
	for _, tc := range []struct {
		held       AnswerSources
		v6         bool
		want       netip.Addr
		unanswered uint64
	}{
		{held: AnswerSources{router4, router6, sid}, want: router4},
		{held: AnswerSources{Router6: router6, SID: sid}, want: dummyIPv4},
		{held: AnswerSources{}, want: dummyIPv4},
		{held: AnswerSources{router4, router6, sid}, v6: true, want: router6},
		{held: AnswerSources{Router4: router4, SID: sid}, v6: true, want: sid},
		{held: AnswerSources{Router4: router4}, v6: true, unanswered: 1},
	} {
		m := NewRoutesOnly()
		m.SetAnswerSources(tc.held)
		got, sent := m.errorSource(tc.v6)
		if got != tc.want || sent != tc.want.IsValid() || m.unanswered.Load() != tc.unanswered {
			t.Errorf("a mesh holding %+v answers an error over IPv6 %v from %v, sent %v, counting %d unanswered, want %v and %d", tc.held, tc.v6, got, sent, m.unanswered.Load(), tc.want, tc.unanswered)
		}
	}
}

// netstack.answer.source is recorded each time the router-ids or the answer SID change, naming those held
// and neither for a set that changes nothing nor for a first set holding none
func TestAnswerSourceIsRecordedWhenItChanges(t *testing.T) {
	var recorded []map[string]string
	m := NewRoutesOnly()
	m.events = func(kind, _ string, attrs ...slog.Attr) {
		if kind != "netstack.answer.source" {
			t.Errorf("setting the answer sources recorded %s", kind)
		}
		named := make(map[string]string)
		for _, attr := range attrs {
			named[attr.Key] = attr.Value.String()
		}
		recorded = append(recorded, named)
	}
	router4, router6, sid := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("3fff:c::1"), netip.MustParseAddr("3fff:b:0:106::1")
	m.SetAnswerSources(AnswerSources{})
	m.SetAnswerSources(AnswerSources{Router4: router4, SID: sid})
	m.SetAnswerSources(AnswerSources{Router4: router4, SID: sid})
	m.SetAnswerSources(AnswerSources{router4, router6, sid})
	m.SetAnswerSources(AnswerSources{})
	want := []map[string]string{
		{"ipv4": "100.64.0.1", "sid": "3fff:b:0:106::1"},
		{"ipv4": "100.64.0.1", "ipv6": "3fff:c::1", "sid": "3fff:b:0:106::1"},
		{},
	}
	if len(recorded) != len(want) {
		t.Fatalf("five sets, three of them changes, recorded %v", recorded)
	}
	for i := range want {
		if !maps.Equal(recorded[i], want[i]) {
			t.Errorf("change %d was recorded as %v, want %v", i, recorded[i], want[i])
		}
	}
	if got := m.AnswerSources(); got != (AnswerSources{}) {
		t.Errorf("a mesh last handed nothing answers from %+v", got)
	}
}
