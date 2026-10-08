// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// netmonFixture is a laptop that moved from wifi to a dock three minutes ago
func netmonFixture() NetmonInfo {
	dock := NetmonDefault{Interface: "en7", Gateway: netip.MustParseAddr("10.0.0.1")}
	wifi := NetmonDefault{Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}
	return NetmonInfo{
		Watching: true,
		Families: []NetmonFamily{
			{Family: "ipv4", Default: dock, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.20")}},
			{Family: "ipv6", Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:7::20")}},
		},
		LastChange: &NetmonChange{
			At:  time.Date(2026, 10, 8, 9, 14, 2, 0, time.UTC),
			Ago: Duration(3*time.Minute + 4*time.Second),
			Families: []NetmonFamilyChange{
				{Family: "ipv4", DefaultWas: &wifi, Default: &dock,
					Added: []netip.Addr{netip.MustParseAddr("10.0.0.20")}, Removed: []netip.Addr{netip.MustParseAddr("192.168.1.20")}},
				{Family: "ipv6", Added: []netip.Addr{netip.MustParseAddr("2001:db8:7::20")}, Removed: []netip.Addr{netip.MustParseAddr("2001:db8:1::20")}},
			},
		},
	}
}

func TestNetmonRendersAsTheGoldenFiles(t *testing.T) {
	info := netmonFixture()
	var out strings.Builder
	RenderNetmon(&out, info)
	golden(t, "netmon.txt", []byte(out.String()))
	goldenJSON(t, "netmon.json", info)

	// a watch that has signaled nothing yet, on a host with no route off it
	info.LastChange = nil
	info.Families[0] = NetmonFamily{Family: "ipv4"}
	out.Reset()
	RenderNetmon(&out, info)
	golden(t, "netmon-quiet.txt", []byte(out.String()))

	out.Reset()
	RenderNetmon(&out, NetmonInfo{})
	golden(t, "netmon-unwatched.txt", []byte(out.String()))
}

// netmonSource serves the netmon view and the probe action, recording what the action was asked
type netmonSource struct {
	fakeSource
	peer string
	all  bool
}

func (*netmonSource) DebugNetmon() NetmonInfo { return netmonFixture() }

func (s *netmonSource) DebugProbe(_ context.Context, peer string, all bool) (Result, error) {
	s.peer, s.all = peer, all
	return Result{Acted: []string{"example/gateway/1@0"}, Detail: "Asked 1 session(s) to prove their path now"}, nil
}

// the netmon view is a snapshot without key material, so a caller the root class refuses still reads it
func TestNetmonIsReadByACallerTheRootClassRefuses(t *testing.T) {
	server := injected(t, &netmonSource{}, Caller{UID: 4242})
	if status, body := get(t, server.Client(), server.URL+PathDebugNetmon); status != http.StatusOK || !strings.Contains(body, `"en7"`) {
		t.Errorf("uid 4242 asking for the netmon view was answered %d %q", status, body)
	}
	if refused := post(t, server.URL+PathDebugNetmon, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the netmon view was answered %s", refused.Status)
	}
}

// a probe is an action of the root class that takes a POST with a peer or every session
// a source without sessions to probe says so by name
func TestProbeIsARootActionThatTakesAPost(t *testing.T) {
	refused := injected(t, &netmonSource{}, Caller{UID: 4242})
	if answer := post(t, refused.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusForbidden {
		t.Errorf("uid 4242 asking for a probe was answered %s", answer.Status)
	}

	source := &netmonSource{}
	root := injected(t, source, Caller{UID: 0})
	if status, body := get(t, root.Client(), root.URL+PathDebugProbe); status != http.StatusMethodNotAllowed {
		t.Errorf("a GET of the probe was answered %d %q", status, body)
	}
	answer := post(t, root.URL+PathDebugProbe, `{"peer":"example/gateway"}`)
	body, _ := io.ReadAll(answer.Body)
	if answer.StatusCode != http.StatusOK || source.peer != "example/gateway" || source.all || !strings.Contains(string(body), "example/gateway/1@0") {
		t.Errorf("a probe of one peer was answered %s %q and reached the source as %+v", answer.Status, body, source)
	}
	if answer := post(t, root.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusOK || !source.all {
		t.Errorf("a probe of every session was answered %s and reached the source as %+v", answer.Status, source)
	}

	bare := injected(t, fakeSource{}, Caller{UID: 0})
	if answer := post(t, bare.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusNotImplemented {
		t.Errorf("a probe of a source without sessions was answered %s", answer.Status)
	}
}
