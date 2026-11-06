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

// netmonFixture is a laptop that moved from wifi to a dock three minutes ago, beside a container bridge and a point-to-point link,
// its host read 12 seconds ago
func netmonFixture() NetmonInfo {
	dock := NetmonDefault{Interface: "eth1", Gateway: netip.MustParseAddr("198.51.100.1")}
	wifi := NetmonDefault{Interface: "wlan0", Gateway: netip.MustParseAddr("203.0.113.1")}
	links4 := []NetmonLink{
		{Name: "docker0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.129/25")}}, {Name: "eth1", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.20/25")}}, {Name: "lo"},
		{Name: "ppp0", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.33/32")}, Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.64/28")}},
	}
	links6 := []NetmonLink{{Name: "docker0"}, {Name: "eth1", Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:7::20/64")}}, {Name: "lo"}}
	return NetmonInfo{
		Watching: true,
		Families: []NetmonFamily{
			{Family: "ipv4", Default: dock, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("198.51.100.129"), netip.MustParseAddr("203.0.113.33")}, Links: links4},
			{Family: "ipv6", Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:7::20")}, Links: links6},
		},
		ReadAt:  time.Date(2026, 10, 8, 9, 16, 54, 0, time.UTC),
		ReadAgo: Duration(12 * time.Second),
		LastChange: &NetmonChange{
			At:  time.Date(2026, 10, 8, 9, 14, 2, 0, time.UTC),
			Ago: Duration(3*time.Minute + 4*time.Second),
			Families: []NetmonFamilyChange{
				{Family: "ipv4", DefaultWas: &wifi, Default: &dock,
					Added: []netip.Addr{netip.MustParseAddr("198.51.100.20")}, Removed: []netip.Addr{netip.MustParseAddr("203.0.113.20")}, Links: links4},
				{Family: "ipv6", Added: []netip.Addr{netip.MustParseAddr("2001:db8:7::20")}, Removed: []netip.Addr{netip.MustParseAddr("2001:db8:1::20")}, Links: links6},
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

	// a watch whose reads have failed for a minute, the families left as its last read found them
	info = netmonFixture()
	info.ReadAt, info.ReadAgo = time.Date(2026, 10, 8, 9, 15, 6, 0, time.UTC), Duration(2*time.Minute)
	info.ReadFailing = &NetmonReadFailing{Since: time.Date(2026, 10, 8, 9, 16, 6, 0, time.UTC), Failures: 6, Err: "kernel: dump addresses: no buffer space available"}
	out.Reset()
	RenderNetmon(&out, info)
	golden(t, "netmon-failing.txt", []byte(out.String()))
	goldenJSON(t, "netmon-failing.json", info)
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
	return Result{Acted: []string{"example/gateway:1@0"}, Detail: "Asked 1 session(s) to prove their path now"}, nil
}

// the netmon view reads the host's network as the watch holds it, and a POST to it is refused
func TestNetmonReadsTheNetworkWatch(t *testing.T) {
	server := served(t, &netmonSource{})
	if status, body := get(t, server.Client(), server.URL+PathDebugNetmon); status != http.StatusOK || !strings.Contains(body, `"eth1"`) {
		t.Errorf("the netmon view was answered %d %q", status, body)
	}
	if refused := post(t, server.URL+PathDebugNetmon, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the netmon view was answered %s", refused.Status)
	}
}

// a probe is an action that takes a POST with a peer or every session
// a source without sessions to probe says so by name
func TestProbeIsAnActionThatTakesAPost(t *testing.T) {
	source := &netmonSource{}
	server := served(t, source)
	if status, body := get(t, server.Client(), server.URL+PathDebugProbe); status != http.StatusMethodNotAllowed {
		t.Errorf("a GET of the probe was answered %d %q", status, body)
	}
	answer := post(t, server.URL+PathDebugProbe, `{"peer":"example/gateway"}`)
	body, _ := io.ReadAll(answer.Body)
	if answer.StatusCode != http.StatusOK || source.peer != "example/gateway" || source.all || !strings.Contains(string(body), "example/gateway:1@0") {
		t.Errorf("a probe of one peer was answered %s %q and reached the source as %+v", answer.Status, body, source)
	}
	if answer := post(t, server.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusOK || !source.all {
		t.Errorf("a probe of every session was answered %s and reached the source as %+v", answer.Status, source)
	}

	bare := served(t, fakeSource{})
	if answer := post(t, bare.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusNotImplemented {
		t.Errorf("a probe of a source without sessions was answered %s", answer.Status)
	}
}
