// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// pmtuFixture is a steering node at link.mtu 8918 with a session settled under a path that carries 1450 bytes
// one searching up with a probe out, one under the floor and one its platform does not search
func pmtuFixture() PMTUInfo {
	return PMTUInfo{
		LinkMTU: 8918, Steering: 56, DeviceMTU: 8862, TooBigSent: 4, MSSClamped: 1,
		Sessions: []PMTUSession{
			{
				Peer: "example/bravo:2@alpha", Endpoint: "198.51.100.7:4500", State: PMTUConfirmed, DontFragment: true,
				Budget: 1450, MSSv4: 1410, MSSv6: 1390, Route: 8938, Target: 8918,
				Last: &PMTUOutcome{Size: 1454, Ago: Duration(3 * time.Minute)},
				Sent: 21, Acked: 12, Lost: 9,
				Changed: &PMTUChange{From: 1442, To: 1450, Reason: "probe", Ago: Duration(3 * time.Minute)},
			},
			{
				Peer: "example/charlie:3@alpha", Endpoint: "[2001:db8::3]:4500", State: PMTUSearchingUp, DontFragment: true,
				Budget: 1400, MSSv4: 1360, MSSv6: 1340, Route: 8878, Target: 8878,
				Probe: &PMTUProbe{Size: 5138, Attempts: 2, MaxAttempts: 3},
				Last:  &PMTUOutcome{Size: 1400, Acked: true, Ago: Duration(7 * time.Second)},
				Sent:  2, Acked: 1,
			},
			{
				Peer: "example/delta:4@alpha", Endpoint: "203.0.113.4:4500", State: PMTUUnderFloor,
				Budget: 1280, MSSv4: 1240, MSSv6: 1220, Route: 1182, Target: 1182,
				Sent: 6, Acked: 2, Lost: 4, Refusals: 1,
				Last:    &PMTUOutcome{Size: 1280, Ago: Duration(40 * time.Second)},
				Changed: &PMTUChange{From: 1400, To: 1280, Reason: "floor", Ago: Duration(time.Minute)},
			},
			{
				Peer: "example/echo:5@alpha", Endpoint: "192.0.2.5:4500", State: PMTUNotSearched,
				Budget: 8918, MSSv4: 8878, MSSv6: 8858,
			},
		},
	}
}

func TestPMTURendersAsTheGoldenFiles(t *testing.T) {
	info := pmtuFixture()
	var out strings.Builder
	RenderPMTU(&out, info)
	golden(t, "pmtu.txt", []byte(out.String()))
	goldenJSON(t, "pmtu.json", info)

	// a node with no steering whose tun did not answer, and no session
	info.Steering, info.DeviceMTU, info.Sessions = 0, 0, []PMTUSession{}
	out.Reset()
	RenderPMTU(&out, info)
	golden(t, "pmtu-bare.txt", []byte(out.String()))
}

// pmtuSource serves the pmtu view, keeping the peer it was asked for
type pmtuSource struct {
	fakeSource
	asked chan string
}

func (s pmtuSource) DebugPMTU(peer string) PMTUInfo {
	s.asked <- peer
	return pmtuFixture()
}

// the view is a snapshot without key material, so a caller the root class refuses still reads it
// the peer named reaches the source as it was written, and a POST is refused
func TestPMTUIsReadByACallerTheRootClassRefuses(t *testing.T) {
	source := pmtuSource{asked: make(chan string, 1)}
	server := injected(t, source, Caller{UID: 4242})
	if status, body := get(t, server.Client(), server.URL+PathDebugPMTU+"?peer=example%2Fbravo"); status != http.StatusOK {
		t.Errorf("uid 4242 asking a daemon under --debug-access root for the pmtu view was answered %d %q", status, body)
	}
	if peer := <-source.asked; peer != "example/bravo" {
		t.Errorf("the source was asked for %q, want example/bravo", peer)
	}
	if refused := post(t, server.URL+PathDebugPMTU, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the pmtu view was answered %s", refused.Status)
	}
}

// the client asks for the peer it is given and decodes the view the daemon answers
func TestPMTUClientNamesThePeer(t *testing.T) {
	source := pmtuSource{asked: make(chan string, 1)}
	client := serveStream(t, source, func(*http.Server) {})
	info, err := client.PMTU(context.Background(), "bravo")
	if err != nil {
		t.Fatal(err)
	}
	if peer := <-source.asked; peer != "bravo" {
		t.Errorf("the source was asked for %q, want bravo", peer)
	}
	if len(info.Sessions) != len(pmtuFixture().Sessions) || info.Sessions[0].Changed == nil {
		t.Errorf("the client decoded %+v", info)
	}
}
