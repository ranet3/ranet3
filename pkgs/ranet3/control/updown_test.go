// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// downFor is how long ago the fixtures went down, the same for every clock a render reads
const downFor = 3*time.Minute + 4*time.Second

// wentDown is when the fixtures went down
var wentDown = time.Date(2026, 10, 12, 21, 4, 5, 0, time.UTC)

// downStatus is a gateway taken off the mesh, its counts at zero and its reconciler withdrawn on the pass the down asked for
func downStatus() Status {
	return Status{
		Version: "v0.1.0", Organization: "example", CommonName: "gateway",
		Port: 13000, Endpoints: []string{"0/ip4", "1/ip6"},
		TUN: "ranet3", MTU: 1400, Queues: 4,
		Uptime:    Duration(26 * time.Hour),
		Responder: true, ForwardsIPv4: true, ForwardsIPv6: true,
		Registry:  RegistryInfo{Path: "/etc/ranet3/registry.json", Organizations: 1, Nodes: 12},
		Kernel:    KernelStatus{Enabled: true, Where: "table 100", Table: 100, Protocol: 155, Metric: 1024, PassAt: time.Now().Add(-downFor)},
		Counts:    Counts{Originated: 1},
		Originate: []Originated{{Prefix: netip.MustParsePrefix("2001:db8:a::/48")}},
		Down:      &Down{Since: wentDown, For: Duration(downFor)},
	}
}

func TestStatusOfANodeOffTheMeshRendersAsTheGoldenFile(t *testing.T) {
	var out strings.Builder
	RenderStatus(&out, downStatus())
	golden(t, "status-down.txt", []byte(out.String()))
	goldenJSON(t, "status-down.json", downStatus().Down)
}

// upDownFixture is the debug view of the gateway an operator took off the mesh
func upDownFixture() UpDownInfo {
	return UpDownInfo{
		Down: &Down{Since: wentDown, For: Duration(downFor)},
		Flag: "/var/lib/ranet3/down", Flagged: true,
		Last: &UpDownChange{Down: true, Cause: CauseRequest, At: wentDown, Ago: Duration(downFor)},
	}
}

func TestUpDownRendersAsTheGoldenFiles(t *testing.T) {
	info := upDownFixture()
	var out strings.Builder
	RenderUpDown(&out, info)
	golden(t, "updown.txt", []byte(out.String()))
	goldenJSON(t, "updown.json", info)

	// restarted an hour later, and down again from the flag rather than from a request
	info.Down = &Down{Since: wentDown, For: Duration(time.Hour + time.Minute)}
	info.Last = &UpDownChange{Down: true, Cause: CauseFlag, At: wentDown.Add(time.Hour), Ago: Duration(time.Minute)}
	out.Reset()
	RenderUpDown(&out, info)
	golden(t, "updown-restarted.txt", []byte(out.String()))

	// put back by a request, the flag gone with it
	info = UpDownInfo{Flag: "/var/lib/ranet3/down", Last: &UpDownChange{Cause: CauseRequest, At: wentDown, Ago: Duration(downFor)}}
	out.Reset()
	RenderUpDown(&out, info)
	golden(t, "updown-up.txt", []byte(out.String()))
}

// a flag and a state that disagree say what a restart would do, and a daemon without a state directory says it keeps none
func TestUpDownSaysWhatARestartWouldDo(t *testing.T) {
	for name, test := range map[string]struct {
		info UpDownInfo
		want string
	}{
		"down without its flag": {UpDownInfo{Down: &Down{Since: wentDown}, Flag: "/var/lib/ranet3/down"}, "a restart would put this node back on the mesh"},
		"up beside a flag":      {UpDownInfo{Flag: "/var/lib/ranet3/down", Flagged: true}, "a restart would start this node down"},
		"no state directory":    {UpDownInfo{}, "keeps no state directory"},
		"never moved":           {UpDownInfo{Flag: "/var/lib/ranet3/down"}, "not since the daemon started"},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			RenderUpDown(&out, test.info)
			if !strings.Contains(out.String(), test.want) {
				t.Errorf("the view reads %q, want it to say %q", out.String(), test.want)
			}
		})
	}
}

// upDownSource serves the updown view
type upDownSource struct{ fakeSource }

func (upDownSource) DebugUpDown() UpDownInfo { return upDownFixture() }

// the view discloses what the status already does, so a caller the root class refuses still reads it
// a source that cannot go down says so by name
func TestUpDownIsReadByACallerTheRootClassRefuses(t *testing.T) {
	server := injected(t, upDownSource{}, Caller{UID: 4242})
	if status, body := get(t, server.Client(), server.URL+PathDebugUpDown); status != http.StatusOK || !strings.Contains(body, `"/var/lib/ranet3/down"`) {
		t.Errorf("uid 4242 asking for the updown view was answered %d %q", status, body)
	}
	if refused := post(t, server.URL+PathDebugUpDown, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the updown view was answered %s", refused.Status)
	}
	bare := injected(t, fakeSource{}, Caller{UID: 0})
	if status, body := get(t, bare.Client(), bare.URL+PathDebugUpDown); status != http.StatusNotImplemented {
		t.Errorf("a source that cannot go down answered %d %q", status, body)
	}
}
