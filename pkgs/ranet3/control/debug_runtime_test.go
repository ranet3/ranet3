// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// runtimeFixture is a daemon twenty minutes up that has collected once
func runtimeFixture() RuntimeInfo {
	return RuntimeInfo{
		Version:         "2026.912.0+ed50ac2a11a7",
		GoVersion:       "go1.26.7",
		Revision:        "ed50ac2a11a77f5827de2084b6427ddad87701d2",
		Modified:        true,
		GOMAXPROCS:      16,
		CPUs:            16,
		Goroutines:      412,
		Threads:         129,
		Descriptors:     233,
		DescriptorLimit: 524288,
		HeapAlloc:       38 << 20,
		HeapObjects:     183244,
		NextGC:          64 << 20,
		Sys:             105 << 20,
		GCCycles:        1,
		GCPauseTotal:    Duration(4200 * time.Microsecond),
		LastGC:          Duration(37 * time.Second),
		Uptime:          Duration(20*time.Minute + 3*time.Second),
		Resolver:        "cgo",
	}
}

func TestRuntimeRendersAsTheGoldenFiles(t *testing.T) {
	info := runtimeFixture()
	var out strings.Builder
	RenderRuntime(&out, info)
	golden(t, "runtime.txt", []byte(out.String()))
	goldenJSON(t, "runtime.json", info)

	// a build that recorded no revision, a process out of descriptors and one that has not collected yet
	info.Revision, info.Modified, info.Descriptors, info.GCCycles, info.LastGC, info.GCPauseTotal = "", false, -1, 0, 0, 0
	out.Reset()
	RenderRuntime(&out, info)
	golden(t, "runtime-bare.txt", []byte(out.String()))
}

// plainRuntime serves the runtime view and names no access, so it serves under DebugRoot
type plainRuntime struct{ fakeSource }

func (plainRuntime) DebugRuntime() RuntimeInfo { return runtimeFixture() }

// the runtime is a snapshot without key material, so a caller the root class refuses still reads it
// it is a read, so a POST is refused
func TestRuntimeIsReadByACallerTheRootClassRefuses(t *testing.T) {
	server := injected(t, plainRuntime{}, Caller{UID: 4242})
	if status, body := get(t, server.Client(), server.URL+PathDebugRuntime); status != http.StatusOK {
		t.Errorf("uid 4242 asking a daemon under --debug-access root for the runtime was answered %d %q", status, body)
	}
	if refused := post(t, server.URL+PathDebugRuntime, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the runtime was answered %s", refused.Status)
	}
}
