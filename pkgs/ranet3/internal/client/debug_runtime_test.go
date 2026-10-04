// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/version"
)

// the resolver follows the net package's own startup rules
// a build without the cgo resolver, the netgo tag and a netdns setting each force go
// the last netdns setting wins, and one naming a debug level alone names no resolver
func TestResolverFollowsTheNetPackage(t *testing.T) {
	cgo := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "1"}}
	plain := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}}
	for name, test := range map[string]struct {
		goos     string
		settings []debug.BuildSetting
		godebug  string
		want     string
	}{
		"linux without cgo":         {goos: "linux", settings: plain, want: "go"},
		"linux with cgo":            {goos: "linux", settings: cgo, want: "cgo"},
		"linux with netgo":          {goos: "linux", settings: append(cgo, debug.BuildSetting{Key: "-tags", Value: "osusergo,netgo"}), want: "go"},
		"darwin without cgo":        {goos: "darwin", settings: plain, want: "cgo"},
		"darwin with netgo":         {goos: "darwin", settings: append(plain, debug.BuildSetting{Key: "-tags", Value: "netgo"}), want: "go"},
		"netdns go":                 {goos: "linux", settings: cgo, godebug: "netdns=go", want: "go"},
		"a debug level before go":   {goos: "linux", settings: cgo, godebug: "netdns=1+go", want: "go"},
		"a debug level after go":    {goos: "linux", settings: cgo, godebug: "netdns=go+1", want: "go"},
		"a level and more after go": {goos: "linux", settings: cgo, godebug: "netdns=go+1+cgo", want: "go"},
		"the last setting wins":     {goos: "linux", settings: cgo, godebug: "netdns=go,netdns=cgo", want: "cgo"},
		"a debug level alone last":  {goos: "linux", settings: cgo, godebug: "netdns=go,netdns=2", want: "cgo"},
		"another setting named":     {goos: "linux", settings: cgo, godebug: "http2client=0,netdnsx=go", want: "cgo"},
		"the build's default":       {goos: "linux", settings: append(cgo, debug.BuildSetting{Key: "DefaultGODEBUG", Value: "netdns=go"}), want: "go"},
		"the environment overrides": {goos: "linux", settings: append(cgo, debug.BuildSetting{Key: "DefaultGODEBUG", Value: "netdns=go"}), godebug: "netdns=cgo", want: "cgo"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := resolver(test.goos, test.settings, test.godebug); got != test.want {
				t.Errorf("the resolver reads %s, want %s", got, test.want)
			}
		})
	}
}

// the view counts what the runtime and the kernel hold for this very process
// a collection runs first, so the collector has a cycle and a last one to report
func TestDebugRuntimeCountsThisProcess(t *testing.T) {
	runtime.GC()
	info := (&Client{started: time.Now().Add(-time.Minute)}).DebugRuntime()
	if info.GoVersion != runtime.Version() || info.Goroutines < 1 || info.Threads < 1 ||
		info.GOMAXPROCS != runtime.GOMAXPROCS(0) || info.CPUs != runtime.NumCPU() {
		t.Errorf("the runtime reads %+v", info)
	}
	if info.GCCycles < 1 || info.LastGC <= 0 || info.LastGC > control.Duration(time.Minute) || info.GCPauseTotal <= 0 ||
		info.HeapAlloc == 0 || info.HeapObjects == 0 || info.NextGC < info.HeapAlloc || info.Sys < info.HeapAlloc {
		t.Errorf("the heap and the collector read %+v", info)
	}
	// stdin, stdout and stderr at least
	if info.Descriptors < 3 || uint64(info.Descriptors) > info.DescriptorLimit {
		t.Errorf("%d descriptors open against a limit of %d", info.Descriptors, info.DescriptorLimit)
	}
	if info.Uptime < control.Duration(time.Minute) {
		t.Errorf("a client started a minute ago reports %s up", info.Uptime)
	}
}

// reading the view stops no goroutine of the daemon, so polling it costs the data path nothing
func TestDebugRuntimeStopsNoGoroutine(t *testing.T) {
	pauses := func() uint64 {
		sample := []metrics.Sample{{Name: "/sched/pauses/total/other:seconds"}}
		metrics.Read(sample)
		var count uint64
		for _, bucket := range sample[0].Value.Float64Histogram().Counts {
			count += bucket
		}
		return count
	}
	before := pauses()
	client := &Client{started: time.Now()}
	for range 10 {
		client.DebugRuntime()
	}
	if after := pauses(); after != before {
		t.Errorf("ten reads of the view stopped every goroutine %d times", after-before)
	}
}

// the view names the revision the build was given, as a nix build gives it, and its tree's state
func TestDebugRuntimeNamesThePassedRevision(t *testing.T) {
	defer func(previous string) { version.Revision = previous }(version.Revision)
	version.Revision = "ed50ac2-dirty"
	if info := (&Client{started: time.Now()}).DebugRuntime(); info.Revision != "ed50ac2" || !info.Modified {
		t.Errorf("a build given ed50ac2-dirty reports revision %q modified %v", info.Revision, info.Modified)
	}
}
