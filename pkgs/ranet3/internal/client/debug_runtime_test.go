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

// an endpoint resolver that prefers go reads go whatever the build and the environment
// one that does not follows the net package's own startup rules
// a build without the cgo resolver, the netgo tag and a netdns setting naming go each force go
// the last netdns setting wins, and one naming a debug level alone names no resolver
func TestResolverFollowsTheNetPackage(t *testing.T) {
	cgo := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "1"}}
	plain := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}}
	for name, test := range map[string]struct {
		prefersGo bool
		settings  []debug.BuildSetting
		godebug   string
		want      string
	}{
		"preferring go with cgo":    {prefersGo: true, settings: cgo, godebug: "netdns=cgo", want: "go"},
		"without cgo":               {settings: plain, want: "go"},
		"with cgo":                  {settings: cgo, want: "cgo"},
		"with netgo":                {settings: append(cgo, debug.BuildSetting{Key: "-tags", Value: "osusergo,netgo"}), want: "go"},
		"netdns go":                 {settings: cgo, godebug: "netdns=go", want: "go"},
		"a debug level before go":   {settings: cgo, godebug: "netdns=1+go", want: "go"},
		"a debug level after go":    {settings: cgo, godebug: "netdns=go+1", want: "go"},
		"a level and more after go": {settings: cgo, godebug: "netdns=go+1+cgo", want: "go"},
		"the last setting wins":     {settings: cgo, godebug: "netdns=go,netdns=cgo", want: "cgo"},
		"a debug level alone last":  {settings: cgo, godebug: "netdns=go,netdns=2", want: "cgo"},
		"another setting named":     {settings: cgo, godebug: "http2client=0,netdnsx=go", want: "cgo"},
		"the build's default":       {settings: append(cgo, debug.BuildSetting{Key: "DefaultGODEBUG", Value: "netdns=go"}), want: "go"},
		"the environment overrides": {settings: append(cgo, debug.BuildSetting{Key: "DefaultGODEBUG", Value: "netdns=go"}), godebug: "netdns=cgo", want: "cgo"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := resolver(test.prefersGo, test.settings, test.godebug); got != test.want {
				t.Errorf("the resolver reads %s, want %s", got, test.want)
			}
		})
	}
}

// the view counts what the runtime and the kernel hold for this very process
// a collection runs first, so the collector has a cycle to report, and only what holds whatever ran since is asserted of the runtime's answer
func TestDebugRuntimeCountsThisProcess(t *testing.T) {
	c := testClient(t)
	c.started = time.Now().Add(-time.Minute)
	runtime.GC()
	info := c.DebugRuntime()
	if info.GoVersion != runtime.Version() || info.Goroutines < 1 || info.Threads < 1 ||
		info.GOMAXPROCS != runtime.GOMAXPROCS(0) || info.CPUs != runtime.NumCPU() {
		t.Errorf("the runtime reads %+v", info)
	}
	if info.GCCycles < 1 || info.LastGC < 0 || info.GCPauseTotal <= 0 || info.NextGC == 0 ||
		info.HeapAlloc == 0 || info.HeapObjects == 0 || info.Sys < info.HeapAlloc {
		t.Errorf("the heap and the collector read %+v", info)
	}
	// a build sandbox may hide the descriptor listing, where the view says so with -1
	// otherwise stdin, stdout and stderr at least
	if openDescriptors() < 0 {
		if info.Descriptors != -1 {
			t.Errorf("%d descriptors reported where the listing cannot be read", info.Descriptors)
		}
	} else if info.Descriptors < 3 || uint64(info.Descriptors) > info.DescriptorLimit {
		t.Errorf("%d descriptors open against a limit of %d", info.Descriptors, info.DescriptorLimit)
	}
	if info.Uptime < control.Duration(time.Minute) {
		t.Errorf("a client started a minute ago reports %s up", info.Uptime)
	}
}

// the view gives each metric it names, the collector's statistics and the ages the clock sets, as the runtime's reads hand them over
// a collection after the sample's time, as a wall clock stepped back gives, is no negative age
func TestDebugRuntimeReadsItsSample(t *testing.T) {
	last := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	// each metric the view might name holds a value of its own, so a name it reads in place of another gives a wrong field
	values := map[string]uint64{
		"/memory/classes/heap/objects:bytes": 1001,
		"/gc/heap/objects:objects":           1002,
		"/gc/heap/goal:bytes":                1003,
		"/memory/classes/total:bytes":        1004,
		"/gc/heap/live:bytes":                1005,
	}
	for _, sample := range []struct {
		name   string
		cycles int64
		now    time.Time
		age    control.Duration
	}{
		{"after the last collection", 7, last.Add(1500 * time.Millisecond), control.Duration(1500 * time.Millisecond)},
		{"before any collection", 0, last.Add(time.Second), 0},
		{"before the last collection", 7, last.Add(-time.Second), 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			defer func(read func(*[4]metrics.Sample) [4]uint64, collector func(*debug.GCStats), clock func() time.Time) {
				readMetrics, readCollector, readClock = read, collector, clock
			}(readMetrics, readCollector, readClock)
			readMetrics = func(samples *[4]metrics.Sample) (held [4]uint64) {
				for i, named := range samples {
					value, ok := values[named.Name]
					if !ok {
						t.Errorf("the view names %s, which the sample does not hold", named.Name)
					}
					held[i] = value
				}
				return held
			}
			readCollector = func(stats *debug.GCStats) {
				*stats = debug.GCStats{NumGC: sample.cycles, PauseTotal: 9 * time.Millisecond, LastGC: last}
			}
			readClock = func() time.Time { return sample.now }
			c := testClient(t)
			c.started = sample.now.Add(-time.Hour)
			info := c.DebugRuntime()
			want := control.RuntimeInfo{HeapAlloc: 1001, HeapObjects: 1002, NextGC: 1003, Sys: 1004, GCCycles: sample.cycles,
				GCPauseTotal: control.Duration(9 * time.Millisecond), LastGC: sample.age, Uptime: control.Duration(time.Hour)}
			got := control.RuntimeInfo{HeapAlloc: info.HeapAlloc, HeapObjects: info.HeapObjects, NextGC: info.NextGC, Sys: info.Sys, GCCycles: info.GCCycles,
				GCPauseTotal: info.GCPauseTotal, LastGC: info.LastGC, Uptime: info.Uptime}
			if got != want {
				t.Errorf("the view reads %+v from its sample, want %+v", got, want)
			}
		})
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
	client := testClient(t)
	before := pauses()
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
	if info := testClient(t).DebugRuntime(); info.Revision != "ed50ac2" || !info.Modified {
		t.Errorf("a build given ed50ac2-dirty reports revision %q modified %v", info.Revision, info.Modified)
	}
}
