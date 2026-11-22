// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/internal/version"
)

// the runtime's two reads and the clock the view takes, each of which a test replaces to hand the view values it knows
// a metric's value is read in readMetrics, as only the runtime makes a metrics.Value
var (
	readMetrics   = metricValues
	readCollector = debug.ReadGCStats
	readClock     = time.Now
)

// metricValues reads the samples' metrics from runtime/metrics, which stops no goroutine, and is each one's value in their order
func metricValues(samples *[4]metrics.Sample) (values [4]uint64) {
	metrics.Read(samples[:])
	for i := range samples {
		values[i] = samples[i].Value.Uint64()
	}
	return values
}

// DebugRuntime reads this process from the go runtime and the kernel
func (c *Client) DebugRuntime() control.RuntimeInfo {
	heap := readMetrics(&[4]metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/gc/heap/objects:objects"}, {Name: "/gc/heap/goal:bytes"}, {Name: "/memory/classes/total:bytes"}})
	// the collector's statistics, which it reads without stopping the world
	var collector debug.GCStats
	readCollector(&collector)
	now := readClock()
	info := control.RuntimeInfo{
		Version:      version.String(),
		GoVersion:    runtime.Version(),
		GOMAXPROCS:   runtime.GOMAXPROCS(0),
		CPUs:         runtime.NumCPU(),
		Goroutines:   runtime.NumGoroutine(),
		Threads:      pprof.Lookup("threadcreate").Count(),
		Descriptors:  openDescriptors(),
		HeapAlloc:    heap[0],
		HeapObjects:  heap[1],
		NextGC:       heap[2],
		Sys:          heap[3],
		GCCycles:     collector.NumGC,
		GCPauseTotal: control.Duration(collector.PauseTotal),
		Uptime:       control.Duration(now.Sub(c.started)),
	}
	// a wall clock stepped back past the last collection reads zero, never a negative age
	if collector.NumGC > 0 {
		info.LastGC = control.Duration(max(now.Sub(collector.LastGC), 0))
	}
	info.Revision, info.Modified = version.VCS()
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) == nil {
		info.DescriptorLimit = uint64(limit.Cur)
	}
	var settings []debug.BuildSetting
	if build, ok := debug.ReadBuildInfo(); ok {
		settings = build.Settings
	}
	info.Resolver = resolver(registry.PrefersGo, settings, os.Getenv("GODEBUG"))
	return info
}

// resolver names what the endpoint resolver, the daemon's one lookup, can reach
// go where it runs go's own resolver alone, cgo where it may go to the C library
// one that prefers go runs it whatever the build, and the rest follow the rules the net package applies at startup
func resolver(prefersGo bool, settings []debug.BuildSetting, godebug string) string {
	if prefersGo {
		return "go"
	}
	var library, netgo bool
	var defaults string
	for _, setting := range settings {
		switch setting.Key {
		case "CGO_ENABLED":
			library = setting.Value == "1"
		case "-tags":
			netgo = slices.Contains(strings.Split(setting.Value, ","), "netgo")
		case "DefaultGODEBUG":
			defaults = setting.Value
		}
	}
	if !library || netgo || netdnsMode(defaults+","+godebug) == "go" {
		return "go"
	}
	return "cgo"
}

// netdnsMode is the resolver the last netdns in a GODEBUG list names
// empty where that setting names a debug level alone
// a value is cut at its first + alone, as the net package cuts it, and a part starting with a digit is a debug level
func netdnsMode(godebug string) string {
	mode := ""
	for setting := range strings.SplitSeq(godebug, ",") {
		name, value, ok := strings.Cut(setting, "=")
		if !ok || name != "netdns" {
			continue
		}
		mode = ""
		first, second, _ := strings.Cut(value, "+")
		for _, part := range []string{first, second} {
			if part != "" && (part[0] < '0' || part[0] > '9') {
				mode = part
			}
		}
	}
	return mode
}

// openDescriptors counts this process's open descriptors, the listing's own included
// -1 means the listing could not be opened, which a process out of descriptors cannot do
func openDescriptors() int {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	return len(entries)
}
