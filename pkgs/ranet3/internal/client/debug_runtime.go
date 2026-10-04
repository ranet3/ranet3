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
	"ranet3.com/pkgs/ranet3/internal/version"
)

// DebugRuntime reads this process from the go runtime and the kernel
// the heap comes from runtime/metrics and the collector from its own statistics, and neither stops the world
func (c *Client) DebugRuntime() control.RuntimeInfo {
	heap := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/heap/objects:objects"},
		{Name: "/gc/heap/goal:bytes"},
		{Name: "/memory/classes/total:bytes"},
	}
	metrics.Read(heap)
	var collector debug.GCStats
	debug.ReadGCStats(&collector)
	info := control.RuntimeInfo{
		Version:      version.String(),
		GoVersion:    runtime.Version(),
		GOMAXPROCS:   runtime.GOMAXPROCS(0),
		CPUs:         runtime.NumCPU(),
		Goroutines:   runtime.NumGoroutine(),
		Threads:      pprof.Lookup("threadcreate").Count(),
		Descriptors:  openDescriptors(),
		HeapAlloc:    heap[0].Value.Uint64(),
		HeapObjects:  heap[1].Value.Uint64(),
		NextGC:       heap[2].Value.Uint64(),
		Sys:          heap[3].Value.Uint64(),
		GCCycles:     collector.NumGC,
		GCPauseTotal: control.Duration(collector.PauseTotal),
		Uptime:       control.Duration(time.Since(c.started)),
	}
	if collector.NumGC > 0 {
		info.LastGC = control.Duration(time.Since(collector.LastGC))
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
	info.Resolver = resolver(runtime.GOOS, settings, os.Getenv("GODEBUG"))
	return info
}

// resolver names what a lookup can reach, by the rules the net package applies at startup
// go where only the go resolver runs, cgo where a lookup may go to the C library
// darwin reaches the system resolver through libSystem with or without cgo
func resolver(goos string, settings []debug.BuildSetting, godebug string) string {
	library, netgo, defaults := goos == "darwin", false, ""
	for _, setting := range settings {
		switch setting.Key {
		case "CGO_ENABLED":
			library = library || setting.Value == "1"
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
