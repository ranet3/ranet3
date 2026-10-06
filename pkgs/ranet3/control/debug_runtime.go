// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"io"
	"time"
)

// PathDebugRuntime is the daemon's process as the go runtime sees it
const PathDebugRuntime = PathDebug + "runtime"

func init() {
	debugRead(PathDebugRuntime, classRead, "runtime", RuntimeSource.DebugRuntime)
}

// RuntimeSource is a Source that reports its own process
type RuntimeSource interface {
	DebugRuntime() RuntimeInfo
}

// RuntimeInfo is the daemon's build and what its process holds right now
type RuntimeInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	// Revision is the commit the build came from, whole where the toolchain recorded it
	// Modified says that commit's tree had uncommitted changes
	Revision   string `json:"revision,omitempty"`
	Modified   bool   `json:"modified"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	CPUs       int    `json:"cpus"`
	Goroutines int    `json:"goroutines"`
	// Threads is the OS threads the runtime has started, which it does not give back
	Threads int `json:"threads"`
	// Descriptors is -1 where the descriptor listing could not be opened, as in a process out of them
	Descriptors     int    `json:"descriptors"`
	DescriptorLimit uint64 `json:"descriptor_limit"`
	// the heap and the collector, in bytes and cycles
	HeapAlloc    uint64   `json:"heap_alloc"`
	HeapObjects  uint64   `json:"heap_objects"`
	NextGC       uint64   `json:"next_gc"`
	Sys          uint64   `json:"sys"`
	GCCycles     int64    `json:"gc_cycles"`
	GCPauseTotal Duration `json:"gc_pause_total"`
	// LastGC is how long before the answer the last cycle ended, zero before the first
	LastGC Duration `json:"last_gc"`
	Uptime Duration `json:"uptime"`
	// Resolver is go where only the go resolver can run
	// cgo where a lookup may go to the C library, which holds an OS thread for as long as it takes
	Resolver string `json:"resolver"`
}

// Runtime reads the daemon's process
func (c *Client) Runtime() (RuntimeInfo, error) { return read[RuntimeInfo](c, PathDebugRuntime) }

// RenderRuntime writes the process as name and value pairs
func RenderRuntime(w io.Writer, info RuntimeInfo) {
	revision := info.Revision
	switch {
	case revision == "":
		revision = "not recorded in this build"
	case info.Modified:
		revision += " with uncommitted changes"
	}
	descriptors := fmt.Sprintf("%d of %d", info.Descriptors, info.DescriptorLimit)
	if info.Descriptors < 0 {
		descriptors = fmt.Sprintf("not countable, the limit is %d", info.DescriptorLimit)
	}
	collector := "no cycle yet"
	if info.GCCycles > 0 {
		collector = fmt.Sprintf("%s, the last %s ago", countOf(int(info.GCCycles), "cycle"), sinceText(time.Duration(info.LastGC)))
	}
	pairs(w, [][]string{
		{"Version", info.Version},
		{"Go", info.GoVersion},
		{"Revision", revision},
		{"Uptime", shortDuration(time.Duration(info.Uptime))},
		{"CPUs", fmt.Sprintf("%d, GOMAXPROCS %d", info.CPUs, info.GOMAXPROCS)},
		{"Goroutines", fmt.Sprint(info.Goroutines)},
		{"Threads", fmt.Sprint(info.Threads)},
		{"Descriptors", descriptors},
		{"Heap", fmt.Sprintf("%s in use, %d objects, next cycle at %s",
			bytesText(info.HeapAlloc), info.HeapObjects, bytesText(info.NextGC))},
		{"Memory", bytesText(info.Sys) + " from the system"},
		{"GC", collector},
		{"GC pause", shortDuration(time.Duration(info.GCPauseTotal))},
		{"Resolver", info.Resolver},
	})
}

// bytesText writes a size with the binary unit that keeps it under 1024
func bytesText(n uint64) string {
	const units = "KMGTPE"
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value, unit := float64(n)/1024, 0
	for value >= 1024 && unit < len(units)-1 {
		value, unit = value/1024, unit+1
	}
	return fmt.Sprintf("%.1f %ciB", value, units[unit])
}
