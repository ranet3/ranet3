// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package kernel

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// orderBenchLANs is how many LANs inside the none class orderBenchExit holds
const orderBenchLANs = 4000

// orderBenchExit is the mesh's table of an exit at babel's limit of 16,384
// route keys: orderBenchLANs /28 LANs inside the none class 198.18.0.0/15, the
// range RFC 2544 sets aside for benchmarks, every other /28 so no two touch
// and the none set holds a range between each two, and /64 LANs outside every
// class filling the rest, with the routes the reconciler left in the kernel
// for them. The reconciler also left a route at each /28 between two LANs,
// whose entry the table no longer holds, so the report's routes meet
// orderBenchLANs separate ranges of the none set as derived.
func orderBenchExit() (*netstack.RouteTable, []egress.Class, []meshkernel.Route) {
	table := netstack.NewRouteTable()
	classes := []egress.Class{{From: schema.MustPrefix("198.18.0.0/15"), To: egress.Translation{None: true}}}
	peer := &netstack.Peer{ID: "example/peer"}
	var routes []meshkernel.Route
	set := func(lan netip.Prefix) {
		table.Set(netip.Prefix{}, lan, peer)
		routes = append(routes, meshkernel.Route{Destination: lan, Metric: 1024})
	}
	for i := range orderBenchLANs {
		raw := netip.MustParseAddr("198.18.0.0").As4()
		binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+uint32(32*i))
		set(netip.PrefixFrom(netip.AddrFrom4(raw), 28))
		binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+16)
		routes = append(routes, meshkernel.Route{Destination: netip.PrefixFrom(netip.AddrFrom4(raw), 28), Metric: 1024})
	}
	for i := range 16384 - orderBenchLANs {
		raw := netip.MustParseAddr("2001:db8::").As16()
		binary.BigEndian.PutUint32(raw[4:], uint32(i))
		set(netip.PrefixFrom(netip.AddrFrom16(raw), 64))
	}
	return table, classes, routes
}

// orderBenchFilter is a filter over orderBenchExit's table after its first
// pass, its route source, and the routes the reconciler left in the kernel
func orderBenchFilter(b *testing.B) (*BorderFilter, *routeSource, []meshkernel.Route) {
	b.Helper()
	table, classes, routes := orderBenchExit()
	rt := borderRuntime(nil)
	rt.Sets = orderSets(classes, table)
	f := newBorderFilter(&egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("192.0.2.0/24")}}, rt, &fakeBorder{})
	if err := f.reconcile(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = f.Close() })
	return f, f.Routes(table).(*routeSource), routes
}

// One pass of the antispoof filter that moves no set at an exit at babel's
// limit, its none set of thousands of ranges, a route in the kernel for each
// entry and for each gap between two LANs inside the none class, and the
// promise of a Snapshot outstanding, over the fake backend: the
// pass takes what the reconciler's report and the source's promise keep out
// of the sets and walks the table for its report. The pass of the filter
// before the route source is measured apart, at that commit.
func BenchmarkBorderPassAtTheTablesLimit(b *testing.B) {
	f, src, routes := orderBenchFilter(b)
	src.Installed(routes)
	_ = src.Snapshot()
	b.ReportAllocs()
	for b.Loop() {
		// a sweep reads the filter back and reports, where a wake of the table moving nothing returns early
		f.trigger = "sweep"
		if err := f.reconcile(); err != nil {
			b.Fatal(err)
		}
	}
}

// What the reconciler's report costs at the same exit: Installed weighs the
// routes against the last pass's none sets under noneMu
func BenchmarkRouteReportAtTheTablesLimit(b *testing.B) {
	_, src, routes := orderBenchFilter(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = src.Snapshot()
		src.Installed(routes)
	}
}
