// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
)

// A range of this node's own that another router announces too, inside an
// exemption, is reported once, at warning with an event saying the range is
// this node's own and naming the offer's router-id and nothing carved or
// routed, and its end at info, each line its own and not the carved
// conflict's, and neither naming own, which the event alone carries
func TestBorderOwnCopyConflictIsReportedOnceAsThisNodesOwn(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	p := netip.MustParsePrefix
	conflict := egress.ExemptConflict{Exemption: egress.Exemption{Interface: "eth1", Prefix: p("198.18.0.0/25")}, Prefix: p("198.18.0.0/25"), RouterID: "0102030405060708", Own: true}
	derived := egress.BorderSets{Conflicts: []egress.ExemptConflict{conflict}}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	cfg := overlay(t)
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: []schema.Prefix{schema.MustPrefix("198.18.0.0/25")}}}}
	f, err := startBorderFilter(cfg, rt, &fakeBorder{})
	if err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	derived = egress.BorderSets{}
	f.reconcile()
	f.reconcile()
	var got []map[string]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0) {
		got = append(got, event.Attrs)
	}
	want := []map[string]string{{"exemption": "198.18.0.0/25", "interface": "eth1", "prefix": "198.18.0.0/25", "own": "true", "router_id": "0102030405060708"}}
	if !slices.EqualFunc(got, want, maps.Equal) {
		t.Errorf("recorded antispoof.conflict %v, want %v", got, want)
	}
	if strings.Count(lines.String(), "level=WARN msg=\"antispoof admits this node's range though another router announces it too\"") != 1 ||
		strings.Count(lines.String(), "level=INFO msg=\"antispoof no longer sees another router announce this node's range\"") != 1 ||
		strings.Contains(lines.String(), "drops part of an exemption") || strings.Contains(lines.String(), " own=") {
		t.Errorf("the copy was not logged once each way as this node's own:\n%s", lines.String())
	}
}
