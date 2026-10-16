// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

// reconcilerStandIn is the reconciler a reload hands cap.table to, answering with refusal
type reconcilerStandIn struct {
	tables    []kernel.Table
	announced [][]netip.Prefix
	refusal   error
}

func (s *reconcilerStandIn) setTable(t kernel.Table, announced []netip.Prefix) error {
	s.tables = append(s.tables, t)
	s.announced = append(s.announced, announced)
	return s.refusal
}

// reloadOf is reloadFixture with a stand-in reconciler and a bus, its configuration changed by start
func reloadOf(t *testing.T, start func(*config.Config)) (*Client, string, *reconcilerStandIn, *events.Bus) {
	t.Helper()
	c, path := reloadFixture(t)
	start(c.config())
	reconciler, bus := &reconcilerStandIn{}, events.New()
	c.SetReconcilerTable(reconciler.setTable)
	c.events = bus
	return c, path, reconciler, bus
}

// lastReload is the attributes of the last daemon.reload recorded
func lastReload(t *testing.T, bus *events.Bus) map[string]string {
	t.Helper()
	reloads := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "daemon.reload" }, 0)
	if len(reloads) == 0 {
		t.Fatal("no reload was recorded")
	}
	return reloads[len(reloads)-1].Attrs
}

func TestReloadHandsTheReconcilerWhatAssignAnnouncedExpandsInto(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"an addition": func(c *config.Config) {
			c.Cap.Route = &babel.Routes{Announce: announce("fd00:1::1/64", "fd00:2::1/64")}
		},
		"a removal": func(c *config.Config) { c.Cap.Route = &babel.Routes{} },
		"a source-specific addition": func(c *config.Config) {
			c.Cap.Route = &babel.Routes{Announce: []schema.Announce{
				{Prefix: schema.MustPrefix("fd00:1::1/64")},
				{Prefix: schema.MustPrefix("fd00:2::1/64"), From: schema.MustPrefix("fd00:3::/64")},
			}}
		},
		"a host address change": func(c *config.Config) {
			c.Cap.Route = &babel.Routes{Announce: announce("fd00:1::2/64")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, path, reconciler, _ := reloadOf(t, func(old *config.Config) {
				old.Cap.Table = &kernel.Table{AssignAnnounced: true}
				old.Cap.Route = &babel.Routes{Announce: announce("fd00:1::1/64")}
			})
			next := *c.config()
			change(&next)
			writeConfig(t, path, &next)
			if err := c.ReloadFrom(path); err != nil {
				t.Fatalf("the reload was refused: %v", err)
			}
			if !slices.Equal(c.config().Routes().Announce, next.Routes().Announce) {
				t.Error("the reload did not take the new announcements")
			}
			if len(reconciler.tables) != 1 || !slices.Equal(reconciler.announced[0], next.Routes().Announced()) {
				t.Errorf("the reconciler was handed the announcements %v, want %v once", reconciler.announced, next.Routes().Announced())
			}
		})
	}
}

func TestReloadHandsAChangedTableToTheReconciler(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
		old.Cap.Table = &kernel.Table{
			Addresses: []schema.Prefix{schema.MustPrefix("10.66.0.5/32")},
			Rules:     []kernel.Rule{{To: schema.MustPrefix("198.18.104.0/24"), Table: kernel.DefaultTable, Priority: 100}},
		}
		old.Cap.Route = &babel.Routes{Announce: announce("fd00:1::1/64")}
	})
	next := *c.config()
	next.Cap.Table = &kernel.Table{
		Metric:          64,
		PrefSrc4:        schema.MustAddr("10.66.0.6"),
		Addresses:       []schema.Prefix{schema.MustPrefix("10.66.0.6/32")},
		AssignAnnounced: true,
		Rules:           []kernel.Rule{{To: schema.MustPrefix("198.18.105.0/24"), Table: kernel.DefaultTable, Priority: 100}},
		Reconcile:       schema.Duration(time.Minute),
		CaptureGrace:    schema.Duration(20 * time.Second),
	}
	next.Cap.Route = &babel.Routes{Announce: announce("fd00:2::1/64")}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload changing every field of cap.table a reload applies was refused: %v", err)
	}
	if len(reconciler.tables) != 1 || !reflect.DeepEqual(reconciler.tables[0], *c.config().Cap.Table) {
		t.Fatalf("the reconciler was handed %+v, want the cap.table the reload read once", reconciler.tables)
	}
	if want := next.Routes().Announced(); !slices.Equal(reconciler.announced[0], want) {
		t.Errorf("the reconciler was handed the announcements %v, want %v", reconciler.announced[0], want)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.route,cap.table" {
		t.Errorf("the reload was recorded as applying %q, want cap.route and cap.table", got)
	}

	// the same file again changes no capability, so the reconciler is not handed the table it runs
	if err := c.ReloadFrom(path); err != nil {
		t.Fatal(err)
	}
	if len(reconciler.tables) != 1 {
		t.Errorf("a reload that changed nothing handed the reconciler %d tables in all", len(reconciler.tables))
	}
	if attrs := lastReload(t, bus); attrs["applied"] != "" || attrs["err"] != "" {
		t.Errorf("a reload that changed nothing was recorded as %v", attrs)
	}
}

// a reload changing cap.route and leaving the addresses the table assigns as they were hands the reconciler nothing
func TestReloadHandsTheReconcilerNothingWhileTheAssignedAddressesStay(t *testing.T) {
	for name, move := range map[string]struct {
		table         *kernel.Table
		before, after []schema.Announce
	}{
		"announcements reordered with one written twice": {
			&kernel.Table{AssignAnnounced: true},
			announce("fd00:1::1/64", "fd00:2::1/64"), announce("fd00:2::1/64", "fd00:1::1/64", "fd00:2::1/64"),
		},
		"one announcement given a source": {
			&kernel.Table{AssignAnnounced: true},
			announce("fd00:1::1/64", "fd00:2::1/64"),
			[]schema.Announce{{Prefix: schema.MustPrefix("fd00:1::1/64")}, {Prefix: schema.MustPrefix("fd00:2::1/64"), From: schema.MustPrefix("fd00:3::/64")}},
		},
		"a table assigning nothing": {&kernel.Table{}, nil, announce("fd00:4::/64")},
		"no table":                  {nil, nil, announce("fd00:4::/64")},
		"assign_announced off":      {&kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("10.66.0.5/32")}}, announce("fd00:1::1/64"), announce("fd00:4::/64")},
	} {
		t.Run(name, func(t *testing.T) {
			c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
				old.Cap.Table = move.table
				old.Cap.Route = &babel.Routes{Announce: move.before}
			})
			next := *c.config()
			next.Cap.Route = &babel.Routes{Announce: move.after}
			writeConfig(t, path, &next)
			if err := c.ReloadFrom(path); err != nil {
				t.Fatalf("the reload was refused: %v", err)
			}
			if len(reconciler.tables) != 0 {
				t.Errorf("the reconciler was handed %+v for a table that did not change", reconciler.tables)
			}
			if got := lastReload(t, bus)["applied"]; got != "cap.route" {
				t.Errorf("the reload was recorded as applying %q, want cap.route alone", got)
			}
		})
	}
}

// heldReloadWait is how long a second reload is given to get through while the first is held inside the reconciler
// a reload nothing holds back takes a few milliseconds
const heldReloadWait = 300 * time.Millisecond

// two reloads of different files overlap, the first held between handing the reconciler its table and storing its file
// the node then stores the file whose table the reconciler took last
func TestOverlappingReloadsLeaveTheReconcilerOnTheStoredTable(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(old *config.Config) { old.Cap.Table = &kernel.Table{} })
	first, second := filepath.Join(filepath.Dir(path), "first.yaml"), filepath.Join(filepath.Dir(path), "second.yaml")
	for file, metric := range map[string]uint32{first: 32, second: 64} {
		next := *c.config()
		next.Cap.Table = &kernel.Table{Metric: metric}
		writeConfig(t, file, &next)
	}
	var mu sync.Mutex
	var running kernel.Table
	calls := 0
	entered, release := make(chan struct{}), make(chan struct{})
	c.SetReconcilerTable(func(table kernel.Table, _ []netip.Prefix) error {
		mu.Lock()
		running, calls = table, calls+1
		hold := calls == 1
		mu.Unlock()
		if hold {
			close(entered)
			<-release
		}
		return nil
	})
	done := make(chan error, 2)
	go func() { done <- c.ReloadFrom(first) }()
	<-entered
	go func() { done <- c.ReloadFrom(second) }()
	time.Sleep(heldReloadWait)
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("a reload failed: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if stored := c.config().Cap.Table.Metric; stored != running.Metric {
		t.Errorf("the node stores cap.table metric %d and the reconciler was last handed metric %d", stored, running.Metric)
	}
}

// joinedAndAnnounced is a reload that would change the trust document, the peers dialed and the announcements, as well as whatever the case changes
func joinedAndAnnounced(t *testing.T, c *Client, next *config.Config) {
	t.Helper()
	grown := readRegistry(t, c.config().Auth.Trust)
	grown[0].Nodes = append(slices.Clone(grown[0].Nodes), registry.Node{
		CommonName: "third",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, next.Auth.Trust, grown)
	next.Dial.To = append(slices.Clone(next.Dial.To), identity.MustParse("example/third:1"))
	next.Cap.Route = &babel.Routes{Announce: announce("fd00:9::/64")}
}

// changedNothing holds that a refused reload left the configuration, the trust document, the dialers, the announcements and the reconciler as they were
func changedNothing(t *testing.T, c *Client, old *config.Config, bus *events.Bus) {
	t.Helper()
	if c.config() != old {
		t.Error("the refused reload stored its configuration")
	}
	if _, err := c.index().Key(identity.MustParse("example/third")); err == nil {
		t.Error("the refused reload stored its trust document")
	}
	if got := dialerCount(c); got != 0 {
		t.Errorf("the refused reload started %d dialers", got)
	}
	if got := c.speaker.Stats().Originated; got != 0 {
		t.Errorf("the refused reload announces %d prefixes", got)
	}
	if attrs := lastReload(t, bus); attrs["err"] == "" || attrs["applied"] != "" {
		t.Errorf("the refused reload was recorded as %v", attrs)
	}
}

func TestReloadRefusesMovingTheTableByName(t *testing.T) {
	mesh := &kernel.VRF{Name: "mesh"}
	for name, move := range map[string]struct {
		old, next *kernel.Table
		naming    string
	}{
		"another id":          {&kernel.Table{}, &kernel.Table{ID: 201}, "cap.table id changed"},
		"another proto":       {&kernel.Table{}, &kernel.Table{Proto: kernel.DefaultProtocol + 1}, "cap.table proto changed"},
		"a vrf written":       {&kernel.Table{}, &kernel.Table{VRF: mesh}, "cap.table vrf changed"},
		"the vrf taken out":   {&kernel.Table{VRF: mesh}, &kernel.Table{}, "cap.table vrf changed"},
		"another vrf":         {&kernel.Table{VRF: mesh}, &kernel.Table{VRF: &kernel.VRF{Name: "other"}}, "cap.table vrf changed"},
		"the vrf made here":   {&kernel.Table{VRF: mesh}, &kernel.Table{VRF: &kernel.VRF{Name: "mesh", Create: true}}, "cap.table vrf changed"},
		"the block written":   {nil, &kernel.Table{}, "cap.table added"},
		"the block taken out": {&kernel.Table{}, nil, "cap.table removed"},
	} {
		t.Run(name, func(t *testing.T) {
			c, path, reconciler, bus := reloadOf(t, func(old *config.Config) { old.Cap.Table = move.old })
			old := c.config()
			next := *old
			next.Cap.Table = move.next
			joinedAndAnnounced(t, c, &next)
			writeConfig(t, path, &next)
			if err := c.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), move.naming) {
				t.Fatalf("the reload was refused with %v, want it to say %q", err, move.naming)
			}
			if len(reconciler.tables) != 0 {
				t.Errorf("the refused reload handed the reconciler %+v", reconciler.tables)
			}
			changedNothing(t, c, old, bus)
		})
	}
}

// the reconciler is the last to refuse, so its refusal leaves everything a reload applies as it was
func TestReloadTheReconcilerRefusesChangesNothing(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) { old.Cap.Table = &kernel.Table{} })
	reconciler.refusal = errors.New("kernel: a refusal")
	old := c.config()
	next := *old
	next.Cap.Table = &kernel.Table{Metric: 32}
	joinedAndAnnounced(t, c, &next)
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); !errors.Is(err, reconciler.refusal) {
		t.Fatalf("the reload answered %v, want the reconciler's refusal", err)
	}
	if len(reconciler.tables) != 1 {
		t.Errorf("the reconciler was asked %d times, want once", len(reconciler.tables))
	}
	changedNothing(t, c, old, bus)
}

// a translator with return set resolved an auto source among the mesh addresses once, at startup
// a reload is refused when the new addresses resolve another source or none, and applied when they resolve the same
func TestReloadRefusesMovingTheSourceCapEgressReturnsUnder(t *testing.T) {
	auto := &egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("198.51.100.0/24")}, Return: true}
	written := &egress.Egress{Advertise: auto.Advertise, Return: true, Source4: egress.Source{Addr: netip.MustParseAddr("10.66.0.5")}}
	noReturn := &egress.Egress{Advertise: auto.Advertise}
	assigning := func(list ...string) *kernel.Table {
		table := &kernel.Table{}
		for _, prefix := range list {
			table.Addresses = append(table.Addresses, schema.MustPrefix(prefix))
		}
		return table
	}
	node := func(exit *egress.Egress, table *kernel.Table, announced ...string) *config.Config {
		return &config.Config{Cap: config.Caps{Egress: exit, Table: table, Route: &babel.Routes{Announce: announce(announced...)}}}
	}
	// one IPv4 mesh address and an auto source, a node that starts
	start := node(auto, assigning("10.66.0.5/32"))
	for name, move := range map[string]struct {
		next   *config.Config
		naming string
	}{
		"the address renumbered":        {node(auto, assigning("10.66.0.6/32")), "cap.route or cap.table moved the mesh address cap.egress return translates to"},
		"cap.table assigning a second":  {node(auto, assigning("10.66.0.5/32", "10.66.0.6/32")), "egress.source4"},
		"cap.route announcing a second": {node(auto, assigning("10.66.0.5/32"), "10.66.1.6/32"), "egress.source4"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := reloadable(start, move.next); err == nil || !strings.Contains(err.Error(), move.naming) {
				t.Errorf("the reload was refused with %v, want it to say %q", err, move.naming)
			}
		})
	}
	for name, move := range map[string]struct{ old, next *config.Config }{
		"a written source beside another address renumbered": {
			node(written, assigning("10.66.0.5/32", "10.66.0.7/32")), node(written, assigning("10.66.0.5/32", "10.66.0.8/32")),
		},
		"an address of a family the node does not advertise": {start, node(auto, assigning("10.66.0.5/32", "fd00:66::5/128"))},
		"a link-local address beside it":                     {start, node(auto, assigning("10.66.0.5/32", "169.254.0.5/32"))},
		"a range rather than an address":                     {start, node(auto, assigning("10.66.0.5/32", "10.66.2.0/24"))},
		"the announced address no longer assigned as well": {
			node(auto, &kernel.Table{AssignAnnounced: true}, "10.66.0.5/32"), node(auto, &kernel.Table{}, "10.66.0.5/32"),
		},
		"another metric": {start, node(auto, &kernel.Table{Metric: 64, Addresses: start.Cap.Table.Addresses})},
		"no return":      {node(noReturn, assigning("10.66.0.5/32")), node(noReturn, assigning("10.66.0.6/32"))},
	} {
		t.Run(name, func(t *testing.T) {
			if err := reloadable(move.old, move.next); err != nil {
				t.Errorf("a reload leaving the translator's source where it was was refused: %v", err)
			}
		})
	}
}

// speakerRecording gives c a speaker of its configuration that records on bus
func speakerRecording(t *testing.T, c *Client, bus *events.Bus) {
	t.Helper()
	speaker, err := babel.New(c.config().Babel(), c.config().Routes(), babel.Runtime{Events: bus}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	c.speaker = speaker
}

// steering is a cap.segment steering one source through via, which sizes the tun by the length of via
func steering(via ...string) *srv6.Segments {
	addresses := make([]schema.Addr, 0, len(via))
	for _, address := range via {
		addresses = append(addresses, schema.MustAddr(address))
	}
	return &srv6.Segments{Source: schema.MustAddr("3fff:1:69c:8c0::1"),
		Steer: []srv6.Steer{{From: schema.MustPrefix("3fff:a::1/128"), Via: addresses}}}
}

// segmentsOf gives c a mesh holding the tables of its cap.segment, as New installs them
func segmentsOf(t *testing.T, c *Client) {
	t.Helper()
	segments, steering, err := c.config().Segments().Tables()
	if err != nil {
		t.Fatal(err)
	}
	c.Mesh = netstack.NewRoutesOnly()
	c.Mesh.SetSegments(segments)
	c.Mesh.SetSteering(steering)
}

func TestReloadHandsTheSpeakerAChangedCapBabel(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	speakerRecording(t, c, bus)
	next := *c.config()
	next.Cap.Babel = &babel.Config{Hello: schema.Duration(2 * time.Second)}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a changed cap.babel was refused: %v", err)
	}
	if got := recorded(bus, "babel.config.applied"); len(got) != 1 || got[0].Attrs["hello"] != "2s" {
		t.Errorf("the speaker recorded %v, want one change to a 2s hello", got)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.babel" {
		t.Errorf("the reload was recorded as applying %q, want cap.babel", got)
	}
}

// a reload installs the tables cap.segment builds, and a steering stopped over the control socket stays stopped with the new table
func TestReloadInstallsTheSegmentTablesItBuilds(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(old *config.Config) { old.Cap.Segment = steering("3fff:1:69c:98d6::1") })
	segmentsOf(t, c)
	c.Mesh.SetSteeringEnabled(false)
	next := *c.config()
	next.Cap.Segment = steering("3fff:1:69c:6c46::1")
	next.Cap.Segment.Local = []srv6.Segment{{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a steering of the same length was refused: %v", err)
	}
	segments, steered, err := next.Segments().Tables()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Mesh.Segments().Segments(); !slices.Equal(got, segments.Segments()) {
		t.Errorf("the mesh answers for %v, want %v", got, segments.Segments())
	}
	if got := c.Mesh.Steering().Entries(); !slices.Equal(got, steered.Entries()) {
		t.Errorf("the mesh steers %v, want %v", got, steered.Entries())
	}
	if c.Mesh.SteeringEnabled() {
		t.Error("the reload started the steering an operator had stopped")
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.segment" {
		t.Errorf("the reload was recorded as applying %q, want cap.segment", got)
	}
}

// a steering whose longest list needs another tun MTU applies in place, the device moving with it
func TestReloadAppliesASteeringThatNeedsAnotherMTU(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(old *config.Config) { old.Cap.Segment = steering("3fff:1:69c:98d6::1") })
	segmentsOf(t, c)
	for _, via := range [][]string{
		{"3fff:1:69c:98d6::1", "3fff:1:69c:6c46::1"},
		{"3fff:1:69c:6c46::1"},
	} {
		next := *c.config()
		next.Cap.Segment = steering(via...)
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err != nil {
			t.Fatalf("a steering through %d segments was refused: %v", len(via), err)
		}
		_, steered, err := next.Segments().Tables()
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Mesh.Steering().Entries(); !slices.Equal(got, steered.Entries()) {
			t.Errorf("the mesh steers %v, want %v", got, steered.Entries())
		}
		if got := lastReload(t, bus)["applied"]; got != "cap.segment" {
			t.Errorf("the reload was recorded as applying %q, want cap.segment", got)
		}
	}
}

// a link.mtu within the read buffers the mesh opened with applies in place
func TestReloadAppliesALinkMTUWithinTheReadBuffers(t *testing.T) {
	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	c.Mesh = netstack.NewRoutesOnly()
	next := *c.config()
	next.Link.MTU = 2048
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a link.mtu of 2048 under buffers of 2048 bytes was refused: %v", err)
	}
	if got := c.config().Link.SessionMTU(); got != 2048 {
		t.Errorf("the node runs link.mtu %d, want 2048", got)
	}
	if got := lastReload(t, bus)["applied"]; got != "link.mtu" {
		t.Errorf("the reload was recorded as applying %q, want link.mtu", got)
	}
}

// a reload moves the device to the new link.mtu less the longest list the new steering carries
// from the device the running link.mtu and steering leave
// the expected sizes count an outer IPv6 header, the fixed part of the segment routing header and 16 bytes a segment, RFC 8754
func TestReloadPlansTheTUNAtLinkMTULessTheLongestList(t *testing.T) {
	header := func(segments int) int { return 40 + 8 + 16*segments }
	node := func(mtu uint16, via ...string) func(*config.Config) {
		return func(c *config.Config) {
			c.Link.MTU = mtu
			c.Cap.Segment = nil
			if len(via) > 0 {
				c.Cap.Segment = steering(via...)
			}
		}
	}
	a, b := "3fff:1:69c:98d6::1", "3fff:1:69c:6c46::1"
	for name, move := range map[string]struct {
		old, next func(*config.Config)
		from, to  int
	}{
		"a list one segment longer":             {node(0, a), node(0, a, b), 1400 - header(1), 1400 - header(2)},
		"a list one segment shorter":            {node(0, a, b), node(0, a), 1400 - header(2), 1400 - header(1)},
		"the steering taken out":                {node(0, a), node(0), 1400 - header(1), 1400},
		"link.mtu raised under one list":        {node(1400, a), node(2000, a), 1400 - header(1), 2000 - header(1)},
		"link.mtu lowered with the list longer": {node(2000, a), node(1500, a, b), 2000 - header(1), 1500 - header(2)},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _, _ := reloadOf(t, move.old)
			segmentsOf(t, c)
			next := *c.config()
			move.next(&next)
			plan, err := c.planTUN(c.config(), &next)
			if err != nil {
				t.Fatalf("the plan was refused: %v", err)
			}
			if plan.from != move.from || plan.to != move.to {
				t.Errorf("the plan moves the tun from %d to %d bytes, want %d to %d", plan.from, plan.to, move.from, move.to)
			}
		})
	}
}

// the read buffers are sized once for the link.mtu the mesh opened with, so a link.mtu past them is refused before anything else applies
// the refusal names both sizes and says a restart applies it
func TestReloadRefusesALinkMTUPastTheReadBuffersAndChangesNothing(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
		old.Cap.Segment = steering("3fff:1:69c:98d6::1")
		old.Cap.Table = &kernel.Table{}
	})
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	c.hub = hub
	segments, steered := c.Mesh.Segments(), c.Mesh.Steering()
	old := c.config()
	next := *old
	next.Link.MTU = 9000
	next.Cap.Segment = steering("3fff:1:69c:98d6::1", "3fff:1:69c:6c46::1")
	next.Cap.Segment.Local = []srv6.Segment{{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd}}
	next.Cap.Babel = &babel.Config{Hello: schema.Duration(2 * time.Second)}
	next.Cap.Table = &kernel.Table{Metric: 32}
	next.Link.Listen = true
	joinedAndAnnounced(t, c, &next)
	writeConfig(t, path, &next)
	err = c.ReloadFrom(path)
	if err == nil {
		t.Fatal("a link.mtu past the read buffers the mesh opened with was applied")
	}
	for _, want := range []string{"9000", "2048", "restart to apply"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q, which does not say %s", err, want)
		}
	}
	changedNothing(t, c, old, bus)
	if c.Mesh.Segments() != segments || c.Mesh.Steering() != steered {
		t.Error("the refused reload installed segment tables")
	}
	if got := recorded(bus, "babel.config.applied"); len(got) != 0 {
		t.Errorf("the refused reload reached the speaker: %v", got)
	}
	if len(reconciler.tables) != 0 {
		t.Errorf("the refused reload handed the reconciler %+v", reconciler.tables)
	}
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	if c.responder != nil {
		t.Error("the refused reload started the responder")
	}
}

// a link.mtu past the read buffers is refused where the steering added with it keeps the device at its MTU
// link.mtu 2000 with nothing steered runs the device at 2000
// link.mtu 2064 under one segment runs it at 2000 as well
// a steered read of 2000 bytes would then grow to 2064 bytes in a buffer of 2048
func TestReloadRefusesALinkMTUPastTheReadBuffersWhereTheDeviceStays(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(old *config.Config) { old.Link.MTU = 2000 })
	segmentsOf(t, c)
	old, steered := c.config(), c.Mesh.Steering()
	next := *old
	next.Link.MTU = 2064
	next.Cap.Segment = steering("3fff:1:69c:98d6::1")
	_, nextSteering, err := next.Segments().Tables()
	if err != nil {
		t.Fatal(err)
	}
	device, err := steeredMTU(next.Link.SessionMTU(), nextSteering)
	if err != nil {
		t.Fatal(err)
	}
	if device != 2000 {
		t.Fatalf("the next configuration runs the device at %d bytes, want the 2000 it runs at now", device)
	}
	writeConfig(t, path, &next)
	err = c.ReloadFrom(path)
	if err == nil {
		t.Fatal("a link.mtu of 2064 past read buffers of 2048 bytes was applied")
	}
	for _, want := range []string{"2064", "2048", "restart to apply"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q, which does not say %s", err, want)
		}
	}
	if c.config() != old || c.Mesh.Steering() != steered {
		t.Error("the refused reload stored its configuration or installed its steering")
	}
}

// longDialRetry keeps a dialer whose session went from dialing again within convergeBudget, so only a wake brings it back
const longDialRetry = 10 * time.Minute

// listenNode is one node of a mesh whose nodes answer and dial as each says
type listenNode struct {
	// org is example where a test names none
	org    string
	name   string
	port   uint16
	listen bool
	dials  []*listenNode
	// announce is the prefix the node puts into the mesh, none where it is invalid
	announce netip.Prefix
	// transit writes cap.transit enable = true, where the node otherwise leaves the block out
	transit    bool
	client     *Client
	events     *events.Bus
	configPath string
	keyPath    string
	trustPath  string
}

// writeListenConfig writes node's config file with link.listen at listen and loads it back
func writeListenConfig(t *testing.T, node *listenNode, listen bool) *config.Config {
	t.Helper()
	var body strings.Builder
	fmt.Fprintf(&body, "node: %s/%s\nauth:\n  key: %s\n  trust: %s\n"+
		"link:\n  port: %d\n  endpoints:\n    - serial: \"0\"\n      family: ip4\n  listen: %t\n"+
		"cap:\n  babel:\n    hello: 200ms\n    update: 400ms\n",
		node.org, node.name, node.keyPath, node.trustPath, node.port, listen)
	if node.transit {
		body.WriteString("  transit:\n    enable: true\n")
	}
	if node.announce.IsValid() {
		fmt.Fprintf(&body, "  route:\n    announce: [%q]\n", node.announce)
	}
	if len(node.dials) > 0 {
		body.WriteString("dial:\n  to:\n")
		for _, peer := range node.dials {
			fmt.Fprintf(&body, "    - %s/%s:0\n", peer.org, peer.name)
		}
	}
	if err := os.WriteFile(node.configPath, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(node.configPath)
	if err != nil {
		t.Fatalf("%s: %v", node.name, err)
	}
	return cfg
}

// listenMesh builds a client for each node on 127.0.0.1 under one key for each organization, with names unique to this mesh
func listenMesh(t *testing.T, nodes ...*listenNode) {
	t.Helper()
	retryPort(t, "bind", func() error { return tryListenMesh(t, nodes) })
}

func tryListenMesh(t *testing.T, nodes []*listenNode) error {
	t.Helper()
	mesh := meshCounter.Add(1)
	loopback := "127.0.0.1"
	var document registry.Registry
	keys := make(map[string]ed25519.PrivateKey)
	for _, node := range nodes {
		node.org = cmp.Or(node.org, "example")
		node.name = fmt.Sprintf("%s-%d", strings.SplitN(node.name, "-", 2)[0], mesh)
		node.port = freeUDPPort(t)
		block := slices.IndexFunc(document, func(org registry.Organization) bool { return org.Organization == node.org })
		if block < 0 {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keys[node.org] = private
			document = append(document, registry.Organization{PublicKey: keyPEM(public), Organization: node.org})
			block = len(document) - 1
		}
		document[block].Nodes = append(document[block].Nodes, registry.Node{CommonName: node.name, Endpoints: []registry.Endpoint{{
			SerialNumber: "0", AddressFamily: "ip4", Address: &loopback, Port: node.port,
		}}})
	}
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "registry.json")
	writeRegistry(t, trustPath, document)
	for org, private := range keys {
		writeKey(t, filepath.Join(dir, org+".pem"), private)
	}
	for i, node := range nodes {
		node.configPath, node.keyPath, node.trustPath = filepath.Join(dir, node.name+".yaml"), filepath.Join(dir, node.org+".pem"), trustPath
		node.events = events.New()
		client, err := newClient(writeListenConfig(t, node, node.listen), keys[node.org], trust(t, document), netstack.NewRoutesOnly(), nil, node.events)
		if err != nil {
			for _, built := range nodes[:i] {
				built.client.Close()
			}
			return fmt.Errorf("%s: %w", node.name, err)
		}
		node.client = client
		t.Cleanup(client.Close)
	}
	return nil
}

// runListen starts each node as run does for a loopbackNode
func runListen(t *testing.T, nodes ...*listenNode) func() {
	t.Helper()
	loopbacks := make([]*loopbackNode, 0, len(nodes))
	for _, node := range nodes {
		loopbacks = append(loopbacks, &loopbackNode{name: node.name, client: node.client})
	}
	_, stop := run(t, loopbacks...)
	return stop
}

// pathTo is the name of the session or dialer from node to peer
func pathTo(peer *listenNode) string { return peer.org + "/" + peer.name + ":0@0" }

// sessionEvents is every event of kind node recorded for the session with peer
func sessionEvents(node, peer *listenNode, kind string) []control.Event {
	return node.events.Recorded(func(got, path string, _ []slog.Attr) bool { return got == kind && path == pathTo(peer) }, 0)
}

// held is the session node holds with peer, or nil
func held(node, peer *listenNode) *ike.Session {
	node.client.sessions.mu.Lock()
	defer node.client.sessions.mu.Unlock()
	if live := node.client.sessions.live[pathTo(peer)]; live != nil {
		return live.session
	}
	return nil
}

// hub answers a and dials d, so it holds one session it answered and one it dialed
// turning link.listen off closes the answered one with a Delete, keeps the dialed one and wakes the dialer that brings a back
// an IKE_SA_INIT arriving while it is off is refused, and turning it on again answers the next dial and not that one
func TestReloadTurningListenOffClosesAnsweredSessionsAndOnAnswersAgain(t *testing.T) {
	a, hub, d := &listenNode{name: "a", listen: true}, &listenNode{name: "h", listen: true}, &listenNode{name: "d", listen: true}
	a.dials, hub.dials = []*listenNode{hub}, []*listenNode{d}
	listenMesh(t, a, hub, d)
	a.client.dialRetry, hub.client.dialRetry = longDialRetry, longDialRetry
	runListen(t, a, hub, d)
	waitFor(t, convergeBudget, "hub's dialed session with d", func() bool { return held(hub, d) != nil })
	// a session is recorded only once it holds its path
	waitFor(t, convergeBudget, "hub to record its answered session with a", func() bool {
		return len(sessionEvents(hub, a, "ike.session.established")) > 0
	})
	if got := sessionEvents(hub, a, "ike.session.established"); len(got) != 1 || got[0].Attrs["role"] != "responder" {
		t.Fatalf("hub holds a by %v, want the one session it answered, so this proves nothing", got)
	}
	dialed := held(hub, d)
	// hub dials a as well from here, and its dialer stands down behind the session a opened
	hub.dials = []*listenNode{a, d}
	if err := hub.client.ReloadFrom(writeListenPath(t, hub, true)); err != nil {
		t.Fatalf("dialing a as well was refused: %v", err)
	}
	// a dialer that first looks after listen went off finds no session and dials without the wake
	waitFor(t, convergeBudget, "hub's dialer for a to stand down", dialerStandingDown)

	if err := hub.client.ReloadFrom(writeListenPath(t, hub, false)); err != nil {
		t.Fatalf("turning link.listen off was refused: %v", err)
	}
	if got := recorded(hub.events, "responder.changed"); len(got) != 1 || got[0].Attrs["listen"] != "false" || got[0].Attrs["closed"] != "1" {
		t.Errorf("turning listen off was recorded as %v, want one answered session closed", got)
	}
	if got := lastReload(t, hub.events)["applied"]; got != "link.listen" {
		t.Errorf("the reload was recorded as applying %q, want link.listen", got)
	}
	// without the Delete, a would hold its session until its liveness check gave up, 10 seconds idle and 62 of retransmissions
	waitFor(t, convergeBudget, "a to be told its session is gone", func() bool {
		return len(sessionEvents(a, hub, "ike.session.ended")) > 0
	})
	waitFor(t, convergeBudget, "hub's dialer for a to be woken", func() bool {
		return len(sessionEvents(hub, a, "dial.woken")) > 0
	})
	waitFor(t, convergeBudget, "hub to dial a again, which only the wake can do in time", func() bool {
		established := sessionEvents(hub, a, "ike.session.established")
		return len(established) == 2 && established[1].Attrs["role"] == "initiator" && held(hub, a) != nil
	})
	if held(hub, d) != dialed || len(sessionEvents(hub, d, "ike.session.ended")) != 0 {
		t.Error("turning listen off closed a session hub dialed")
	}
	stale, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	refused := hub.client.hub.Refused()
	if _, err := stale.WriteToUDP(unclaimedInit(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(hub.port)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "hub to refuse an IKE_SA_INIT while listen is off", func() bool { return hub.client.hub.Refused() > refused })

	if err := hub.client.ReloadFrom(writeListenPath(t, hub, true)); err != nil {
		t.Fatalf("turning link.listen on was refused: %v", err)
	}
	if _, err := a.client.Redial(t.Context(), hub.name, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "hub to answer a's next dial", func() bool {
		established := sessionEvents(hub, a, "ike.session.established")
		return len(established) == 3 && established[2].Attrs["role"] == "responder" && held(hub, a) != nil
	})
	// the responder reads the hub's queue in arrival order
	// an IKE_SA_INIT held over from listen off would have failed before a's dial was answered
	for _, failed := range recorded(hub.events, "ike.handshake.failed") {
		if from, err := netip.ParseAddrPort(failed.Attrs["from"]); err == nil && int(from.Port()) == stale.LocalAddr().(*net.UDPAddr).Port {
			t.Errorf("turning listen on answered an IKE_SA_INIT that arrived while it was off: %v", failed)
		}
	}
}

// writeListenPath rewrites node's config with link.listen at listen and returns its path
func writeListenPath(t *testing.T, node *listenNode, listen bool) string {
	t.Helper()
	writeListenConfig(t, node, listen)
	return node.configPath
}

// droppedFrom indexes the trust document node read with peer's node taken out, as a reload that dropped peer stores it
func droppedFrom(t *testing.T, node, peer *listenNode) *registry.Index {
	t.Helper()
	document := readRegistry(t, node.trustPath)
	for i := range document {
		document[i].Nodes = slices.DeleteFunc(document[i].Nodes, func(listed registry.Node) bool { return listed.CommonName == peer.name })
	}
	return trust(t, document)
}

// a responder asks the trust document in force on each handshake, so one a reload stored refuses the next handshake of a node it dropped
func TestResponderAnswersEachHandshakeUnderTheStoredDocument(t *testing.T) {
	a, h := &listenNode{name: "a"}, &listenNode{name: "h", listen: true}
	a.dials = []*listenNode{h}
	listenMesh(t, a, h)
	runListen(t, a, h)
	// a redial before a adopts its session finds none to close, and the wake waits until that session ends
	heldAtBothEnds(t, a, h)
	h.client.storeIndex(droppedFrom(t, h, a))
	if _, err := a.client.Redial(t.Context(), h.name, false); err != nil {
		t.Fatal(err)
	}
	refusal := fmt.Sprintf("notify type %d", ike.N_AUTHENTICATION_FAILED)
	refused := func() bool {
		return slices.ContainsFunc(sessionEvents(a, h, "dial.failed"), func(failed control.Event) bool { return strings.Contains(failed.Attrs["err"], refusal) })
	}
	waitFor(t, convergeBudget, "a's next handshake with h to be answered", func() bool {
		return refused() || len(sessionEvents(a, h, "ike.session.established")) > 1
	})
	if !refused() {
		t.Error("h admitted a handshake from a node the document it stored had dropped")
	}
}

// heldAtBothEnds waits until node and peer each hold their session with the other, and fails at once on a session either end refused
func heldAtBothEnds(t *testing.T, node, peer *listenNode) {
	t.Helper()
	waitFor(t, convergeBudget, fmt.Sprintf("the session of %s and %s held at both ends", node.name, peer.name), func() bool {
		for _, end := range [][2]*listenNode{{node, peer}, {peer, node}} {
			if refused := sessionEvents(end[0], end[1], "ike.session.revoked"); len(refused) > 0 {
				t.Fatalf("%s refused its session with %s: %s", end[0].name, end[1].name, refused[0].Attrs["err"])
			}
		}
		return held(node, peer) != nil && held(peer, node) != nil
	})
}

// h answers a and dials d, nodes of another organization under another key, and each session holds the key that verified its peer
// so both come up, and a reload that keeps every key keeps both
func TestSessionsWithAnotherOrganizationSurviveAReloadKeepingEveryKey(t *testing.T) {
	a, h, d := &listenNode{org: "alpha", name: "a"}, &listenNode{org: "bravo", name: "h", listen: true}, &listenNode{org: "alpha", name: "d", listen: true}
	a.dials, h.dials = []*listenNode{h}, []*listenNode{d}
	listenMesh(t, a, h, d)
	runListen(t, a, h, d)
	heldAtBothEnds(t, a, h)
	heldAtBothEnds(t, h, d)
	answered, dialed := held(h, a), held(h, d)
	if err := h.client.ReloadFrom(h.configPath); err != nil {
		t.Fatalf("a reload keeping every key was refused: %v", err)
	}
	if held(h, a) != answered || held(h, d) != dialed {
		t.Error("a reload keeping every key closed a session with another organization")
	}
	if got := recorded(h.events, "ike.session.revoked"); len(got) != 0 {
		t.Errorf("a reload keeping every key revoked %v", got)
	}
}

// a handshake that asked the trust before a reload and is adopted after that reload's sweep answers to the document the reload stored
func TestSessionAdoptedAfterAReloadsSweepAnswersToTheStoredDocument(t *testing.T) {
	a, h := &listenNode{name: "a"}, &listenNode{name: "h", listen: true}
	a.dials = []*listenNode{h}
	listenMesh(t, a, h)
	a.client.dialRetry = longDialRetry
	set := h.client.sessions
	set.mu.Lock()
	locked := true
	defer func() {
		if locked {
			set.mu.Unlock()
		}
	}()
	runListen(t, a, h)
	waitFor(t, convergeBudget, "h's first answered session waiting for its session set in adopt", waitingInAdopt)
	if len(set.live) != 0 {
		t.Fatalf("h holds %d sessions while its first waits in adopt, want none for a sweep to reach", len(set.live))
	}
	h.client.storeIndex(droppedFrom(t, h, a))
	set.mu.Unlock()
	locked = false
	waitFor(t, convergeBudget, "h to adopt or refuse the session", func() bool {
		return len(sessionEvents(h, a, "ike.session.established")) > 0 || len(sessionEvents(a, h, "ike.session.ended")) > 0
	})
	if held(h, a) != nil {
		t.Error("h holds a session from a node the document it stored had dropped")
	}
	want := map[string]string{"reason": "handshake", "peer": "example/" + a.name + ":0",
		"endpoint": netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.port).String(), "err": "registry: example/" + a.name + " is not in the trust document"}
	if got := sessionEvents(h, a, "ike.session.revoked"); len(got) != 1 || !maps.Equal(got[0].Attrs, want) {
		t.Errorf("h recorded %v, want one revocation with %v", got, want)
	}
}

// reloads turning the responder off and on while the node shuts down start nothing behind the wait in Run
func TestReloadTurningListenWhileTheNodeStopsDoesNotPanic(t *testing.T) {
	node, peer := &listenNode{name: "n", listen: true}, &listenNode{name: "p", listen: true}
	node.dials = []*listenNode{peer}
	listenMesh(t, node, peer)
	stop := runListen(t, node)
	off, on := filepath.Join(filepath.Dir(node.configPath), "off.yaml"), node.configPath
	body, err := os.ReadFile(on)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, []byte(strings.Replace(string(body), "listen: true", "listen: false", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var reloaded atomic.Int64
	go func() {
		defer close(done)
		for i := range racingReloads {
			path := off
			if i%2 == 1 {
				path = on
			}
			if err := node.client.ReloadFrom(path); err != nil {
				t.Errorf("a reload failed: %v", err)
				return
			}
			reloaded.Add(1)
		}
	}()
	waitFor(t, convergeBudget, "the first reloads", func() bool { return reloaded.Load() >= racingReloads/4 })
	stop()
	<-done
	// once Run has returned, a reload turning listen on starts nothing that its wait would have had to cover
	for _, path := range []string{off, on} {
		if err := node.client.ReloadFrom(path); err != nil {
			t.Fatal(err)
		}
	}
	node.client.dialersMu.Lock()
	defer node.client.dialersMu.Unlock()
	if node.client.responder != nil {
		t.Error("a reload after the node stopped started a responder")
	}
}

// racingReloads is how many reloads race the stop, enough that some land before it, some during and some after
const racingReloads = 200

// a reload turning link.listen on before Run leaves Run with the responder it started rather than a second one on the hub
// turning listen off then stops that one responder
func TestReloadTurningListenOnBeforeRunStartsOneResponder(t *testing.T) {
	node, peer := &listenNode{name: "n"}, &listenNode{name: "p", listen: true}
	node.dials = []*listenNode{peer}
	listenMesh(t, node, peer)
	if err := node.client.ReloadFrom(writeListenPath(t, node, true)); err != nil {
		t.Fatalf("turning link.listen on was refused: %v", err)
	}
	node.client.dialersMu.Lock()
	first := node.client.responder
	node.client.dialersMu.Unlock()
	if first == nil {
		t.Fatal("turning link.listen on started no responder, so this proves nothing")
	}
	runListen(t, node)
	// Run starts its speaker after its own start of the responder
	waitFor(t, convergeBudget, "Run to start its speaker", func() bool { return node.client.speaker.Passes() > 0 })
	if err := node.client.ReloadFrom(writeListenPath(t, node, false)); err != nil {
		t.Fatalf("turning link.listen off was refused: %v", err)
	}
	select {
	case <-first.done:
	default:
		t.Error("turning link.listen off left the responder the first reload started reading the hub")
	}
}

// link.listen turned off right after it went on stops a responder that may not have reached the hub yet
// the hub refuses unclaimed IKE afterward rather than queueing it for a responder started later
func TestListenTurnedOffRightAfterOnLeavesTheHubRefusing(t *testing.T) {
	node, peer := &listenNode{name: "n"}, &listenNode{name: "p", listen: true}
	node.dials = []*listenNode{peer}
	listenMesh(t, node, peer)
	c := node.client
	off := c.config()
	on := *off
	on.Link.Listen = true
	c.cfg.Store(&on)
	c.syncResponder()
	c.cfg.Store(off)
	c.syncResponder()

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	refused := c.hub.Refused()
	if _, err := sender.WriteToUDP(unclaimedInit(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(node.port)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the hub to refuse an IKE_SA_INIT while listen is off", func() bool { return c.hub.Refused() > refused })
}
