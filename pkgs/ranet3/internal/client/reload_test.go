// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
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
	grown := slices.Clone(c.registry())
	grown[0].Nodes = append(slices.Clone(grown[0].Nodes), registry.Node{
		CommonName: "third",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, next.Auth.Trust, grown)
	next.Dial.To = append(slices.Clone(next.Dial.To), config.Peer{Org: "example", Name: "third", Serial: "1"})
	next.Cap.Route = &babel.Routes{Announce: announce("fd00:9::/64")}
}

// changedNothing holds that a refused reload left the configuration, the trust document, the dialers, the announcements and the reconciler as they were
func changedNothing(t *testing.T, c *Client, old *config.Config, bus *events.Bus) {
	t.Helper()
	if c.config() != old {
		t.Error("the refused reload stored its configuration")
	}
	if _, _, ok := c.registry().FindNode("example", "third"); ok {
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
