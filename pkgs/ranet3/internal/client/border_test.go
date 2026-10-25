// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// borderRecord is the border filter as the node drives one, recording each
// overlay and SID list a reload hands it
type borderRecord struct {
	mu      sync.Mutex
	border  egress.Border
	sids    []netip.Addr
	handed  int
	refusal error
	debug   egress.BorderDebug
}

func (b *borderRecord) SetConfig(cfg egress.Border, sids []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handed++
	if b.refusal != nil {
		return b.refusal
	}
	b.border, b.sids = cfg, slices.Clone(sids)
	return nil
}

func (b *borderRecord) Capability() egress.Border {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.border
}

func (b *borderRecord) SIDs() []netip.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.sids)
}

func (b *borderRecord) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.handed
}

func (*borderRecord) Inside() []string { return []string{"ranet3", "lo"} }

func (*borderRecord) Where() string { return "nftables table inet ranet3 chain border" }

func (*borderRecord) Stats() egress.BorderStats {
	return egress.BorderStats{At: time.Unix(1_790_000_000, 0), Ready: true, Installed: 7, Dropped: egress.BorderDrops{Source4: 3, RoutingHeader: 1}}
}

func (b *borderRecord) Debug() egress.BorderDebug { return b.debug }

// borderOf is a cap.border of the prefixes given
func borderOf(prefixes ...string) *egress.Border {
	border := &egress.Border{}
	for _, prefix := range prefixes {
		border.Overlay = append(border.Overlay, schema.MustPrefix(prefix))
	}
	return border
}

// an exit whose border's chain is not read back withdraws its SID and reads
// neither family ready, whatever the translator holds, the status saying why,
// and both come back with the chain
func TestEgressStopsWhileTheBorderIsNotReady(t *testing.T) {
	const sid = "3fff:1:69c:8c6::3"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	c.SetExit(&fakeExit{status: egress.Status{Ready4: true, Ready6: true}})
	c.SetEgressReady(true, true, true)
	for _, ready := range []bool{false, true, false, true} {
		c.SetBorderReady(ready)
		if got := sidOriginated(c, sid); got != ready {
			t.Errorf("with the border ready %v the SID's /128 is originated %v", ready, got)
		}
		status := c.egress()
		if ready && (len(status.Ready) != 2 || status.Unready != "") {
			t.Errorf("with the border ready the egress status reads ready %v, unready %q", status.Ready, status.Unready)
		}
		if !ready && (len(status.Ready) != 0 || status.Unready != "until the border filter is read back") {
			t.Errorf("with the border not ready the egress status reads ready %v, unready %q, want neither family and the border named", status.Ready, status.Unready)
		}
	}
}

// a node writing cap.border starts with the border not ready, so a translator
// serving the SIDs before the filter's first pass originates none
func TestEgressWaitsForTheBordersFirstPass(t *testing.T) {
	const sid = "3fff:1:69c:8c6::3"
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Link.Port = freeUDPPort(t)
	egressNode(cfg, egressSegment(sid, "3fff:a::/32"))
	c, err := newClient(cfg, privateKey, trust(t, reg), netstack.NewRoutesOnly(), nil, events.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetEgressReady(true, true, true)
	if sidOriginated(c, sid) {
		t.Error("before the border's first pass the SID's /128 is originated")
	}
	c.SetBorderReady(true)
	if !sidOriginated(c, sid) {
		t.Error("after the border's first pass the SID's /128 is not originated")
	}
}

// A republish that read the SID's two conditions before one of them fell ends
// before the republish of the fall, so the SID's /128 ends withdrawn: the
// border going down while the translator's republish is held, and the
// translator withdrawing while the border's is held
func TestRepublishRacingAFallLeavesTheSIDWithdrawn(t *testing.T) {
	const sid = "3fff:1:69c:8c6::3"
	for _, arm := range []struct {
		name         string
		held, racing func(c *Client)
		stored       func(c *Client) bool
	}{
		{
			name:   "the border going down",
			held:   func(c *Client) { c.SetEgressReady(true, true, true) },
			racing: func(c *Client) { c.SetBorderReady(false) },
			stored: func(c *Client) bool { return c.borderHeld.Load() },
		},
		{
			name:   "the translator withdrawing",
			held:   func(c *Client) { c.SetBorderReady(true) },
			racing: func(c *Client) { c.SetEgressReady(true, true, false) },
			stored: func(c *Client) bool { return !c.egressServes.Load() },
		},
	} {
		t.Run(arm.name, func(t *testing.T) {
			c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
			segmentsOf(t, c)
			speakerRecording(t, c, bus)
			h := holdRepublish(c)
			c.SetEgressReady(true, true, true)
			c.SetBorderReady(true)
			if !sidOriginated(c, sid) {
				t.Fatal("the SID is not originated with the border and the translator ready")
			}

			h.armed.Store(true)
			held := make(chan struct{})
			go func() { defer close(held); arm.held(c) }()
			h.wait(t)
			fell := make(chan struct{})
			go func() { defer close(fell); arm.racing(c) }()
			waitFor(t, heldWait, "the fall stored", func() bool { return arm.stored(c) })
			// a fall whose republish nothing orders runs to its end here
			select {
			case <-fell:
			case <-time.After(unorderedWait):
			}
			close(h.release)
			joined(t, "the held republish", held)
			joined(t, "the fall", fell)
			if sidOriginated(c, sid) {
				t.Errorf("after %s the SID's /128 is originated: the republish that read it standing landed last", arm.name)
			}
		})
	}
}

// the translator's own reason stays beside the border's, and a node with no
// egress segment is not held, since the hold covers the egress segments alone
func TestEgressStatusKeepsTheTranslatorsReasonBesideTheBorders(t *testing.T) {
	const reason = "net.ipv4.ip_forward is 0"
	c := &Client{Mesh: &netstack.Mesh{}}
	c.cfg.Store(&config.Config{})
	c.borderHeld.Store(true)
	c.SetExit(&fakeExit{status: egress.Status{Ready6: true, Unready: reason}})
	if got := c.egress(); len(got.Ready) != 1 || got.Unready != reason {
		t.Errorf("a node with no egress segment reads ready %v, unready %q, want the translator's word alone", got.Ready, got.Unready)
	}
	cfg := &config.Config{}
	egressNode(cfg, egressSegment("3fff:1:69c:8c6::3", "3fff:a::/32"))
	c.cfg.Store(cfg)
	if got := c.egress().Unready; got != reason+", and until the border filter is read back" {
		t.Errorf("the egress status reads unready %q", got)
	}
}

// a reload changing the overlay or the SIDs hands the running filter both,
// and one reordering the overlay hands it nothing
func TestReloadMovesTheBorderInPlace(t *testing.T) {
	const sid, moved = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::4"
	c, path, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	border := &borderRecord{}
	c.SetBorder(border)

	reordered := *c.config()
	reordered.Cap.Border = borderOf("198.18.0.0/15", "3fff::/20")
	writeConfig(t, path, &reordered)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reordered overlay was refused: %v", err)
	}
	if border.calls() != 0 || strings.Contains(lastReload(t, bus)["applied"], "cap.border") {
		t.Errorf("a reordered overlay handed the filter %d lists and applied %q", border.calls(), lastReload(t, bus)["applied"])
	}

	grown := *c.config()
	grown.Cap.Border = borderOf("198.18.0.0/15", "3fff::/20", "2001:db8::/32")
	writeConfig(t, path, &grown)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a grown overlay was refused: %v", err)
	}
	if got := border.Capability().Normalized(); len(got.Overlay) != 3 || border.calls() != 1 {
		t.Errorf("after a grown overlay the filter holds %v after %d lists", got.Overlay, border.calls())
	}
	if !strings.Contains(lastReload(t, bus)["applied"], "cap.border") {
		t.Errorf("a grown overlay applied %q, want cap.border among it", lastReload(t, bus)["applied"])
	}

	next := *c.config()
	next.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(moved, "3fff:a::/32")}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an egress segment moved to another SID was refused: %v", err)
	}
	if got := border.SIDs(); !slices.Equal(got, []netip.Addr{netip.MustParseAddr(moved)}) || border.calls() != 2 {
		t.Errorf("after the SID moved the filter drops %v after %d lists, want %s alone", got, border.calls(), moved)
	}
}

// every local SID admits only an outer source in the overlay, so a reload
// narrowing the overlay alone rebuilds the table the mesh acts on, and a SID
// delivering to the mesh refuses a source the old overlay held
func TestReloadMovingTheOverlayRebuildsTheLocalTable(t *testing.T) {
	const sid, mesh = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::1"
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment(sid, "3fff:a::/32"), srv6.Segment{SID: schema.MustAddr(mesh), Behavior: srv6.BehaviorEndDT46})
	})
	segmentsOf(t, c)
	c.SetBorder(&borderRecord{})
	handled := func() srv6.Result {
		inner := make([]byte, 40)
		inner[0], inner[6] = 0x60, 59
		raw, err := srv6.Encapsulate(inner, netip.MustParseAddr("3fff:b::1"), []netip.Addr{netip.MustParseAddr(mesh)})
		if err != nil {
			t.Fatal(err)
		}
		return c.Mesh.Segments().Handle(raw)
	}
	if got := handled(); got.Action != srv6.ActionDeliver {
		t.Fatalf("from inside 3fff::/20 the SID returned %v (%v), want a delivery", got.Action, got.Err)
	}
	narrowed := *c.config()
	narrowed.Cap.Border = borderOf("198.18.0.0/15", "3fff:a::/32")
	writeConfig(t, path, &narrowed)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a narrowed overlay was refused: %v", err)
	}
	if got := handled(); got.Action != srv6.ActionDrop || !errors.Is(got.Err, srv6.ErrSourceRefused) {
		t.Errorf("from outside the narrowed overlay the SID returned %v (%v), want a refusal of the source", got.Action, got.Err)
	}
}

// the filter and its run goroutine are built once in main, so a reload
// adding cap.border is refused and applies nothing
func TestReloadRefusesAddingTheBorder(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	next := *c.config()
	next.Cap.Border = borderOf("3fff::/20")
	writeConfig(t, path, &next)
	err := c.ReloadFrom(path)
	if err == nil || !strings.Contains(err.Error(), "cap.border added, restart to apply") {
		t.Errorf("a reload adding cap.border was answered %v", err)
	}
	if c.config().Cap.Border != nil {
		t.Error("the refused reload stored cap.border")
	}
}

// and a reload removing it is refused, leaving the filter its overlay
func TestReloadRefusesRemovingTheBorder(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) { cfg.Cap.Border = borderOf("3fff::/20") })
	border := &borderRecord{}
	c.SetBorder(border)
	next := *c.config()
	next.Cap.Border = nil
	writeConfig(t, path, &next)
	err := c.ReloadFrom(path)
	if err == nil || !strings.Contains(err.Error(), "cap.border removed, restart to apply") {
		t.Errorf("a reload removing cap.border was answered %v", err)
	}
	if c.config().Cap.Border == nil || border.calls() != 0 {
		t.Errorf("the refused reload dropped cap.border or handed the filter %d lists", border.calls())
	}
}

// down takes the node off the mesh and leaves the border filter running and
// ready, since the kernel still forwards and the host's services still trust
// mesh sources
func TestDownKeepsTheBorder(t *testing.T) {
	c, _, translator := downable(t, t.TempDir())
	c.SetBorder(&borderRecord{})
	c.SetBorderReady(true)
	if _, err := c.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if on, _ := translator.calls(); len(on) == 0 || on[len(on)-1] {
		t.Fatalf("down left the translator at %v", on)
	}
	status := c.Status().Border
	if held := c.borderHeld.Load(); held || status == nil || !status.Ready {
		t.Errorf("down left the border not ready %v with status %+v", held, status)
	}
	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// a node whose host forwards and whose file writes no cap.border is told so
// at every reload, naming the families, and one writing the block or on a
// host forwarding nothing is not
func TestUnborderedNodeIsWarnedWhereItsHostForwards(t *testing.T) {
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bordered := &config.Config{Cap: config.Caps{Border: borderOf("3fff::/20")}}
	for _, host := range []struct {
		v4, v6  bool
		warning string
	}{
		{true, true, "this node forwards IPv4 and IPv6 and holds no cap.border"},
		{true, false, "this node forwards IPv4 and holds no cap.border"},
		{false, true, "this node forwards IPv6 and holds no cap.border"},
		{false, false, ""},
	} {
		forwards := func() (bool, bool) { return host.v4, host.v6 }
		lines.Reset()
		warnUnbordered(bordered, forwards)
		if lines.Len() != 0 {
			t.Errorf("a node with cap.border on a host forwarding %v %v warned:\n%s", host.v4, host.v6, lines.String())
		}
		warnUnbordered(&config.Config{}, forwards)
		switch got := lines.String(); {
		case host.warning == "" && got != "":
			t.Errorf("a node on a host forwarding nothing warned:\n%s", got)
		case host.warning != "" && (!strings.Contains(got, host.warning) || !strings.Contains(got, "add cap.border")):
			t.Errorf("a node with no cap.border on a host forwarding %v %v warned %q, want it to say %q", host.v4, host.v6, got, host.warning)
		}
	}

	// a reload reads the host this test runs on, so the warning it wants is
	// the one that host's forwarding gives, and the peers a reload starts log
	// beside the test reading
	var reloaded syncBuffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&reloaded, nil)))
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	writeConfig(t, path, c.config())
	if err := c.ReloadFrom(path); err != nil {
		t.Fatal(err)
	}
	want := 0
	if v4, v6 := forwardingEnabled(); v4 || v6 {
		want = 1
	}
	if n := reloaded.count("holds no cap.border"); n != want {
		t.Errorf("a reload of a node with no cap.border warned %d times, want %d: %q", n, want, reloaded.lines("cap.border"))
	}
}

// the border accepts the mesh tun and lo, and an exit's egress leaves through
// the mesh tun, so it adds nothing
func TestBorderInsideIsEveryDeviceTheMeshArrivesOn(t *testing.T) {
	for name, node := range map[string]struct {
		exit bool
		want []string
	}{
		"a leaf":  {false, []string{"ranet3", "lo"}},
		"an exit": {true, []string{"ranet3", "lo"}},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
				if node.exit {
					egressNode(cfg, egressSegment("3fff:1:69c:8c6::3", "3fff:a::/32"))
				}
			})
			c.Mesh = &netstack.Mesh{Name: "ranet3"}
			if got := c.BorderInside(); !slices.Equal(got, node.want) {
				t.Errorf("the border accepts %v, want %v", got, node.want)
			}
		})
	}
}

// the filter drops the SID of every local segment, whatever its behavior
func TestBorderDropsEveryLocalSegmentsSID(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment("3fff:1:69c:8c6::3", "3fff:a::/32"), srv6.Segment{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd})
	})
	c.Mesh = &netstack.Mesh{Name: "ranet3"}
	want := []netip.Addr{netip.MustParseAddr("3fff:1:69c:8c6::3"), netip.MustParseAddr("3fff:1:69c:8c6::1")}
	if got := c.BorderRuntime().SIDs; !slices.Equal(got, want) {
		t.Errorf("the border drops %v, want %v", got, want)
	}
}

// the status carries the filter as it reports itself, and nothing on a node
// with no cap.border
func TestStatusReportsTheBorderOnlyWhereItRuns(t *testing.T) {
	c := writable(t)
	if status := c.Status().Border; status != nil {
		t.Errorf("a node with no border reported %+v", status)
	}
	sids := []netip.Addr{netip.MustParseAddr("3fff:1:69c:8c6::3"), netip.MustParseAddr("3fff:1:69c:8c6::1")}
	c.SetBorder(&borderRecord{border: *borderOf("3fff::/20", "198.18.0.0/15"), sids: sids})
	status := c.Status().Border
	want := control.BorderDrops{OverlaySourceIPv4: 3, RoutingHeader: 1}
	if status == nil || !status.Ready || status.Installed != 7 || status.Dropped != want || len(status.Overlay) != 2 || len(status.Inside) != 2 {
		t.Errorf("the border reported %+v", status)
	}
	if status != nil && !slices.Equal(status.SIDs, []netip.Addr{sids[1], sids[0]}) {
		t.Errorf("the border reported the SIDs %v, want them in order", status.SIDs)
	}
}

// the scrape carries the border's readiness and a series per kind of drop,
// and nothing of the border on a node with no cap.border
func TestMetricsExposeTheBorderOnlyWhereItRuns(t *testing.T) {
	c := writable(t)
	var off strings.Builder
	c.Metrics(&off)
	if strings.Contains(off.String(), "ranet3_border") {
		t.Errorf("a node with no border wrote:\n%s", off.String())
	}
	c.SetBorder(&borderRecord{})
	var out strings.Builder
	c.Metrics(&out)
	for _, want := range []string{
		"ranet3_border_ready 1",
		`ranet3_border_dropped_packets_total{reason="overlay_source",family="ipv4"} 3`,
		`ranet3_border_dropped_packets_total{reason="overlay_source",family="ipv6"} 0`,
		`ranet3_border_dropped_packets_total{reason="routing_header",family="ipv6"} 1`,
		`ranet3_border_dropped_packets_total{reason="sid_destination",family="ipv6"} 0`,
	} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}
}

// debug rules reads every policy rule the dump finds, an l3mdev rule as one,
// marks the reconciler's by the protocol cap.table names and the ones the
// reconciler derived, a goto and a suppress length among them, lists what it
// derived that the host does not hold, and carries the border's chain
func TestDebugRulesSortsEveryRuleByOwnerAndNamesTheMissing(t *testing.T) {
	const ownProto = kernel.DefaultProtocol + 1
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Cap.Table = &kernel.Table{Proto: ownProto}
	})
	derived := []kernel.DumpedRule{
		{Family: kernel.FamilyIPv4, Priority: 5100, FWMark: 0x72, FWMask: ^uint32(0), Action: "goto", Goto: 5190, Protocol: ownProto},
		{Family: kernel.FamilyIPv4, Priority: 5110, To: netip.MustParsePrefix("198.18.0.0/15"), Action: "lookup", Table: uint32(kernel.DefaultTable), Protocol: ownProto},
		{Family: kernel.FamilyIPv4, Priority: 5190, Action: "nop", Protocol: ownProto},
		{Family: kernel.FamilyIPv6, Priority: 5410, Action: "lookup", Table: 254, Suppress: kernel.SuppressUpTo(0), Protocol: ownProto},
	}
	c.SetReconcilerRules(func() []kernel.DumpedRule { return derived })
	held := []kernel.DumpedRule{
		{Family: kernel.FamilyIPv4, Priority: 0, Action: "lookup", Table: 255, Protocol: 2},
		derived[0], derived[1], derived[2],
		// the reconciler's protocol on a rule it did not derive
		{Family: kernel.FamilyIPv4, Priority: 5120, IIF: "eth1", Action: "lookup", Table: 254, Protocol: ownProto},
		// the default protocol, which a reconciler naming another does not own
		{Family: kernel.FamilyIPv4, Priority: 5150, From: netip.MustParsePrefix("198.18.104.0/24"), Action: "lookup", Table: 254, Protocol: kernel.DefaultProtocol},
		{Family: kernel.FamilyIPv4, Priority: 1000, L3mdev: true, Action: "lookup", Protocol: 2},
		{Family: kernel.FamilyIPv6, Priority: 5410, Action: "lookup", Table: 254, Protocol: 4},
	}
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return held, nil }
	info := c.DebugRules()
	type flags struct{ owned, wanted bool }
	want := []flags{{false, false}, {true, true}, {true, true}, {true, true}, {true, false}, {false, false}, {false, false}, {false, false}}
	if len(info.Policy) != len(want) {
		t.Fatalf("debug rules read %d rules, want %d: %+v", len(info.Policy), len(want), info.Policy)
	}
	for i, rule := range info.Policy {
		if got := (flags{rule.Owned, rule.Wanted}); got != want[i] {
			t.Errorf("rule %d %+v reads owned %v, wanted %v, want %+v", i, rule, rule.Owned, rule.Wanted, want[i])
		}
	}
	if !info.Policy[6].L3mdev {
		t.Errorf("debug rules reads the l3mdev rule as %+v", info.Policy[6])
	}
	if info.Policy[1].Goto != 5190 || info.Policy[1].Suppress != nil {
		t.Errorf("debug rules reads the mark's goto as %+v", info.Policy[1])
	}
	zero := 0
	missing := control.PolicyRule{Family: "ipv6", Priority: 5410, Action: "lookup", Table: 254, Suppress: &zero, Protocol: ownProto, Owned: true, Wanted: true}
	if len(info.Missing) != 1 || !reflect.DeepEqual(info.Missing[0], missing) {
		t.Errorf("debug rules names missing %+v, want %+v alone", info.Missing, missing)
	}
	if info.PolicyErr != "" || info.Border != nil {
		t.Errorf("debug rules reads policy error %q and border %+v on a node with no border", info.PolicyErr, info.Border)
	}

	passed := time.Now().Add(-3 * time.Second)
	c.SetBorder(&borderRecord{debug: egress.BorderDebug{
		Where: "nftables table inet ranet3 chain border", Hook: "prerouting", Priority: -300, PassAt: passed, Ready: true,
		Rules: []egress.BorderReading{{Spec: "drop ipv6 routing header", Verdict: "drop", Reason: "routing_header", Family: "ipv6", Held: true, Packets: 2, Bytes: 160}},
	}})
	for name, dump := range map[string]struct {
		err  error
		want string
	}{
		"a platform with none": {kernel.ErrUnsupported, "this platform has no policy rules"},
		"a dump that failed":   {errors.New("kernel: dump rules: permission denied"), "kernel: dump rules: permission denied"},
	} {
		c.ruleDump = func() ([]kernel.DumpedRule, error) { return nil, dump.err }
		info := c.DebugRules()
		if info.PolicyErr != dump.want || len(info.Policy) != 0 || len(info.Missing) != 0 {
			t.Errorf("%s: debug rules reads policy error %q, %d rules and missing %+v", name, info.PolicyErr, len(info.Policy), info.Missing)
		}
		chain := info.Border
		if chain == nil || !chain.ReadAt.Equal(passed) || chain.ReadAt.Location() != time.UTC || time.Duration(chain.ReadAgo) < 3*time.Second ||
			len(chain.Rules) != 1 || chain.Rules[0].Packets != 2 || chain.Priority != -300 || !chain.Ready {
			t.Errorf("%s: debug rules carries the chain %+v", name, chain)
		}
	}
}
