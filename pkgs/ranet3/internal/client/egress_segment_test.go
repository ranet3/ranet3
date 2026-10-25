// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

const (
	// heldWait is how long a test waits for a republish it holds or releases, generous for a loaded machine
	heldWait = 10 * time.Second
	// unorderedWait is how long a test gives a republish that nothing orders behind a held one to run to its end
	unorderedWait = 200 * time.Millisecond
)

// egressSegment is an End.DT46 at sid delivering to egress for the allow list given
func egressSegment(sid string, allow ...string) srv6.Segment {
	segment := srv6.Segment{SID: schema.MustAddr(sid), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress}
	for _, prefix := range allow {
		segment.Allow = append(segment.Allow, schema.MustPrefix(prefix))
	}
	return segment
}

// egressNode makes cfg a SID-only exit answering at the segments given, with
// the cap.egress and the cap.border they need. The overlay covers every allow
// list these tests write.
func egressNode(cfg *config.Config, segments ...srv6.Segment) {
	cfg.Cap.Egress = &egress.Egress{}
	cfg.Cap.Border = &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("198.18.0.0/15")}}
	cfg.Cap.Segment = &srv6.Segments{Local: segments}
}

// sidOriginated reports the speaker originating sid's /128
func sidOriginated(c *Client, sid string) bool {
	host := netip.PrefixFrom(netip.MustParseAddr(sid), 128)
	return slices.ContainsFunc(c.speaker.Originated(), func(route babel.OriginatedRoute) bool { return route.Destination == host })
}

// the translator's families are fixed at startup, so the first egress segment
// and the last are a restart, and a segment changing
// its SID or the order of its allow list is not
func TestEgressSegmentsComeAndGoOnlyByRestart(t *testing.T) {
	node := func(segments ...srv6.Segment) *config.Config {
		cfg := &config.Config{}
		egressNode(cfg, segments...)
		if len(segments) == 0 {
			cfg.Cap.Segment = nil
		}
		return cfg
	}
	first := egressSegment("3fff:1:69c:8c6::3", "3fff:a::/32", "198.18.104.0/24")
	moved := egressSegment("3fff:1:69c:8c6::4", "198.18.104.0/24", "3fff:a::/32")
	waypoint := srv6.Segment{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd}
	for name, move := range map[string]struct {
		old, next *config.Config
		naming    string
	}{
		"the first":                 {node(), node(first), "cap.segment adds the first egress segment, restart to apply"},
		"the first beside another":  {node(waypoint), node(waypoint, first), "cap.segment adds the first egress segment, restart to apply"},
		"the last":                  {node(first), node(), "cap.segment removes the last egress segment, restart to apply"},
		"the last for a waypoint":   {node(first), node(waypoint), "cap.segment removes the last egress segment, restart to apply"},
		"another SID and its order": {node(first), node(moved), ""},
		"a second beside the first": {node(first), node(first, moved), ""},
		"a waypoint beside it":      {node(first), node(first, waypoint), ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := reloadable(move.old, move.next)
			switch {
			case move.naming == "" && err != nil:
				t.Errorf("the reload was refused: %v", err)
			case move.naming != "" && (err == nil || !strings.Contains(err.Error(), move.naming)):
				t.Errorf("the reload was answered with %v, want it to say %q", err, move.naming)
			}
		})
	}
}

// A host that stops forwarding IPv4 while IPv4 is not ready leaves the
// readiness pair as it was, and the translator's word alone originates the
// SID's /128, which its word withdraws again once the host forwards IPv4
func TestSIDFollowsTheTranslatorsWordWhileTheReadinessPairStays(t *testing.T) {
	const sid = "3fff:1:69c:8c6::3"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	for _, serves := range []bool{false, true, false} {
		c.SetEgressReady(false, true, serves)
		if got := sidOriginated(c, sid); got != serves {
			t.Errorf("with IPv6 alone ready and the SIDs served %v, the SID's /128 is originated %v", serves, got)
		}
	}
}

// heldRepublish holds the next republish once it has read the configuration
// and the translator's word, before it hands the speaker anything, until
// release is closed
type heldRepublish struct {
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func holdRepublish(c *Client) *heldRepublish {
	h := &heldRepublish{entered: make(chan struct{}), release: make(chan struct{})}
	c.SetExit(&fakeExit{announce: func() []netip.Prefix {
		if h.armed.CompareAndSwap(true, false) {
			close(h.entered)
			<-h.release
		}
		return nil
	}})
	return h
}

func (h *heldRepublish) wait(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(heldWait):
		t.Fatal("the held republish never started")
	}
}

// joined waits for done, failing the test after heldWait
func joined(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(heldWait):
		t.Fatalf("%s never returned", what)
	}
}

// A readiness change whose republish read the configuration before a reload
// moved the SID ends before the reload's own republish, so the speaker ends
// on the moved SID
func TestReadinessRacingAReloadEndsOnTheMovedSID(t *testing.T) {
	const old, moved = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::4"
	c, path, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(old, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	h := holdRepublish(c)
	c.SetEgressReady(false, true, true)
	if !sidOriginated(c, old) {
		t.Fatal("a served SID was not originated")
	}

	h.armed.Store(true)
	ready := make(chan struct{})
	go func() { defer close(ready); c.SetEgressReady(true, true, true) }()
	h.wait(t)
	before := c.config()
	next := *before
	next.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(moved, "3fff:a::/32")}}
	writeConfig(t, path, &next)
	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		if err := c.ReloadFrom(path); err != nil {
			t.Errorf("the reload moving the SID was refused: %v", err)
		}
	}()
	waitFor(t, heldWait, "the reload storing its configuration", func() bool { return c.config() != before })
	// a reload whose republish nothing orders runs to its end here
	select {
	case <-reloaded:
	case <-time.After(unorderedWait):
	}
	close(h.release)
	joined(t, "the readiness change", ready)
	joined(t, "the reload", reloaded)
	if sidOriginated(c, old) || !sidOriginated(c, moved) {
		t.Errorf("the speaker originates %v, want %s/128 in place of %s/128", c.speaker.Originated(), moved, old)
	}
}

// A reload whose republish read the translator's word before the translator
// withdrew the SID ends before the withdrawal's own republish, so the SID
// stays withdrawn
func TestReloadRacingAWithdrawalLeavesTheSIDWithdrawn(t *testing.T) {
	const sid = "3fff:1:69c:8c6::3"
	c, path, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	h := holdRepublish(c)
	c.SetEgressReady(true, true, true)
	if !sidOriginated(c, sid) {
		t.Fatal("a served SID was not originated")
	}

	writeConfig(t, path, c.config())
	h.armed.Store(true)
	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		if err := c.ReloadFrom(path); err != nil {
			t.Errorf("the unchanged reload was refused: %v", err)
		}
	}()
	h.wait(t)
	withdrawn := make(chan struct{})
	go func() { defer close(withdrawn); c.SetEgressReady(false, true, false) }()
	waitFor(t, heldWait, "the translator storing its word", func() bool { return !c.egressServes.Load() })
	// a withdrawal whose republish nothing orders runs to its end here
	select {
	case <-withdrawn:
	case <-time.After(unorderedWait):
	}
	close(h.release)
	joined(t, "the reload", reloaded)
	joined(t, "the withdrawal", withdrawn)
	if sidOriginated(c, sid) {
		t.Errorf("the SID's /128 is originated after the translator withdrew it")
	}
}

// A republish that waited for another to finish publishes the configuration
// stored while it waited, never the one it found on arrival
func TestRepublishWaitingOnAnotherPublishesTheConfigurationStoredMeanwhile(t *testing.T) {
	const old, moved = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::4"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(old, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	h := holdRepublish(c)
	c.SetEgressReady(true, true, false)

	h.armed.Store(true)
	held := make(chan struct{})
	go func() { defer close(held); c.Republish() }()
	h.wait(t)
	waiting := make(chan struct{})
	go func() { defer close(waiting); c.SetEgressReady(true, true, true) }()
	waitFor(t, heldWait, "the translator storing its word", func() bool { return c.egressServes.Load() })
	// a republish that reads the configuration before it waits has read it by now
	time.Sleep(unorderedWait)
	next := *c.config()
	next.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(moved, "3fff:a::/32")}}
	c.cfg.Store(&next)
	close(h.release)
	joined(t, "the held republish", held)
	joined(t, "the readiness change", waiting)
	if sidOriginated(c, old) || !sidOriginated(c, moved) {
		t.Errorf("the speaker originates %v, want %s/128 in place of %s/128", c.speaker.Originated(), moved, old)
	}
}

// a reload moving an egress segment to another SID moves the /128 with it,
// and one only reordering its allow list applies nothing
func TestReloadMovesTheOriginatedSIDWithTheSegment(t *testing.T) {
	const old, moved = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::4"
	c, path, _, bus := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment(old, "3fff:a::/32", "198.18.104.0/24"))
	})
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	c.SetEgressReady(true, true, true)
	if !sidOriginated(c, old) {
		t.Fatal("ready egress segments left their SID unoriginated")
	}

	reordered := *c.config()
	reordered.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(old, "198.18.104.0/24", "3fff:a::/32")}}
	writeConfig(t, path, &reordered)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reordered allow list was refused: %v", err)
	}
	if got := lastReload(t, bus)["applied"]; strings.Contains(got, "cap.segment") {
		t.Errorf("a reordered allow list applied %q, want cap.segment unchanged", got)
	}

	next := *c.config()
	next.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(moved, "3fff:a::/32", "198.18.104.0/24")}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an egress segment moved to another SID was refused: %v", err)
	}
	if sidOriginated(c, old) || !sidOriginated(c, moved) {
		t.Errorf("after the reload the speaker originates %v, want %s/128 in place of %s/128", c.speaker.Originated(), moved, old)
	}
}

// a node with two egress segments originates both SIDs' /128 while the
// translator says the SIDs are served, and neither once it says they are not
func TestEveryEgressSIDIsOriginatedWhileServed(t *testing.T) {
	const first, second = "3fff:1:69c:8c6::3", "3fff:1:69c:8c6::4"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment(first, "3fff:a::/32"), egressSegment(second, "3fff:b::/32", "198.18.104.0/24"))
	})
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	for _, serves := range []bool{true, false, true} {
		c.SetEgressReady(true, true, serves)
		for _, sid := range []string{first, second} {
			if got := sidOriginated(c, sid); got != serves {
				t.Errorf("with the SIDs served %v, %s/128 is originated %v", serves, sid, got)
			}
		}
	}
}

// a node with no egress segment originates no SID whatever the translator's
// word, so the announcement is cap.route's alone
func TestNodeWithNoEgressSegmentOriginatesNoSID(t *testing.T) {
	cfg := &config.Config{Cap: config.Caps{Segment: &srv6.Segments{Local: []srv6.Segment{{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd}}}}}
	c := &Client{}
	c.egressServes.Store(true)
	if routes := c.announced(cfg, c.egressAdvertised()); len(routes) != 0 {
		t.Errorf("a waypoint originated %v", routes)
	}
}
