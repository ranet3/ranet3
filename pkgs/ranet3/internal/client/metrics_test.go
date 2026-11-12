// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/transport"
)

// hubCountWait bounds each wait for the hub to count what was sent to it
const hubCountWait = 10 * time.Second

// countingWriter counts writes rather than keeping them, the unit a report
// that must not be one line per packet is measured in.
type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(b []byte) (int, error) { w.n.Add(1); return len(b), nil }

// The inbound SPI is cleartext in every datagram, so anyone who has seen one
// can send datagrams this node refuses at the replay check, before any crypto.
// A line per refused batch is then a line per datagram, written synchronously
// on the goroutine that also hands babel its packets and under the log mutex
// every other component shares, which is how a flood of small datagrams
// withdraws this node's routes from the mesh rather than merely wasting its
// time. The count has to stay exact: only the saying of it is bounded.
func TestRefusedESPPacketsAreCountedExactlyAndSaidRarely(t *testing.T) {
	c := testClient(t)
	var lines atomic.Int64
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(countingWriter{&lines}, nil)))

	c.dropReported.Store(-int64(espDropReportInterval))
	const batches = 20000
	for range batches {
		c.noteInboundDropped("peer", 1, errors.New("replayed"))
	}
	if got := c.inboundDropped.Load(); got != batches {
		t.Errorf("the counter reads %d for %d refused packets", got, batches)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d refused batches wrote %d log lines, want the one the interval allows", batches, got)
	}

	// The interval bounds it, not a once-ever flag: an operator has to hear
	// about a flood that is still going.
	c.dropReported.Store(int64(time.Since(c.started)) - int64(espDropReportInterval))
	c.noteInboundDropped("peer", 1, errors.New("replayed"))
	if got := lines.Load(); got != 2 {
		t.Errorf("after the interval passed the report wrote %d lines in total, want 2", got)
	}
}

// A datagram naming no SPI this node holds is refused by the hub, and the
// metric is the only way an operator tells that from silence. It is its own
// series because ranet3_receive_dropped_total, of datagrams refused because
// their session's receive queue was full or held all its receive buffers, means
// something else entirely. The scrape carries the counts of the hub the
// client receives on.
func TestMetricsRendersWhatTheHubRefused(t *testing.T) {
	c := testClient(t)
	hub := c.hub
	sender, err := net.Dial("udp", net.JoinHostPort("127.0.0.1",
		strconv.Itoa(hub.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	// a session nothing reads from, so once its receive queue is full the hub drops what comes for it
	queue, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	if err := queue.RegisterESP(0x07070707); err != nil {
		t.Fatal(err)
	}
	// An ESP SPI no Mux holds, which anyone who can reach the port can send
	// and which an operator needs to be able to see, and an RFC 3948 NAT
	// keepalive, which the hub counts on a counter of its own.
	// They go before the flood, which can fill the socket's receive buffer so the kernel drops whatever follows it.
	for _, datagram := range [][]byte{{9, 9, 9, 9, 0, 0, 0, 1, 0, 0, 0, 0}, {0xff}} {
		if _, err := sender.Write(datagram); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(hubCountWait)
	for hub.Refused() == 0 || hub.Keepalives() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the hub counted %d refused and %d keepalives for one of each, so this proves nothing", hub.Refused(), hub.Keepalives())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// the flood's SPI is registered, so none of it is refused or a keepalive and the scrape carries one of each and no refusal of another cause
	flood := append([]byte{7, 7, 7, 7}, make([]byte, 60)...)
	deadline = time.Now().Add(hubCountWait)
	for hub.Dropped() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the hub dropped nothing for the full queue, so this proves nothing")
		}
		if _, err := sender.Write(flood); err != nil {
			t.Fatal(err)
		}
	}

	// the flood's last datagrams may still be dropping, so the line holds a count between the two reads
	var out strings.Builder
	before := hub.Dropped()
	c.renderReceiveCounters(&out)
	after := hub.Dropped()
	_, line, _ := strings.Cut(out.String(), "\nranet3_receive_dropped_total ")
	var dropped uint64
	if _, err := fmt.Sscanf(line, "%d", &dropped); err != nil || dropped < before || dropped > after {
		t.Errorf("the scrape's dropped line reads %d (%v), want the hub's count, from %d to %d:\n%s", dropped, err, before, after, out.String())
	}
	want := []string{
		"# TYPE ranet3_receive_refused_total counter",
		"ranet3_receive_keepalives_total 1\n",
	}
	// every cause is a series, the unknown ESP SPI's the one the probe raised
	for _, cause := range transport.RefusalCauses {
		refused := 0
		if cause == "unknown_esp" {
			refused = 1
		}
		want = append(want, fmt.Sprintf("ranet3_receive_refused_total{cause=%q} %d\n", cause, refused))
	}
	for _, line := range want {
		if !strings.Contains(out.String(), line) {
			t.Errorf("the scrape does not carry %q:\n%s", line, out.String())
		}
	}
}

// the scrape counts the sockets connected to one busy peer each, those a send or a read failed on and handed back to the shared socket, and the connects that failed
// a change of the network closes the socket and counts no fallback
func TestMetricsCountTheSocketsConnectedToOnePeer(t *testing.T) {
	c := testClient(t)
	hub := c.hub
	busyPeer(t, hub, c.events)
	scrape := func(want ...string) {
		t.Helper()
		var out strings.Builder
		c.renderPairSockets(&out)
		for _, line := range want {
			if !strings.Contains(out.String(), line+"\n") {
				t.Errorf("the scrape does not carry %q:\n%s", line, out.String())
			}
		}
	}
	scrape("# TYPE ranet3_transport_pair_sockets gauge", "ranet3_transport_pair_sockets 1",
		"# TYPE ranet3_transport_pair_fallbacks_total counter", "ranet3_transport_pair_fallbacks_total 0",
		"# TYPE ranet3_transport_pair_connects_failed_total counter", "ranet3_transport_pair_connects_failed_total 0")
	hub.NetworkChanged()
	scrape("ranet3_transport_pair_sockets 0", "# TYPE ranet3_transport_pair_fallbacks_total counter", "ranet3_transport_pair_fallbacks_total 0")
}

// The segment routing half and the reconciler are the two subsystems that
// replaced something a scrape used to carry: seg6local routes the kernel
// counted, and the kernel protocols prometheus-bird-exporter read out of
// BIRD. Neither was exported here until a live run went looking for a steered
// path that had stopped working and found the counter only on a socket.
func TestMetricsExposesSegmentsAndTheReconciler(t *testing.T) {
	c := testClient(t)
	var segments strings.Builder
	c.renderSegmentCounters(&segments)
	for _, want := range []string{
		"# TYPE ranet3_segments_forwarded_total counter",
		"ranet3_segments_delivered_total 0",
		"ranet3_segments_dropped_total 0",
		"ranet3_segments_answered_total 0",
		"# TYPE ranet3_segments_egressed_total counter",
		"ranet3_segments_egressed_total 0",
		"ranet3_segments_refused_total 0",
		"ranet3_segments_not_ready_total 0",
		"ranet3_segments_ecn_unused_total 0",
		"ranet3_steered_total 0",
		// The two ways this node's own steering loses a packet are one series
		// with a reason, since an alert wants their sum and a reader wants
		// which one.
		`ranet3_steer_dropped_total{reason="too_large"} 0`,
		`ranet3_steer_dropped_total{reason="no_route"} 0`,
	} {
		if !strings.Contains(segments.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, segments.String())
		}
	}

	pass := time.Date(2026, 9, 21, 19, 3, 0, 0, time.UTC)
	c.SetReconciler(Reconciler{Status: func() control.KernelStatus {
		return control.KernelStatus{Enabled: true, Installed: 150, Skipped: 8, PassAt: pass, Err: "list routes: bad"}
	}})
	var kernel strings.Builder
	c.renderKernel(&kernel)
	for _, want := range []string{
		"ranet3_kernel_routes_installed 150",
		"ranet3_kernel_routes_skipped 8",
		fmt.Sprintf("ranet3_kernel_pass_timestamp_seconds %d", pass.Unix()),
		"ranet3_kernel_pass_failed 1",
	} {
		if !strings.Contains(kernel.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, kernel.String())
		}
	}

	// A node whose reconciler is off writes none of it, rather than four
	// zeroes that read as a reconciler installing nothing.
	c.SetReconciler(Reconciler{Status: func() control.KernelStatus { return control.KernelStatus{} }})
	var off strings.Builder
	c.renderKernel(&off)
	if off.Len() != 0 {
		t.Errorf("a node with no reconciler wrote %q", off.String())
	}

	// And a reconciler that has not finished a pass reports zero rather than
	// a timestamp two millennia before the epoch.
	c.SetReconciler(Reconciler{Status: func() control.KernelStatus { return control.KernelStatus{Enabled: true} }})
	var first strings.Builder
	c.renderKernel(&first)
	if !strings.Contains(first.String(), "ranet3_kernel_pass_timestamp_seconds 0") {
		t.Errorf("before the first pass the scrape reads:\n%s", first.String())
	}
}

// each taken gauge holds the lookups the reconciler's last pass found taken in
// a family it asked in, and writes no series for a family or a kind of lookup
// it did not ask
func TestMetricsCountTheLookupsTakenInEachFamilyAsked(t *testing.T) {
	c := testClient(t)
	status := func() control.KernelStatus { return control.KernelStatus{Enabled: true} }
	c.SetReconciler(Reconciler{Status: status})
	var none strings.Builder
	c.renderKernel(&none)
	if strings.Contains(none.String(), "_taken") {
		t.Errorf("a reconciler that asked nothing wrote a taken series:\n%s", none.String())
	}
	c.SetReconciler(Reconciler{Status: status, Lookups: func() []kernel.Lookup {
		return []kernel.Lookup{
			{Family: kernel.FamilyIPv4, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Taken: true},
			{Family: kernel.FamilyIPv4, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{Family: kernel.FamilyIPv6, Prefix: netip.MustParsePrefix("3fff::/20")},
			{Family: kernel.FamilyIPv4, Address: netip.MustParseAddr("198.51.100.77"), Taken: true},
			{Family: kernel.FamilyIPv4, Address: netip.MustParseAddr("203.0.113.70"), Taken: true},
			{Family: kernel.FamilyIPv4, Address: netip.MustParseAddr("203.0.113.71")},
		}
	}})
	var taken strings.Builder
	c.renderKernel(&taken)
	for _, want := range []string{
		"# TYPE ranet3_kernel_overlay_taken gauge",
		`ranet3_kernel_overlay_taken{family="ipv4"} 1`,
		`ranet3_kernel_overlay_taken{family="ipv6"} 0`,
		"# TYPE ranet3_kernel_underlay_taken gauge",
		`ranet3_kernel_underlay_taken{family="ipv4"} 2`,
	} {
		if !strings.Contains(taken.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, taken.String())
		}
	}
	if strings.Contains(taken.String(), `ranet3_kernel_underlay_taken{family="ipv6"}`) {
		t.Errorf("the scrape carries the underlay's IPv6 series, which the pass did not ask:\n%s", taken.String())
	}
}

// the forwarding decision's counters are one series, each drop under its reason, and render as the golden file
// a node that forwarded nothing writes every series at 0
func TestMetricsExposeTheTransitCountersAsTheGoldenFile(t *testing.T) {
	var out strings.Builder
	writeTransitCounters(&out, control.TransitCounters{Forwarded: 1200, Delivered: 340, Expired: 1, NoRoute: 2, Held: 3, Refused: 4, Invalid: 5, Martian: 6, SourceRoute: 7, UnroutedSource: 12, NotReady: 13, TooBig: 8, SessionMulticast: 21, Multicast: 9, Forged: 14, RoutingHeader: 15, SID: 16, UnownedSource: 17, Nested: 18, Looped: 19, Answered: 10, Unanswered: 11, Unsent: 20})
	verbGolden(t, "metrics-transit.txt", []byte(out.String()))
	c := testClient(t)
	var zero strings.Builder
	c.renderTransitCounters(&zero)
	if want := `ranet3_transit_packets_total{decision="dropped",reason="no_route"} 0`; !strings.Contains(zero.String(), want) {
		t.Errorf("the scrape does not carry %q:\n%s", want, zero.String())
	}
}

// The advertised and announced prefix counts are separate series, because
// their difference is the alert: announcing fewer than are advertised is this
// node declining to attract traffic it would drop, and no peer can see that
// from its own end. Beside them are the flows each family's limit refused, the
// packets it dropped with no tracked flow and the host's connection table, the
// table's series left out where the pass could not read it.
func TestMetricsExposesWhatTheEgressCapabilityIsWithholding(t *testing.T) {
	c := testClient(t)
	pass := time.Date(2026, 9, 21, 19, 3, 0, 0, time.UTC)
	carried := netip.MustParsePrefix("198.51.100.0/24")
	withheld := netip.MustParsePrefix("2001:db8:1::/48")
	count, most := uint64(9000), uint64(262144)
	c.SetExit(&fakeExit{status: egress.Status{
		PassAt:    pass,
		Ready4:    true,
		Advertise: []netip.Prefix{carried, withheld},
		Announced: []netip.Prefix{carried},
		Refused4:  7, Refused6: 1,
		Dropped4: 4, Dropped6: 2,
		Rules: &egress.Rules{
			Installed: 3, Flows: 91, Untranslated: 17, ConntrackCount: &count, ConntrackMax: &most,
			Conflicts: []string{"ip table nat chain POSTROUTING at priority 100"},
		},
	}})
	var out strings.Builder
	c.renderEgress(&out)
	for _, want := range []string{
		"ranet3_egress_rules_installed 3",
		`ranet3_egress_prefixes{state="advertised"} 2`,
		`ranet3_egress_prefixes{state="announced"} 1`,
		"ranet3_egress_flows_total 91",
		"ranet3_egress_untranslated_flows_total 17",
		`ranet3_egress_refused_total{family="ipv4"} 7`,
		`ranet3_egress_refused_total{family="ipv6"} 1`,
		`ranet3_egress_dropped_total{family="ipv4"} 4`,
		`ranet3_egress_dropped_total{family="ipv6"} 2`,
		"ranet3_egress_conntrack_entries 9000",
		"ranet3_egress_conntrack_max 262144",
		"ranet3_egress_conflicts 1",
		fmt.Sprintf("ranet3_egress_pass_timestamp_seconds %d", pass.Unix()),
		"ranet3_egress_pass_failed 0",
		`ranet3_egress_ready{family="ipv4"} 1`,
		`ranet3_egress_ready{family="ipv6"} 0`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}

	// the gauge is the exit's judgment, which a border whose chain is missing does not narrow
	cfg := &config.Config{}
	egressNode(cfg, egressSegment("3fff:b:0:106::3", "3fff:a::/32"))
	c.cfg.Store(cfg)
	c.SetBorder(&borderRecord{missing: true})
	c.SetExit(&fakeExit{status: egress.Status{Ready6: true}})
	var ready strings.Builder
	c.renderEgress(&ready)
	for _, want := range []string{`ranet3_egress_ready{family="ipv4"} 0`, `ranet3_egress_ready{family="ipv6"} 1`} {
		if !strings.Contains(ready.String(), want) {
			t.Errorf("the scrape of an exit ready for IPv6 alone does not carry %q:\n%s", want, ready.String())
		}
	}
	if strings.Contains(ready.String(), "ranet3_egress_conntrack") {
		t.Errorf("the scrape of an exit that read no connection table carries one:\n%s", ready.String())
	}

	// A node that carries nothing for anybody writes none of it, rather than
	// zeroes that read as an exit node translating nothing.
	var off strings.Builder
	testClient(t).renderEgress(&off)
	if off.Len() != 0 {
		t.Errorf("a node with no egress capability wrote %q", off.String())
	}
}

// An exit carrying its flows itself writes the series every exit has and none
// of the rules', the translation's or connection tracking's, whose zeros
// would read as an exit installing nothing
func TestMetricsOfTheUserspaceExitWriteNoRulesSeries(t *testing.T) {
	c := testClient(t)
	c.SetExit(&fakeExit{status: egress.Status{
		Backend: "userspace", Ready4: true, Ready6: true, Refused4: 3,
		Flows: &egress.Flows{TCP: [2]int{4, 1}, Limits: egress.FlowLimits{Budget: 16 << 20, From: egress.BudgetGoLimit, Connections: 23}},
	}})
	var out strings.Builder
	c.renderEgress(&out)
	for _, want := range []string{
		`ranet3_egress_prefixes{state="advertised"} 0`,
		`ranet3_egress_refused_total{family="ipv4"} 3`,
		"ranet3_egress_pass_timestamp_seconds 0",
		"ranet3_egress_pass_failed 0",
		`ranet3_egress_ready{family="ipv6"} 1`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}
	for _, unwanted := range []string{
		"ranet3_egress_rules_installed", "ranet3_egress_flows_total", "ranet3_egress_untranslated_flows_total",
		"ranet3_egress_dropped_total", "ranet3_egress_conntrack", "ranet3_egress_conflicts", "ranet3_egress_host_held",
	} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("the scrape of the userspace exit carries %q:\n%s", unwanted, out.String())
		}
	}
}

// A userspace exit that bounds the host ports its TCP connections pin writes
// the closed connections it holds for them as a gauge, under a bound of 0 too
func TestMetricsOfTheUserspaceExitBoundingHostPortsWriteTheConnectionsItHolds(t *testing.T) {
	for _, test := range []struct {
		held, bound int
	}{{37, 5120}, {0, 0}} {
		c := testClient(t)
		c.SetExit(&fakeExit{status: egress.Status{
			Backend: "userspace", Ready4: true,
			Flows: &egress.Flows{Host: &egress.HostHold{Held: test.held, Ports: test.held, Bound: test.bound}, Limits: egress.FlowLimits{Budget: 16 << 20, From: egress.BudgetGoLimit, Connections: 23}},
		}})
		var out strings.Builder
		c.renderEgress(&out)
		for _, want := range []string{"# TYPE ranet3_egress_host_held gauge", fmt.Sprintf("ranet3_egress_host_held %d\n", test.held)} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("under a bound of %d the scrape does not carry %q:\n%s", test.bound, want, out.String())
			}
		}
	}
}
