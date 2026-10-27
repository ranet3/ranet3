// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// the column set is the promise the subcommands make
// so a rename is a change an operator's scripts see
// and it belongs in a diff that says so
func TestRenderersKeepTheirColumns(t *testing.T) {
	for name, test := range map[string]struct {
		render func(*strings.Builder)
		want   []string
	}{
		"neighbors": {
			render: func(b *strings.Builder) { RenderNeighbors(b, nil) },
			want:   []string{"Peer", "State", "Cost", "Extra", "Rx cost", "RTT", "Routes", "Expires", "Dropped", "Failed"},
		},
		"routes": {
			render: func(b *strings.Builder) { RenderRoutes(b, nil) },
			want:   []string{"Destination", "From", "Via", "Metric", "Router ID", "Seqno", "Paths"},
		},
		"sessions": {
			render: func(b *strings.Builder) { RenderSessions(b, nil) },
			want:   []string{"Path", "Peer", "Remote", "End", "State", "SPI in/out", "IKE", "Fragments", "ESP", "Age", "Idle"},
		},
		"peers": {
			render: func(b *strings.Builder) { RenderPeers(b, nil) },
			want:   []string{"Path", "Peer", "From", "State"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			test.render(&out)
			header := strings.Fields(out.String())
			for _, column := range test.want {
				if !strings.Contains(out.String(), column) {
					t.Errorf("the %s header is %q, want it to carry %q", name, header, column)
				}
			}
		})
	}
}

// the session table names each SA's transforms by their cap.crypto names, an entry's key exchanges joined with +
// a Child SA keyed by key exchanges of its own has their kex entry after its cipher
// a session the daemon reported no transforms for reads as a dash
// the path's threshold, the largest IP datagram this end cuts a new IKE message to fit, stands beside its transforms, and no where its ends did not both say they support RFC 7383 fragmentation
func TestSessionsRenderAsTheGoldenFiles(t *testing.T) {
	sessions := []Session{
		{Path: "example/gateway:0@0", Peer: "example/gateway", Remote: "192.0.2.7:13000", Preferred: true, Active: true,
			LocalSPI: 0xc0ffee01, RemoteSPI: 0x0badf00d, IKECipher: "aes256gcm", IKEPRF: "sha384", IKEKex: "x25519", ESPCipher: "aes128gcm",
			StartedAt: time.Date(2026, 10, 4, 12, 20, 1, 0, time.UTC), Age: Duration(90 * time.Minute), Idle: Duration(1200 * time.Millisecond)},
		{Path: "example/exit:1@0", Peer: "example/exit", Remote: "[2001:db8::1]:13000", LocalSPI: 1, RemoteSPI: 2,
			StartedAt: time.Date(2026, 10, 4, 13, 50, 1, 0, time.UTC), Age: Duration(time.Second), Idle: Duration(time.Second)},
		{Path: "example/relay:0@0", Peer: "example/relay", Remote: "198.51.100.4:13000", Active: true,
			LocalSPI: 0x5eed0001, RemoteSPI: 0x5eed0002, IKECipher: "aes256gcm", IKEPRF: "sha384", IKEKex: "x25519+mlkem768",
			IKEFragments: true, IKEFragmentThreshold: 1280, ESPCipher: "aes256gcm", ESPKex: "x25519+mlkem768",
			StartedAt: time.Date(2026, 10, 4, 13, 40, 1, 0, time.UTC), Age: Duration(10 * time.Minute), Idle: Duration(300 * time.Millisecond)},
	}
	var out strings.Builder
	RenderSessions(&out, sessions)
	golden(t, "sessions.txt", []byte(out.String()))
	goldenJSON(t, "sessions.json", sessions)
}

// 65535 is infinity and a reader should not have to remember that. An absent
// measurement prints as a dash rather than as a zero, because zero is a cost a
// link can have and a round trip a loopback peer measures.
func TestNeighborsSpellInfinityAndAbsence(t *testing.T) {
	var out strings.Builder
	RenderNeighbors(&out, []Neighbor{{Peer: "example/gateway@0", Cost: 65535}})
	line := out.String()
	if !strings.Contains(line, "inf") {
		t.Errorf("an infinite cost printed as %q", line)
	}
	if strings.Count(line, "-") < 2 {
		t.Errorf("an unmeasured rxcost and rtt printed as %q, want dashes", line)
	}

	cost := uint16(96)
	rtt := Duration(27200 * time.Microsecond)
	out.Reset()
	RenderNeighbors(&out, []Neighbor{{Peer: "example/gateway@0", Alive: true, Cost: 116, ReportedCost: &cost, RTT: &rtt}})
	for _, want := range []string{"up", "116", "96", "27.2ms"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("a measured neighbor printed as %q, want it to carry %q", out.String(), want)
		}
	}
}

// The extra stands beside the cost that holds it, so an operator reads what the link costs apart from what the node charges
func TestNeighborsShowTheExtraApartFromTheCost(t *testing.T) {
	cost := uint16(1120)
	rtt := Duration(27200 * time.Microsecond)
	neighbors := []Neighbor{
		{Peer: "example/gateway:0@0", Alive: true, Cost: 1140, Extra: 1024, ReportedCost: &cost, RTT: &rtt, Routes: 3, Expires: Duration(14 * time.Second)},
		{Peer: "ysun/lagern:0@0", Alive: true, Cost: 116, ReportedCost: &cost, Routes: 1, Expires: Duration(13 * time.Second)},
	}
	var out strings.Builder
	RenderNeighbors(&out, neighbors)
	golden(t, "neighbors.txt", []byte(out.String()))
	goldenJSON(t, "neighbors.json", neighbors)
}

// A prefix this node originates and one held unreachable are the two rows an
// operator is usually looking for, and neither has a next hop to print.
func TestRoutesNameOriginatedAndUnreachable(t *testing.T) {
	var out strings.Builder
	RenderRoutes(&out, []Route{
		{Destination: netip.MustParsePrefix("2001:db8::/48"), Originated: true},
		{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Metric: 65535},
		{Destination: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32"), Via: "example/exit@0", Metric: 212},
	})
	for _, want := range []string{"this node", "unreachable", "2001:db8::/32", "example/exit@0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the route table printed as %q, want it to carry %q", out.String(), want)
		}
	}
}

// ownAndLearned is a route table with a row of each kind: a host prefix this
// node announces and is assigned, a prefix it announces, an address cap.table
// assigns it alone, a prefix held after a retraction, and a learned default
// from a source prefix
func ownAndLearned() []Route {
	return []Route{
		{Destination: netip.MustParsePrefix("198.18.104.117/32"), Originated: true, Assigned: true},
		{Destination: netip.MustParsePrefix("2001:db8::/48"), Originated: true},
		{Destination: netip.MustParsePrefix("2001:db8::5/128"), Assigned: true},
		{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Metric: 65535, Candidates: 1},
		{Destination: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32"), Via: "example/exit@0",
			Metric: 212, RouterID: "0a1b2c3d4e5f6071", Seqno: 42, Candidates: 2},
	}
}

// Every row this node owns names this node as Via, whether it is
// announced, assigned or both, and the wire form says which.
func TestRoutesRenderAsTheGoldenFiles(t *testing.T) {
	routes := ownAndLearned()
	var out strings.Builder
	RenderRoutes(&out, routes)
	golden(t, "routes.txt", []byte(out.String()))
	goldenJSON(t, "routes.json", routes)
}

// whois answers an address cap.table assigns with its host route as this
// node's, then the prefixes it would fall back to, and names one this node
// announces as well as originated.
func TestWhoisNamesAnAssignedAddressThisNodes(t *testing.T) {
	var out strings.Builder
	for i, address := range []netip.Addr{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("198.18.104.117")} {
		if i > 0 {
			out.WriteString("\n")
		}
		RenderWhois(&out, address, Covering(ownAndLearned(), address))
	}
	golden(t, "whois-assigned.txt", []byte(out.String()))
}

// The role line is the three settings that decide what a node is on a fleet,
// said as words rather than as booleans a reader reassembles.
func TestStatusSaysTheRoleInWords(t *testing.T) {
	var out strings.Builder
	RenderStatus(&out, Status{Node: "example/laptop", Responder: false, FullMesh: true, NoTransit: true})
	for _, want := range []string{"example/laptop", "initiator", "full mesh", "no transit", "off, routes configured externally"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status printed as %q, want it to carry %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "responder") {
		t.Error("a node with responder off is reported as one")
	}
}

// the segment line always names forwarded, delivered and dropped
// and names answered, egressed, refused and not ready only while each is above 0
func TestStatusSegmentLineRendersAsTheGoldenFile(t *testing.T) {
	status := downStatus()
	status.Down = nil
	status.Segments = []string{"3fff:1:69c:8c6::1 End.DT46", "3fff:1:69c:8c6::2 End"}
	var out strings.Builder
	for _, counters := range []SegmentCounters{
		{Forwarded: 7, Delivered: 5, Dropped: 4},
		{Forwarded: 7, Delivered: 5, Dropped: 4, Answered: 1, Egressed: 33, Refused: 2, NotReady: 3},
	} {
		status.SegmentCounters = counters
		RenderStatus(&out, status)
		out.WriteString("\n")
	}
	golden(t, "status-segments.txt", []byte(out.String()))
}

// the transit line always names forwarded, delivered and dropped, the last summing the reasons
// and names each reason, answered and unanswered only while each is above 0, and --json carries every count under transit
// the other status goldens hold the line in its place
func TestStatusTransitLineRendersAsTheGoldenFile(t *testing.T) {
	every := TransitCounters{Forwarded: 1200, Delivered: 340, Expired: 1, NoRoute: 2, Held: 3, Refused: 4, Invalid: 5, Martian: 6, SourceRoute: 7, UnroutedSource: 12, NotReady: 13, TooBig: 8, Multicast: 9, Forged: 14, RoutingHeader: 15, SID: 16, UnownedSource: 17, Nested: 18, Looped: 19, Answered: 10, Unanswered: 11}
	for _, c := range []struct {
		counters TransitCounters
		want     string
	}{
		{TransitCounters{}, "0 forwarded, 0 delivered, 0 dropped"},
		{TransitCounters{Forwarded: 1200, Delivered: 340, NoRoute: 2, Answered: 2}, "1200 forwarded, 340 delivered, 2 dropped (2 no route), 2 answered"},
		{every, "1200 forwarded, 340 delivered, 169 dropped (1 expired, 2 no route, 3 held, 4 refused, 5 invalid, 6 martian, 7 source route, 12 unrouted source, 13 not ready, 8 too big, 9 multicast, 14 forged, 15 routing header, 16 SID, 17 unowned source, 18 nested, 19 looped), 10 answered, 11 unanswered"},
	} {
		if got := transitLine(c.counters); got != c.want {
			t.Errorf("the transit line of %+v reads %q, want %q", c.counters, got, c.want)
		}
	}
	goldenJSON(t, "status-transit.json", every)
}

// the egress line names the families that are ready and the ones that are
// not, with the reason for one this node translates, names neither before the
// first pass, and says what the route lookups left out and why: a family held
// by a forward lookup that failed, its prefix withheld, one held by a reply
// lookup leaving by the uplink, a family with no member to read from and a
// prefix with no address to read. It names the flows each family's limit
// refused where any were, against the limit, and the host's connection table
// against its maximum, as far as the pass read them.
func TestStatusEgressLineRendersAsTheGoldenFile(t *testing.T) {
	var out strings.Builder
	for _, ready := range [][]string{nil, {"ipv6"}, {"ipv4", "ipv6"}} {
		out.WriteString(egressLine(EgressStatus{Enabled: true, Where: "nftables ip ranet3, ip6 ranet3", Ready: ready}) + "\n")
	}
	out.WriteString(egressLine(EgressStatus{Enabled: true, Where: "nftables ip ranet3, ip6 ranet3",
		Unready: "the host does not forward ipv4 or ipv6"}) + "\n")
	out.WriteString(egressLine(EgressStatus{Enabled: true, Where: "nftables ip ranet3", Installed: 1}) + "\n")
	advertise := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("::/0")}
	linkLocal := []netip.Prefix{advertise[0], advertise[1], netip.MustParsePrefix("fe80::/10")}
	for _, judged := range []EgressStatus{
		{
			Advertise: advertise, Ready: []string{"ipv6"}, Announced: advertise[1:],
			Unready: "the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3 failed: no route to host, with net.ipv4.conf.ranet3.forwarding at 0",
		},
		{
			Advertise: advertise, Ready: []string{"ipv4"}, Announced: advertise[:1],
			Unready: "the reply lookup of 3fff:20::1 for ::/0 from 8000:: arriving on eth0 leaves by eth0 rather than ranet3",
		},
		{
			Advertise: advertise, Ready: []string{"ipv4", "ipv6"}, Announced: advertise,
			Skipped: "lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay",
		},
		{
			Advertise: linkLocal, Ready: []string{"ipv4", "ipv6"}, Announced: linkLocal,
			Skipped: "lookup skipped for fe80::/10, which holds no address the kernel takes as a unicast destination",
		},
	} {
		judged.Enabled, judged.Where, judged.Installed = true, "nftables ip ranet3, ip6 ranet3", 2
		out.WriteString(egressLine(judged) + "\n")
	}
	count, most := uint64(9000), uint64(262144)
	for _, limited := range []EgressStatus{
		{FlowsPerSource: 4096, ConntrackCount: &count, ConntrackMax: &most},
		{FlowsPerSource: 4096, Refused: EgressPackets{IPv4: 12}, ConntrackCount: &count, ConntrackMax: &most},
		{FlowsPerSource: 4096, Refused: EgressPackets{IPv4: 12, IPv6: 3}, Dropped: EgressPackets{IPv6: 2}, ConntrackCount: &count},
		{FlowsPerSource: 4096, Refused: EgressPackets{IPv6: 3}},
		{FlowsPerSource: 4096, Dropped: EgressPackets{IPv4: 5, IPv6: 2}},
	} {
		limited.Enabled, limited.Where, limited.Installed, limited.Flows = true, "nftables ip ranet3, ip6 ranet3", 20, 4100
		out.WriteString(egressLine(limited) + "\n")
	}
	golden(t, "status-egress.txt", []byte(out.String()))
}

// the border row follows the egress row, naming where the chain is, what it
// accepts and what each drop counted, or that it is not installed and why, and
// the egress line names the border when it holds the egress segments back
func TestStatusBorderLineRendersAsTheGoldenFile(t *testing.T) {
	status := downStatus()
	status.Down = nil
	status.Border = &BorderStatus{
		Where:  "nftables table inet ranet3 chain border",
		Inside: []string{"ranet3", "lo", "gravity"},
		Overlay: []netip.Prefix{
			netip.MustParsePrefix("23.161.104.0/24"), netip.MustParsePrefix("192.104.136.0/24"), netip.MustParsePrefix("204.115.20.0/23"),
			netip.MustParsePrefix("2602:f590::/36"), netip.MustParsePrefix("2a0c:b641:69c::/48"),
		},
		SIDs:      []netip.Addr{netip.MustParseAddr("2a0c:b641:69c:5d26::3")},
		Ready:     true,
		PassAt:    time.Date(2026, 10, 19, 9, 14, 2, 0, time.UTC),
		Installed: 11,
		Dropped:   BorderDrops{OverlaySourceIPv4: 3, OverlaySourceIPv6: 1, RoutingHeader: 2, SIDDestination: 5},
	}
	var out strings.Builder
	RenderStatus(&out, status)
	goldenJSON(t, "status-border.json", status.Border)
	out.WriteString("\n")
	where := "nftables table inet ranet3 chain border"
	for _, border := range []BorderStatus{
		{Where: where, Unready: "another writer changed its table"},
		{Where: where, Unready: "the readback differs", Err: "egress: list the rules of nftables table inet ranet3 chain border: operation not permitted"},
	} {
		out.WriteString(borderLine(border) + "\n")
	}
	out.WriteString(egressLine(EgressStatus{Enabled: true, Where: "nftables ip ranet3, ip6 ranet3", Unready: "until the border filter is read back"}) + "\n")
	golden(t, "status-border.txt", []byte(out.String()))
}

// Go's own String gives "1h3m0.5762s" for an uptime, where the digits make two
// rows harder to compare and carry nothing.
func TestShortDurationRoundsToWhatIsReadable(t *testing.T) {
	for _, test := range []struct {
		in   time.Duration
		want string
	}{
		{27234 * time.Microsecond, "27.2ms"},
		{9*time.Second + 470*time.Millisecond, "9.5s"},
		{time.Minute + 30*time.Second + 400*time.Millisecond, "1m30s"},
		{time.Hour + 3*time.Minute + 576*time.Millisecond, "1h3m0s"},
		{-time.Second, "-"},
	} {
		if got := shortDuration(test.in); got != test.want {
			t.Errorf("shortDuration(%s) = %s, want %s", test.in, got, test.want)
		}
	}
}

// The kernel line names each overlay prefix another program's rule takes and
// each endpoint the underlay's mark is answered through the tun toward, each by
// the answer that took it, ahead of the pass's error.
func TestKernelLineNamesWhatAnotherProgramsRuleTakes(t *testing.T) {
	status := KernelStatus{
		Enabled: true, Where: "table 200 protocol 155", Table: 200, Protocol: 155, Installed: 6,
		Taken: []KernelTaken{
			{Family: "ipv4", Prefix: "192.0.2.0/24", Address: "192.0.2.2", Answer: "table 51820 dev wg0"},
			{Family: "ipv6", Prefix: "3fff::/20", Address: "3fff::2", Answer: "a refusal (permission denied)"},
			{Family: "ipv4", Endpoint: "198.51.100.77", Answer: "table 200 dev ranet0"},
			{Family: "ipv4", Endpoint: "203.0.113.70", Answer: "table 200 dev ranet0"},
		},
		Err: "add rule priority 5110: file exists",
	}
	golden(t, "kernel-taken.txt", []byte(kernelLine(status)+"\n"))
	goldenJSON(t, "kernel-taken.json", status)
	if line := kernelLine(KernelStatus{Enabled: true, Where: "table 200 protocol 155"}); strings.Contains(line, "taken") {
		t.Errorf("the kernel line reads %q with nothing taken, want no taken clause", line)
	}
}

// The kernel line names the families whose default went in as the zero-free
// cover, since `ranet3 routes` shows the /0 and the kernel holds other routes
// in its place.
func TestKernelLineNamesTheCoveredFamilies(t *testing.T) {
	status := KernelStatus{Enabled: true, Where: "interface utun6", Installed: 16, Cover: []string{"ipv4", "ipv6"}}
	golden(t, "kernel-cover.txt", []byte(kernelLine(status)+"\n"))
	goldenJSON(t, "kernel-cover.json", status)
	if line := kernelLine(KernelStatus{Enabled: true, Where: "interface utun6"}); strings.Contains(line, "cover") {
		t.Errorf("the kernel line reads %q with nothing covered, want no cover clause", line)
	}
}

// The egress line leads with the prefixes being announced rather than with the
// ones configured. The two differ exactly when the capability is not working,
// since a prefix is announced only while its family is ready, and that
// difference is the reason to read the line at all.
func TestEgressLineNamesTheWithheldPrefixes(t *testing.T) {
	carried := netip.MustParsePrefix("198.51.100.0/24")
	withheld := netip.MustParsePrefix("2001:db8:1::/48")
	for name, test := range map[string]struct {
		status   EgressStatus
		want     string
		unwanted string
	}{
		"off": {
			status:   EgressStatus{},
			want:     "carries no traffic for others",
			unwanted: "announcing",
		},
		"everything announced": {
			status: EgressStatus{Enabled: true, Where: "a table", Installed: 2,
				Advertise: []netip.Prefix{carried}, Announced: []netip.Prefix{carried}},
			want:     "announcing 198.51.100.0/24",
			unwanted: "withholding",
		},
		"half withheld": {
			status: EgressStatus{Enabled: true, Where: "a table", Installed: 1,
				Advertise: []netip.Prefix{carried, withheld}, Announced: []netip.Prefix{carried}},
			want: "withholding 2001:db8:1::/48",
		},
		"sharing the hook": {
			status: EgressStatus{Enabled: true, Where: "a table",
				Conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}},
			want: "sharing the hook with ip table nat chain POSTROUTING",
		},
	} {
		t.Run(name, func(t *testing.T) {
			line := egressLine(test.status)
			if !strings.Contains(line, test.want) {
				t.Errorf("the egress line reads %q, want it to carry %q", line, test.want)
			}
			if test.unwanted != "" && strings.Contains(line, test.unwanted) {
				t.Errorf("the egress line reads %q, want it not to mention %q", line, test.unwanted)
			}
		})
	}
}
