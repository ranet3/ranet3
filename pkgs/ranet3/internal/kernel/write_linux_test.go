// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// fakeNetlink stands in for the socket so what this backend writes can be read
// back without root. Every other check of the write path needs a real netlink
// socket and /dev/net/tun, so none of them runs in the nix sandbox.
type fakeNetlink struct {
	sent []struct {
		kind, flags uint16
		body        []byte
	}
	replies []nlMessage
	err     error
	// links is every device the fake kernel holds, a name missing here being one nothing holds
	links []linkInfo
}

func (f *fakeNetlink) execute(kind, flags uint16, body []byte) ([]nlMessage, error) {
	f.sent = append(f.sent, struct {
		kind, flags uint16
		body        []byte
	}{kind, flags, body})
	return f.replies, f.err
}

func (f *fakeNetlink) link(index uint32, name string) (linkInfo, error) {
	for _, link := range f.links {
		if index != 0 && index == link.index || index == 0 && name == link.name {
			return link, nil
		}
	}
	return linkInfo{}, unix.ENODEV
}

func (f *fakeNetlink) Close() error { return nil }

func writePlatform(t *testing.T) (*netlinkPlatform, *fakeNetlink) {
	t.Helper()
	conn := &fakeNetlink{}
	return &netlinkPlatform{
		table: Table{ID: 200, Proto: DefaultProtocol}, rt: Runtime{Interface: "ranet0"},
		index:    7,
		conn:     conn,
		occupied: map[Route]bool{}, refused: map[Route]bool{},
	}, conn
}

// A retracted prefix is held as an unreachable route rather than removed, so
// traffic for it is answered with an error instead of following a covering
// route somewhere else. Installing it as an ordinary path would send that
// traffic out of the tun to a peer that no longer announces it.
func TestLinuxInstallsHoldAsUnreachableRoute(t *testing.T) {
	plat, conn := writePlatform(t)
	held := Route{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Unreachable: true}
	if err := plat.AddRoute(held); err != nil {
		t.Fatalf("install the hold: %v", err)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("the install wrote %d messages, want 1", len(conn.sent))
	}
	sent := conn.sent[0]
	if sent.kind != unix.RTM_NEWROUTE {
		t.Errorf("wrote message type %d, want RTM_NEWROUTE", sent.kind)
	}
	if sent.flags&unix.NLM_F_EXCL == 0 || sent.flags&unix.NLM_F_CREATE == 0 {
		t.Errorf("flags %#x: a replace takes over whatever sits at the same key, whoever wrote it", sent.flags)
	}
	if got := sent.body[7]; got != unix.RTN_UNREACHABLE {
		t.Errorf("the hold was written as route type %d, want RTN_UNREACHABLE", got)
	}
	// A route that resolves to an error has no output interface: fib_check_nh
	// is not consulted for one, and naming a device makes the kernel refuse it.
	for attr := range (nlMessage{Kind: unix.RTM_NEWROUTE, Data: sent.body}).attributes(unix.SizeofRtMsg) {
		if attr == unix.RTA_OIF {
			t.Error("the hold names an output interface, which the kernel refuses")
		}
	}

	// A path to the same prefix is not a hold, and is written as one.
	plat, conn = writePlatform(t)
	if err := plat.AddRoute(Route{Destination: held.Destination}); err != nil {
		t.Fatalf("install the path: %v", err)
	}
	if got := conn.sent[0].body[7]; got != unix.RTN_UNICAST {
		t.Errorf("a path was written as route type %d, want RTN_UNICAST", got)
	}
}

// A prefix another writer already holds is reported as skipped rather than as
// a failure. Reported as a failure it would put the whole pass into backoff
// over a key no retry can free, once per pass, for the life of the process.
func TestLinuxReportsOccupiedRouteAsSkipped(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.err = unix.EEXIST
	route := Route{Destination: netip.MustParsePrefix("2001:db8:2::/48")}
	for attempt := range 2 {
		if err := plat.AddRoute(route); !errors.Is(err, errRouteSkipped) {
			t.Errorf("attempt %d reported %v, want the route reported as not installed", attempt, err)
		}
	}
	// And it is not mistaken for an install: the next pass has to try again.
	if !plat.occupied[route] {
		t.Error("the refusal was not recorded, so the warning repeats once a pass")
	}

	// Once the key frees up the record goes with it, or a later refusal is
	// silent.
	conn.err = nil
	if err := plat.AddRoute(route); err != nil {
		t.Fatalf("install after the key freed: %v", err)
	}
	if plat.occupied[route] {
		t.Error("the route installed and is still recorded as held by somebody else")
	}
}

// the kernel takes a preferred source only when it is local in the route's own table or in the local table
// an address on a link inside a vrf bound to another table is local in neither
// the refusal names that rule and the table, not a missing address that is there
func TestLinuxNamesTheRuleAPreferredSourceBroke(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.err = unix.EINVAL
	err := plat.AddRoute(Route{Destination: netip.MustParsePrefix("10.0.0.0/8"), PrefSrc: netip.MustParseAddr("10.99.0.1")})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("the refusal lost its errno: %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "local address in table 200 or in the local table") || strings.Contains(msg, "of this host") {
		t.Errorf("the refusal reads %q, want the rule the kernel applies and the table it applied it in", msg)
	}
}

// Withdrawing matches on this reconciler's own protocol, so a route another
// writer put at the same prefix stays.
func TestLinuxWithdrawalNamesOurOwnProtocol(t *testing.T) {
	plat, conn := writePlatform(t)
	if err := plat.DelRoute(Route{Destination: netip.MustParsePrefix("2001:db8:3::/48")}); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(conn.sent) != 1 || conn.sent[0].kind != unix.RTM_DELROUTE {
		t.Fatalf("the withdrawal wrote %d messages", len(conn.sent))
	}
	if got := conn.sent[0].body[5]; got != DefaultProtocol {
		t.Errorf("the withdrawal named protocol %d, want this reconciler's own %d", got, DefaultProtocol)
	}
	// A route that is already gone is not an error: the reconciler and the
	// kernel disagreeing about one is ordinary and self-correcting.
	plat, conn = writePlatform(t)
	conn.err = unix.ESRCH
	if err := plat.DelRoute(Route{Destination: netip.MustParsePrefix("2001:db8:4::/48")}); err != nil {
		t.Errorf("withdrawing a route that was already gone reported %v", err)
	}
}

// foreignWriters reports another routing daemon exporting into the
// table this reconciler owns, which on the fleet means BIRD and this node
// each displacing the other's routes and waking each other's scan. It dumps
// both families and had no test of any kind: the classifier it calls was
// covered, the dump around it was not, so it could have asked for one family,
// or for the wrong table, unnoticed.
func TestLinuxForeignWritersDumpsBothFamilies(t *testing.T) {
	plat, conn := writePlatform(t)
	const ourTable, ourProtocol = 200, DefaultProtocol
	conn.replies = []nlMessage{
		// Somebody else exporting into our table, which this reports.
		routeDump(ourTable, 187, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.0.0/24")),
		// Our own routes, which are not foreign.
		routeDump(ourTable, ourProtocol, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.1.0/24")),
	}
	got, err := plat.foreignWriters(false)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if len(got) != 1 || got[0] != "isis (187)" {
		t.Errorf("reported protocols %v, want just the one writing into our table", got)
	}
	var families []uint8
	for _, sent := range conn.sent {
		if sent.kind == unix.RTM_GETROUTE && sent.flags&unix.NLM_F_DUMP != 0 {
			families = append(families, sent.body[0])
		}
	}
	if !slices.Contains(families, uint8(unix.AF_INET)) || !slices.Contains(families, uint8(unix.AF_INET6)) {
		t.Errorf("the dump asked for families %v, want both AF_INET and AF_INET6", families)
	}
}

// both dumps of the table name it
// the one reading routes back names the protocol too
// the kernel then filters them
// unfiltered, every pass read every route on the host, a full table in main included
// the configured table is 201 rather than the default
// a dump asking for the default table then names the wrong one
func TestLinuxDumpsCarryTheTableFilter(t *testing.T) {
	plat, conn := writePlatform(t)
	plat.table.ID = 201
	if _, err := plat.Routes(); err != nil {
		t.Fatal(err)
	}
	if _, err := plat.foreignWriters(false); err != nil {
		t.Fatal(err)
	}
	if len(conn.sent) != 4 {
		t.Fatalf("the two reads sent %d requests, want a dump per family each", len(conn.sent))
	}
	for i, sent := range conn.sent {
		// the census asks for every protocol in the table
		protocol := uint8(DefaultProtocol)
		if i >= 2 {
			protocol = 0
		}
		if sent.kind != unix.RTM_GETROUTE || sent.flags&unix.NLM_F_DUMP == 0 || sent.body[5] != protocol {
			t.Errorf("request %d is type %d, flags %#x and protocol %d, want a route dump of protocol %d", i, sent.kind, sent.flags, sent.body[5], protocol)
		}
		table := uint32(0)
		for kind, value := range (nlMessage{Data: sent.body}).attributes(unix.SizeofRtMsg) {
			if kind == unix.RTA_TABLE && len(value) == 4 {
				table = binary.NativeEndian.Uint32(value)
			}
		}
		if table != 201 {
			t.Errorf("request %d names table %d, want 201", i, table)
		}
	}
}

// endingOn is a socket on which the kernel ends every request with errno
// the end goes through collect, as every answer of a real socket does
type endingOn unix.Errno

func (e endingOn) execute(uint16, uint16, []byte) ([]nlMessage, error) {
	end := nlMessage{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Seq: 1, Pid: 1,
		Data: binary.NativeEndian.AppendUint32(nil, uint32(-int32(e)))}
	return collect(1, 1, func() ([]nlMessage, error) { return []nlMessage{end}, nil })
}

func (endingOn) link(uint32, string) (linkInfo, error) { return linkInfo{}, unix.ENODEV }
func (endingOn) Close() error                          { return nil }

// a table nothing has written yet does not exist
// the kernel ends a dump filtered on it with ENOENT, which every fresh node meets
// the table's own two dumps read that as an empty table
// an ENOENT ending any other dump stays the failure it is
func TestLinuxReadsATableNothingWroteAsEmpty(t *testing.T) {
	plat, _ := writePlatform(t)
	plat.conn = endingOn(unix.ENOENT)
	if routes, err := plat.Routes(); err != nil || len(routes) != 0 {
		t.Errorf("a table that does not exist yet read as %v and %v, want it empty", routes, err)
	}
	if writers, err := plat.foreignWriters(false); err != nil || len(writers) != 0 {
		t.Errorf("the census of a table that does not exist yet read as %v and %v, want nobody", writers, err)
	}
	if _, err := plat.Addrs(); !errors.Is(err, unix.ENOENT) {
		t.Errorf("an address dump ending on ENOENT read as %v, want the errno", err)
	}
	if _, err := plat.Rules(); !errors.Is(err, unix.ENOENT) {
		t.Errorf("a rule dump ending on ENOENT read as %v, want the errno", err)
	}
}

// the census and the binding check run on the linux platform itself
// the table is not the default one and the vrf is not named mesh
// a check that compares against DefaultTable or reads a vrf by a fixed name fails a case here
// a vrf that existed first keeps whatever table it was bound to
// the configured name proves nothing about that table, which the kernel is asked for
func TestLinuxCensusAndBindingReadTheConfiguredTableAndVRF(t *testing.T) {
	for name, test := range map[string]struct {
		bound   uint32
		want    []string
		without []string
	}{
		"vrf bound to the configured table": {
			bound:   201,
			want:    []string{"bird (12)"},
			without: []string{"kernel (2)", "bound to another table"},
		},
		"vrf bound to another table": {
			bound: 300,
			want:  []string{"bird (12)", "kernel (2)", "bound to another table", `"vrf_table":300`, `"table":201`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			plat, conn := writePlatform(t)
			plat.table.ID = 201
			plat.table.VRF = &VRF{Name: "gravity"}
			conn.links = []linkInfo{
				{index: 7, name: "ranet0", master: 9},
				{index: 9, name: "gravity", vrfTable: test.bound},
				{index: 11, name: "mesh", vrfTable: 999},
			}
			conn.replies = []nlMessage{
				routeDump(201, unix.RTPROT_BIRD, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.0.0/24")),
				routeDump(201, unix.RTPROT_KERNEL, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.1.0/24")),
			}
			reconciler := newReconciler(plat.table, plat.rt, nil, nil, netstack.NewRouteTable(), plat)
			logs := captureKernelLogs(t)
			reconciler.audit()
			if err := reconciler.reconcile(); err != nil {
				t.Fatalf("pass: %v", err)
			}
			got := logs.String()
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("the census and the pass said %q, want them to include %s", got, want)
				}
			}
			for _, not := range test.without {
				if strings.Contains(got, not) {
					t.Errorf("the census and the pass said %q, want nothing about %s", got, not)
				}
			}
		})
	}
}

// a vrf nothing has made yet reads as bound to no table rather than as a failure
// every fresh start with create set meets one
func TestLinuxVRFTableReadsAMissingVRFAsUnbound(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.links = []linkInfo{{index: 9, name: "mesh", vrfTable: 300}, {index: 10, name: "dummy0"}}
	for name, want := range map[string]uint32{"mesh": 300, "dummy0": 0, "absent": 0} {
		if got, err := plat.VRFTable(name); err != nil || got != want {
			t.Errorf("%s read as bound to %d (err %v), want %d", name, got, err, want)
		}
	}
}

// a device of another kind holding the vrf's name is refused by name, and the tun is never handed to it
// the kernel answers that enslave with a bare errno on every pass, naming neither the device nor its kind
func TestLinuxEnslavesTheTunOnlyToAVRF(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.links = []linkInfo{{index: 9, name: "mesh"}}
	if err := plat.Enslave("mesh"); err == nil || !strings.Contains(err.Error(), "mesh is not a vrf") {
		t.Errorf("enslaving to a device that is not a vrf reported %v", err)
	}
	if len(conn.sent) != 0 {
		t.Fatalf("the refusal still wrote %d messages", len(conn.sent))
	}
	conn.links[0].vrfTable = 200
	if err := plat.Enslave("mesh"); err != nil {
		t.Fatalf("enslave to a vrf: %v", err)
	}
	if len(conn.sent) != 1 || conn.sent[0].kind != unix.RTM_NEWLINK {
		t.Fatalf("the enslave wrote %d messages", len(conn.sent))
	}
	for kind, value := range (nlMessage{Data: conn.sent[0].body}).attributes(unix.SizeofIfInfomsg) {
		if kind == unix.IFLA_MASTER && binary.NativeEndian.Uint32(value) != 9 {
			t.Errorf("the tun was handed to master %d, want the vrf's index 9", binary.NativeEndian.Uint32(value))
		}
	}
}

// lookupFails is the fake whose lookups fail from the nth on
// every other request is answered as the fake answers it
type lookupFails struct {
	*fakeNetlink
	lookups, from int
}

func (f *lookupFails) link(index uint32, name string) (linkInfo, error) {
	if f.lookups++; f.lookups >= f.from {
		return linkInfo{}, unix.ENOBUFS
	}
	return f.fakeNetlink.link(index, name)
}

// a vrf made and then not found by the lookup after it has an index nobody read
// no stop could remove it by that index
// it is deleted by name before the error returns
// the next pass then makes it again and reads the index back
func TestLinuxRemovesAVRFItMadeAndCouldNotLookUp(t *testing.T) {
	plat, conn := writePlatform(t)
	plat.conn = &lookupFails{fakeNetlink: conn, from: 2}
	if index, err := plat.EnsureVRF("mesh", 200); !errors.Is(err, unix.ENOBUFS) || index != 0 {
		t.Fatalf("a vrf whose lookup failed after the create reported index %d and %v", index, err)
	}
	if len(conn.sent) != 2 || conn.sent[0].kind != unix.RTM_NEWLINK || conn.sent[1].kind != unix.RTM_DELLINK {
		t.Fatalf("the create and the failed lookup after it wrote %d messages, want the create and a delete", len(conn.sent))
	}
	removed := conn.sent[1]
	name := ""
	for kind, value := range (nlMessage{Data: removed.body}).attributes(unix.SizeofIfInfomsg) {
		if kind == unix.IFLA_IFNAME {
			name = unix.ByteSliceToString(value)
		}
	}
	if index := binary.NativeEndian.Uint32(removed.body[4:]); index != 0 || name != "mesh" {
		t.Errorf("the delete named index %d and device %q, want mesh by its name", index, name)
	}
	// without the ack the kernel sends nothing back, and the request waits forever
	if removed.flags&unix.NLM_F_ACK == 0 {
		t.Errorf("the delete carries flags %#x, without the ack", removed.flags)
	}
}

// The report reaches an operator through slog, whose text handler quotes
// anything shaped like a byte slice rather than listing it, so a []uint8 of
// protocols 2 and 12 arrived on a live fleet node as protocols="\x02\f" and
// told nobody anything. Rendering therefore belongs to this report rather than
// to its caller, and this asserts the line as printed.
func TestForeignWriterReportRendersReadably(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.replies = []nlMessage{
		routeDump(200, unix.RTPROT_BIRD, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.0.0/24")),
		routeDump(200, unix.RTPROT_KERNEL, unix.RTN_UNICAST, 7, netip.MustParsePrefix("10.99.1.0/24")),
	}
	writers, err := plat.foreignWriters(false)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	var out bytes.Buffer
	slog.New(slog.NewTextHandler(&out, nil)).Warn("sharing", "protocols", strings.Join(writers, ", "))
	line := out.String()
	for _, want := range []string{"bird (12)", "kernel (2)"} {
		if !strings.Contains(line, want) {
			t.Errorf("the report printed %q, want it to name %s", line, want)
		}
	}
	// The defect printed the numbers as raw bytes, and every protocol worth
	// reporting lands on a control character under that spelling.
	if strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 && r != '\n' }) {
		t.Errorf("the report printed %q, carrying the protocol numbers as bytes rather than as text", line)
	}
}

// An unclaimed number has no name to print, and dropping it rather than
// printing the number would hide the writer the report exists to name.
func TestForeignWriterReportNamesAnUnclaimedProtocolByNumber(t *testing.T) {
	if got, want := protocolLabel(155), "155"; got != want {
		t.Errorf("protocol 155 printed as %q, want %q", got, want)
	}
	if got, want := protocolLabel(unix.RTPROT_BABEL), "babel (42)"; got != want {
		t.Errorf("babel printed as %q, want %q", got, want)
	}
}

// On linux the space this reconciler owns is a routing table, which an
// operator reads in the startup line and what the policy rules look up.
func TestLinuxOwnsATable(t *testing.T) {
	plat, _ := writePlatform(t)
	if got := plat.where(plat.table); got != "table 200 protocol 155" {
		t.Errorf("linux reports %q, want the table it owns", got)
	}
}

// The warn-once record is rebuilt by the passes that refuse, so it may only
// rotate for a pass that goes on to install. A dump that fails returns before
// any AddRoute refills it, and two such passes would empty it, so the warning
// a foreign route draws would repeat once a pass for as long as the dump is
// broken, which is exactly when an operator has least use for it.
func TestLinuxKeepsTheRefusalRecordThroughAFailedDump(t *testing.T) {
	plat, conn := writePlatform(t)
	held := Route{Destination: netip.MustParsePrefix("2001:db8:2::/48")}
	conn.err = unix.EEXIST
	if err := plat.AddRoute(held); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the refused install reported %v", err)
	}
	if !plat.occupied[held] {
		t.Fatal("the refusal was not recorded, so this proves nothing")
	}

	conn.err = errors.New("netlink says no")
	for pass := range 2 {
		if _, err := plat.Routes(); err == nil {
			t.Fatalf("pass %d: a failed dump reported success", pass)
		}
	}
	if !plat.occupied[held] {
		t.Error("two passes that never dumped emptied the record, so the warning repeats once a pass")
	}
}
