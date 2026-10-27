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
}

func (f *fakeNetlink) execute(kind, flags uint16, body []byte) ([]nlMessage, error) {
	f.sent = append(f.sent, struct {
		kind, flags uint16
		body        []byte
	}{kind, flags, body})
	return f.replies, f.err
}

func (f *fakeNetlink) link(uint32, string) (linkInfo, error) { return linkInfo{}, unix.ENODEV }

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

// a throw route goes out as RTN_THROW with no device, and reads back as itself
// from the dump of either family, an IPv6 one naming lo as its device
func TestLinuxWritesAndReadsAThrowRoute(t *testing.T) {
	for _, destination := range []string{"203.0.113.128/25", "2001:db8:c:8000::/49"} {
		plat, conn := writePlatform(t)
		thrown := Route{Destination: netip.MustParsePrefix(destination), Throw: true, Metric: holdMetric}
		if err := plat.AddRoute(thrown); err != nil {
			t.Fatalf("install the throw route: %v", err)
		}
		sent := conn.sent[0].body
		if sent[7] != unix.RTN_THROW {
			t.Errorf("%s was written as route type %d, want RTN_THROW", thrown, sent[7])
		}
		dumped := slices.Clone(sent)
		for attr := range (nlMessage{Kind: unix.RTM_NEWROUTE, Data: sent}).attributes(unix.SizeofRtMsg) {
			if attr == unix.RTA_OIF {
				t.Errorf("%s names an output device", thrown)
			}
		}
		if thrown.Destination.Addr().Is6() {
			dumped = putAttrU32(dumped, unix.RTA_OIF, 1)
		}
		got, ok := plat.decodeRoute(nlMessage{Kind: unix.RTM_NEWROUTE, Data: dumped})
		if !ok || got != thrown {
			t.Errorf("%s read back as %v (kept %v)", thrown, got, ok)
		}
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
	got, err := plat.foreignWriters()
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
	if _, err := plat.foreignWriters(); err != nil {
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
	if writers, err := plat.foreignWriters(); err != nil || len(writers) != 0 {
		t.Errorf("the census of a table that does not exist yet read as %v and %v, want nobody", writers, err)
	}
	if _, err := plat.Addrs(); !errors.Is(err, unix.ENOENT) {
		t.Errorf("an address dump ending on ENOENT read as %v, want the errno", err)
	}
	if _, err := plat.Rules(); !errors.Is(err, unix.ENOENT) {
		t.Errorf("a rule dump ending on ENOENT read as %v, want the errno", err)
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
	writers, err := plat.foreignWriters()
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

// a read's mark goes out as RTA_MARK on its own lookup alone, so a marked read
// walks the rules the underlay's packets walk while its reply read and an
// unmarked read walk those of every other packet
func TestBatchSendsAReadsMarkOnItsLookupAlone(t *testing.T) {
	answer := make([]byte, unix.SizeofRtMsg)
	answer[0], answer[7] = unix.AF_INET, unix.RTN_UNICAST
	answer = putAttrU32(answer, unix.RTA_OIF, 3)
	conn := &fakeNetlink{replies: []nlMessage{{Kind: unix.RTM_NEWROUTE, Data: answer}}}
	const mark = 0x72
	reads := []RouteRead{
		{Source: netip.MustParseAddr("198.51.100.10"), Destination: netip.MustParseAddr("203.0.113.70"), Mark: mark, Reply: true},
		{Destination: netip.MustParseAddr("192.0.2.2")},
	}
	if _, err := routeGetBatch(conn, reads); err != nil {
		t.Fatalf("batch: %v", err)
	}
	var lookups [][]byte
	for _, sent := range conn.sent {
		if sent.kind == unix.RTM_GETROUTE {
			lookups = append(lookups, sent.body)
		}
	}
	if len(lookups) != 3 {
		t.Fatalf("the batch sent %d lookups, want the marked read, its reply and the unmarked read", len(lookups))
	}
	for i, want := range []uint32{mark, 0, 0} {
		var got uint32
		for attr, value := range (nlMessage{Kind: unix.RTM_GETROUTE, Data: lookups[i]}).attributes(unix.SizeofRtMsg) {
			if attr == unix.RTA_MARK && len(value) == 4 {
				got = binary.NativeEndian.Uint32(value)
			}
		}
		if got != want {
			t.Errorf("lookup %d carried mark %#x, want %#x", i, got, want)
		}
	}
}
