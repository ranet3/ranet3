// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pf"
)

// the root tests' addressing, all documentation space: the mesh utun's own
// addresses inside the overlay of 192.0.2.0/24 and 3fff:10::/32, a forged
// source inside it, and the loopback addresses. Each outside utun's come from
// its outside method.
var (
	pfMesh4     = netip.MustParseAddr("192.0.2.1")
	pfMesh6     = netip.MustParseAddr("3fff:10::1")
	pfForged4   = netip.MustParseAddr("192.0.2.77")
	pfForged6   = netip.MustParseAddr("3fff:10::77")
	pfLoopback4 = netip.MustParseAddr("127.0.0.1")
	pfLoopback6 = netip.MustParseAddr("::1")
)

const (
	pfctlBin    = "/sbin/pfctl"
	ifconfigBin = "/sbin/ifconfig"
	netstatBin  = "/usr/sbin/netstat"

	// how long a test waits for a datagram it expects at a socket
	pfArrival = 500 * time.Millisecond
	// two of the pages' 5 s periods and the pass's own time, within which a
	// pass puts back what another program changed, written out so a longer
	// period misses it
	pfTwoPeriods = 12 * time.Second
	// pfLaterAnchor is a child of com.apple that sorts after the filter's, so
	// the main ruleset's call evaluates it later
	pfLaterAnchor = "com.apple/ranet3-later"
	// pfCallAnchor is a child of com.apple that sorts after the filter's,
	// into which the call test loads each form of a call into com.apple/*,
	// which there names the children of pfCallAnchor/com.apple, and the probe
	// one of those holds
	pfCallAnchor  = "com.apple/ranet3-call"
	pfProbeAnchor = pfCallAnchor + "/com.apple/probe"
	// pfPort is the port a test's datagram goes to and its listener reads
	pfPort = 9
)

// with no overlay written darwin runs no filter and opens no backend, whose
// reference on pf would fail without root and be listed under this process
// with it, a start with no state directory to record in is refused, and with
// overlay the filter's list holds the antispoof chain's rules but the tun's
// accept, folded into each drop, and no rule of the entry chain, which darwin
// does not write
func TestPfBorderRunsOnlyWhereOverlayIsWritten(t *testing.T) {
	if Filters(nil) || !Filters(overlay(t, "192.0.2.0/24")) || borderSweep != 5*time.Second {
		t.Errorf("darwin filters with no overlay %v, with overlay %v, and sweeps every %v",
			Filters(nil), Filters(overlay(t, "192.0.2.0/24")), borderSweep)
	}
	// a state directory holding no record, so the start runs no pfctl
	if f, err := NewBorderFilter(nil, egress.BorderRuntime{Tun: "utun250", StateDir: t.TempDir()}); f != nil || err != nil {
		t.Errorf("with no overlay NewBorderFilter returned %v (%v), want no filter", f, err)
		if f != nil {
			_ = f.finish()
		}
	}
	if _, err := NewBorderFilter(nil, egress.BorderRuntime{Tun: "utun250"}); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Errorf("a start with no state directory returned %v, want a refusal naming it", err)
	}
	p := &fakePF{}
	be := &borderPF{ctl: p, ref: newFakeReference(p), anchor: pfAnchor, tun: "utun250"}
	f := newBorderFilter(overlay(t, "192.0.2.0/24", "3fff:10::/32"), pfRuntime("utun250", "", nil), be)
	rules, _, _ := f.desired()
	p4, p6 := netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("3fff:10::/32")
	if want := []BorderRule{{Class: BorderInside, Device: "lo0"}, {Class: BorderSource, Source: p4}, {Class: BorderSource, Source: p6, IPv6: true}}; !slices.Equal(rules, want) {
		t.Errorf("the filter's list holds %v, want %v", rules, want)
	}
}

// the start's refusal holds an exemption's interface name pf cannot write to
// the filter that would write it, which runs only where overlay is written
func TestBorderRefusalRunsOnlyWhereOverlayIsWritten(t *testing.T) {
	cfg := overlay(t, "192.0.2.0/24")
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"br-lan": {Exempt: prefixes(t, "192.0.2.32/27")}}}
	if err := RefuseBorder(cfg); err == nil || !strings.Contains(err.Error(), `"br-lan"`) {
		t.Errorf("with overlay the refusal returned %v, want br-lan named", err)
	}
	if err := RefuseBorder(nil); err != nil {
		t.Errorf("with no overlay the refusal returned %v", err)
	}
}

// requirePF skips where the test may not drive the real pf, where the main
// ruleset calls no child of com.apple, and where the filter's anchor holds
// anything already, which is then a daemon's of this host. At the end it
// fails a test that left the anchor holding anything, a reference of this
// process held, or pf running otherwise than it found it, and puts the first
// two back.
func requirePF(t *testing.T) pf.Ctl {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to drive the real pf")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to drive the real pf and create a utun")
	}
	ctl := pf.NewCtl()
	if called, err := ctl.Calls(); err != nil || !called {
		t.Skipf("the main ruleset does not call com.apple/* (%v), so pf evaluates no rule of %s", err, pfAnchor)
	}
	read, err := ctl.Read(pfAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Rules) != 0 || len(read.Tables) != 0 {
		t.Skipf("%s holds %+v already, which a daemon of this host wrote", pfAnchor, read)
	}
	was := pfRunning(t)
	t.Cleanup(func() {
		if read, err := ctl.Read(pfAnchor); err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
			t.Errorf("the test left %s holding %+v (%v)", pfAnchor, read, err)
			_ = ctl.Withdraw(pfAnchor)
		}
		enablers, err := ctl.References()
		if err != nil {
			t.Error(err)
			return
		}
		for _, enabler := range enablers {
			if enabler.PID == os.Getpid() {
				t.Errorf("the test left its reference %d held", enabler.Token)
				_ = ctl.Release(enabler.Token)
			}
		}
		if running := pfRunning(t); running != was {
			t.Errorf("the test left pf running %v, which it found running %v", running, was)
		}
	})
	return ctl
}

func pfRunning(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command(pfctlBin, "-s", "info").CombinedOutput()
	if err != nil {
		t.Fatalf("pfctl -s info: %v: %s", err, out)
	}
	return strings.Contains(string(out), "Status: Enabled")
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
}

// pfUTUN is a utun the test holds by its control descriptor, which takes the
// utun with its addresses and routes when it closes
type pfUTUN struct {
	name  string
	fd    int
	index int
}

func newPFUTUN(t *testing.T) *pfUTUN {
	t.Helper()
	const (
		utunControl = "com.apple.net.utun_control"
		// SYSPROTO_CONTROL and UTUN_OPT_IFNAME, neither of which
		// golang.org/x/sys/unix carries
		sysprotoControl = 2
		utunOptIfname   = 2
	)
	connect := func() (int, error) {
		fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
		if err != nil {
			return -1, err
		}
		info := &unix.CtlInfo{}
		copy(info.Name[:], utunControl)
		if err := unix.IoctlCtlInfo(fd, info); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		// unit 0 asks for the first free utun, so the test never lands on one
		// another program holds
		if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	fd, err := connect()
	for deadline := time.Now().Add(5 * time.Second); errors.Is(err, unix.EBUSY) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		fd, err = connect()
	}
	if err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("read the new utun's name: %v", err)
	}
	device, err := net.InterfaceByName(name)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("index of %s: %v", name, err)
	}
	u := &pfUTUN{name: name, fd: fd, index: device.Index}
	t.Cleanup(func() { _ = unix.Close(u.fd) })
	return u
}

// alias adds one address to the utun as ranet3 does, an IPv4 address with
// itself as the destination and an IPv6 address with none
func (u *pfUTUN) alias(t *testing.T, p netip.Prefix) {
	t.Helper()
	if p.Addr().Is4() {
		mustRun(t, ifconfigBin, u.name, "inet", p.String(), p.Addr().String(), "alias")
		return
	}
	mustRun(t, ifconfigBin, u.name, "inet6", p.String(), "alias")
}

func (u *pfUTUN) up(t *testing.T) {
	t.Helper()
	mustRun(t, ifconfigBin, u.name, "up")
}

// owned gives the utun the mesh's own addresses and brings it up
func (u *pfUTUN) owned(t *testing.T) {
	t.Helper()
	u.alias(t, netip.PrefixFrom(pfMesh4, 32))
	u.alias(t, netip.PrefixFrom(pfMesh6, 128))
	u.up(t)
}

// inject hands the kernel datagram as though it arrived on the utun
func (u *pfUTUN) inject(t *testing.T, datagram []byte) {
	t.Helper()
	family := byte(unix.AF_INET)
	if datagram[0]>>4 == 6 {
		family = unix.AF_INET6
	}
	if _, err := unix.Write(u.fd, append([]byte{0, 0, 0, family}, datagram...)); err != nil {
		t.Fatalf("inject on %s: %v", u.name, err)
	}
}

// pfSend writes one datagram from a socket bound to source, held to the
// interface boundIf where it is not zero, and returns the send's error
func pfSend(source netip.Addr, boundIf int, destination netip.Addr, payload []byte) error {
	family, level, option := unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
	if source.Is6() {
		family, level, option = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if boundIf != 0 {
		if err := unix.SetsockoptInt(fd, level, option, boundIf); err != nil {
			return fmt.Errorf("hold to interface %d: %w", boundIf, err)
		}
	}
	var local, remote unix.Sockaddr
	if source.Is4() {
		local = &unix.SockaddrInet4{Addr: source.As4()}
		remote = &unix.SockaddrInet4{Addr: destination.As4(), Port: 9}
	} else {
		own := &unix.SockaddrInet6{Addr: source.As16()}
		to := &unix.SockaddrInet6{Addr: destination.As16(), Port: 9}
		// only a link-scoped address takes a zone, the interface it is held to
		if source.IsLinkLocalUnicast() {
			own.ZoneId = uint32(boundIf)
		}
		if destination.IsLinkLocalUnicast() || destination.IsLinkLocalMulticast() {
			to.ZoneId = uint32(boundIf)
		}
		local, remote = own, to
	}
	// an IPv6 address may still be tentative just after it was added
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		err = unix.Bind(fd, local)
		if err == nil || !errors.Is(err, unix.EADDRNOTAVAIL) || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("bind %s: %w", source, err)
	}
	return unix.Sendto(fd, payload, 0, remote)
}

// udpDatagram is a UDP datagram from source to destination's port 9, of
// either family
func udpDatagram(source, destination netip.Addr, payload []byte) []byte {
	return udpBetween(netip.AddrPortFrom(source, 40000), netip.AddrPortFrom(destination, pfPort), payload)
}

// udpBetween is a UDP datagram from from to to, of either family
func udpBetween(from, to netip.AddrPort, payload []byte) []byte {
	source, destination := from.Addr(), to.Addr()
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], from.Port())
	binary.BigEndian.PutUint16(udp[2:], to.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	if source.Is6() {
		// UDP over IPv6 carries a checksum over a pseudo-header, RFC 8200 8.1
		pseudo := slices.Concat(source.AsSlice(), destination.AsSlice(), binary.BigEndian.AppendUint32(nil, uint32(len(udp))), []byte{0, 0, 0, unix.IPPROTO_UDP}, udp)
		if len(pseudo)%2 == 1 {
			pseudo = append(pseudo, 0)
		}
		sum := ipChecksum(pseudo)
		if sum == 0 {
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:], sum)
		header := make([]byte, 40)
		header[0] = 0x60
		binary.BigEndian.PutUint16(header[4:], uint16(len(udp)))
		header[6], header[7] = unix.IPPROTO_UDP, 64
		copy(header[8:24], source.AsSlice())
		copy(header[24:40], destination.AsSlice())
		return append(header, udp...)
	}
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:], uint16(20+len(udp)))
	header[8] = 64
	header[9] = unix.IPPROTO_UDP
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(header[10:], ipChecksum(header))
	// a zero UDP checksum over IPv4 means none was computed
	return append(header, udp...)
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// pfReached reports whether a datagram injected up the utun from source to
// destination, an address of this host, reaches a socket bound to it
func pfReached(t *testing.T, up *pfUTUN, source, destination netip.Addr) bool {
	t.Helper()
	listener := pfListen(t, destination)
	defer unix.Close(listener)
	payload := []byte(fmt.Sprintf("from %s up %s", source, up.name))
	up.inject(t, udpDatagram(source, destination, payload))
	return pfGot(listener, payload)
}

// pfSentTo reports whether a datagram from a socket bound to source reaches
// a socket bound to destination, both of this host
func pfSentTo(t *testing.T, source, destination netip.Addr) bool {
	t.Helper()
	listener := pfListen(t, destination)
	defer unix.Close(listener)
	payload := []byte(fmt.Sprintf("from %s", source))
	if err := pfSend(source, 0, destination, payload); err != nil {
		t.Fatalf("send from %s to %s: %v", source, destination, err)
	}
	return pfGot(listener, payload)
}

// pfListen binds a UDP socket to address's port, waiting out an IPv6 address
// still tentative
func pfListen(t *testing.T, address netip.Addr) int {
	t.Helper()
	family := unix.AF_INET
	var local unix.Sockaddr
	if address.Is4() {
		local = &unix.SockaddrInet4{Addr: address.As4(), Port: pfPort}
	} else {
		family, local = unix.AF_INET6, &unix.SockaddrInet6{Addr: address.As16(), Port: pfPort}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		err = unix.Bind(fd, local)
		if err == nil || !errors.Is(err, unix.EADDRNOTAVAIL) || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("bind %s port %d: %v", address, pfPort, err)
	}
	return fd
}

// pfGot reports whether the socket reads payload within pfArrival
func pfGot(fd int, payload []byte) bool {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	for deadline := time.Now().Add(pfArrival); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if n, _, err := unix.Recvfrom(fd, buf, 0); err == nil && string(buf[:n]) == string(payload) {
			return true
		}
	}
	return false
}

// pfFilterRun is a filter on the real pf over a test's utun, running until the
// test ends or stop ends it
type pfFilterRun struct {
	filter  *BorderFilter
	bus     *events.Bus
	cancel  context.CancelCauseFunc
	done    chan error
	stopped bool
	err     error
}

// pfRuntime is the filter's runtime over tun, the loopback link inside beside
// it as the daemon names it, with no carve-out and nothing carved, the
// reference recorded in dir
func pfRuntime(tun, dir string, bus *events.Bus) egress.BorderRuntime {
	return egress.BorderRuntime{Tun: tun, Inside: []string{tun, meshkernel.Loopback}, Events: bus, StateDir: dir}
}

// startPF starts the filter over tun with the overlay of 192.0.2.0/24 and
// 3fff:10::/32, recording its reference in dir
func startPF(t *testing.T, tun, dir string) *pfFilterRun {
	t.Helper()
	return startPFWith(t, overlay(t, "192.0.2.0/24", "3fff:10::/32"), pfRuntime(tun, dir, nil))
}

// startPFWith starts the filter for cfg over rt, its events on a bus of its
// own
func startPFWith(t *testing.T, cfg *egress.Border, rt egress.BorderRuntime) *pfFilterRun {
	t.Helper()
	bus := events.New()
	rt.Events = bus
	f, err := NewBorderFilter(cfg, rt)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		t.Fatal("no filter runs where overlay is written")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	run := &pfFilterRun{filter: f, bus: bus, cancel: cancel, done: make(chan error, 1)}
	go func() { run.done <- f.Run(ctx) }()
	t.Cleanup(func() {
		if err := run.stop(nil); err != nil {
			t.Errorf("the filter's stop: %v", err)
		}
	})
	return run
}

// stop ends Run once, with cause where it is not nil, and returns Run's error
func (r *pfFilterRun) stop(cause error) error {
	if !r.stopped {
		r.cancel(cause)
		r.err, r.stopped = <-r.done, true
	}
	return r.err
}

// recorded is how many events of kind the filter recorded
func (r *pfFilterRun) recorded(kind string) int {
	return len(r.bus.Recorded(func(got, _ string, _ []slog.Attr) bool { return got == kind }, 0))
}

// pfCounted is the packets each rule of the anchor matched, read from pf now,
// by the rule's String, which a debug read gives whatever label pf holds
func pfCounted(t *testing.T, f *BorderFilter) map[string]uint64 {
	t.Helper()
	debug := f.Debug()
	if debug.Err != "" {
		t.Fatalf("read the anchor: %s", debug.Err)
	}
	counted := map[string]uint64{}
	for _, chain := range debug.Chains {
		for _, rule := range chain.Rules {
			counted[rule.Spec] += rule.Packets
		}
	}
	return counted
}

// pfCounts reports whether, of the counters before and after, rule's moved
// and every other rule's stayed, so a packet met that rule alone
func pfCounts(before, after map[string]uint64, rule string) bool {
	for spec, packets := range after {
		if moved := packets != before[spec]; moved != (spec == rule) {
			return false
		}
	}
	return after[rule] > before[rule]
}

// pfQuiet reports whether no counter moved, so no rule of the anchor matched
func pfQuiet(before, after map[string]uint64) bool { return maps.Equal(before, after) }

// heldRecord is the record's references, as pf.Reference writes them
func heldRecord(t *testing.T, dir string) []pf.Enabler {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, pfRecord))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Held []struct {
			Token uint64 `json:"token,string"`
			PID   int    `json:"pid"`
		} `json:"held"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("parse the record %s: %v", raw, err)
	}
	var out []pf.Enabler
	for _, held := range record.Held {
		out = append(out, pf.Enabler{Token: held.Token, PID: held.PID})
	}
	return out
}

// listedUnder reports whether pf lists token under this process
func listedUnder(t *testing.T, ctl pf.Ctl, token uint64) bool {
	t.Helper()
	enablers, err := ctl.References()
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(enablers, func(e pf.Enabler) bool { return e.Token == token && e.PID == os.Getpid() })
}

// anchorHolds reports whether the filter's anchor holds what startPF writes,
// the lo0 pass and the two overlay drops over the overlay table, which one
// holding what the parsers cannot read does not
func anchorHolds(t *testing.T, ctl pf.Ctl) bool {
	t.Helper()
	read, err := ctl.Read(pfAnchor)
	if errors.Is(err, pf.ErrUnreadable) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(read.Rules) == 3 && len(read.Tables) == 1
}

// pfWithin polls held until it holds or bound has passed
func pfWithin(t *testing.T, bound time.Duration, held func() bool) bool {
	t.Helper()
	for deadline := time.Now().Add(bound); ; time.Sleep(100 * time.Millisecond) {
		if held() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// outside gives the utun the n-th outside link's addresses, 198.51.100.n
// with itself as far end and 2001:db8:n::1/64, and brings it up
func (u *pfUTUN) outside(t *testing.T, n int) (v4, v6 netip.Addr) {
	t.Helper()
	v4 = netip.AddrFrom4([4]byte{198, 51, 100, byte(n)})
	v6 = netip.MustParseAddr(fmt.Sprintf("2001:db8:%d::1", n))
	u.alias(t, netip.PrefixFrom(v4, 24))
	u.alias(t, netip.PrefixFrom(v6, 64))
	u.up(t)
	return v4, v6
}

// stranger is a source outside the overlay on the n-th outside link
func stranger(v6 bool, n int) netip.Addr {
	if v6 {
		return netip.MustParseAddr(fmt.Sprintf("2001:db8:%d::77", n))
	}
	return netip.AddrFrom4([4]byte{198, 51, 100, 77})
}

// pfDaemonSets derives the sets on each pass as the daemon does: the links
// and the carve-outs from darwin's network watch over every interface but the
// mesh utun, and the carved sets and the conflicts from routes, the mesh's
// table as the test sets it. The second value carries the watch's wakes, as
// the daemon hands the filter its network trigger.
func pfDaemonSets(t *testing.T, mesh string, routes *netstack.RouteTable) (func(*egress.Border) egress.BorderSets, <-chan struct{}) {
	t.Helper()
	shared, err := meshkernel.ShareWatcher(nil, mesh)
	if err != nil {
		t.Fatalf("open the watcher: %v", err)
	}
	watch, err := meshkernel.WatchNetwork(nil, mesh, shared.Reader())
	if err != nil {
		_ = shared.Close()
		t.Fatalf("open the watch: %v", err)
	}
	t.Cleanup(func() {
		_ = watch.Close()
		_ = shared.Close()
	})
	wake := make(chan struct{}, 1)
	go func() {
		for range watch.Changes() {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
	}()
	return func(cfg *egress.Border) egress.BorderSets {
		state, _ := watch.State()
		var out egress.BorderSets
		for _, family := range []meshkernel.NetworkFamily{state.IPv4, state.IPv6} {
			for _, link := range family.Links {
				out.Links = append(out.Links, link.Name)
			}
		}
		slices.Sort(out.Links)
		out.Links = slices.Compact(out.Links)
		if cfg != nil {
			out.CarveOuts = meshkernel.CarveOuts(state, cfg.Overlay)
			out.Carved, out.Conflicts = meshkernel.CarvedSets(cfg, out.CarveOuts, routes.Snapshot())
		}
		return out
	}, wake
}

// pfDaemonRuntime is pfRuntime with the sets and both wakes as the daemon
// gives them, over routes
func pfDaemonRuntime(t *testing.T, mesh string, routes *netstack.RouteTable) egress.BorderRuntime {
	t.Helper()
	rt := pfRuntime(mesh, t.TempDir(), nil)
	rt.Sets, rt.Network = pfDaemonSets(t, mesh, routes)
	rt.Routes = routes.Changes()
	return rt
}

// pfArm is one datagram of a root test: injected up a utun from source to
// one of this host's addresses, or sent from a socket bound to source where up
// is nil, and the rule of the anchor it meets, empty for none
type pfArm struct {
	name                string
	up                  *pfUTUN
	source, destination netip.Addr
	reached             bool
	rule                string
}

func (a pfArm) send(t *testing.T) bool {
	t.Helper()
	if a.up == nil {
		return pfSentTo(t, a.source, a.destination)
	}
	return pfReached(t, a.up, a.source, a.destination)
}

// pfNoAnchor runs each arm with no anchor of the filter's, each of which then
// reaches its destination
func pfNoAnchor(t *testing.T, arms []pfArm) {
	t.Helper()
	for _, arm := range arms {
		if !arm.send(t) {
			t.Fatalf("with no anchor, %s from %s to %s did not arrive, so the arm shows nothing", arm.name, arm.source, arm.destination)
		}
	}
}

// pfUnder runs each arm under the filter's anchor: it reaches its destination
// where it should and moves its rule's counter alone, or none where it meets
// no rule
func pfUnder(t *testing.T, f *BorderFilter, arms []pfArm) {
	t.Helper()
	for _, arm := range arms {
		before := pfCounted(t, f)
		reached := arm.send(t)
		after := pfCounted(t, f)
		met := pfQuiet(before, after)
		if arm.rule != "" {
			met = pfCounts(before, after, arm.rule)
		}
		if reached != arm.reached || !met {
			t.Errorf("under the anchor, %s from %s to %s arrived %v, want %v, the counters moving from %v to %v, want %q alone", arm.name, arm.source, arm.destination, reached, arm.reached, before, after, arm.rule)
		}
	}
}

// a forged overlay source on the real pf, both families, each arm first run
// with no anchor. Up either outside utun to that utun's own address the anchor
// drops it and counts it on its family's overlay drop. Up the mesh utun to its
// own address no rule of the anchor matches it, since each drop names every
// interface but the mesh utun. From a socket bound to the mesh's own address
// to 127.0.0.1 and ::1 it arrives on lo0 with that source and the lo0 pass
// passes it, and the anchor less its lo0 pass, lo0 then outside the mesh,
// drops and counts it. A source outside the overlay up an outside utun no
// rule matches.
func TestPfBorderDropsAForgedOverlaySource(t *testing.T) {
	requirePF(t)
	mesh, first, second := newPFUTUN(t), newPFUTUN(t), newPFUTUN(t)
	mesh.owned(t)
	first4, first6 := first.outside(t, 1)
	second4, second6 := second.outside(t, 2)
	arms := []pfArm{
		{"a forged source up the first outside utun", first, pfForged4, first4, false, "drop ipv4 source 192.0.2.0/24"},
		{"a forged source up the first outside utun", first, pfForged6, first6, false, "drop ipv6 source 3fff:10::/32"},
		{"a forged source up the second outside utun", second, pfForged4, second4, false, "drop ipv4 source 192.0.2.0/24"},
		{"a forged source up the second outside utun", second, pfForged6, second6, false, "drop ipv6 source 3fff:10::/32"},
		{"an overlay source up the mesh utun", mesh, pfForged4, pfMesh4, true, ""},
		{"an overlay source up the mesh utun", mesh, pfForged6, pfMesh6, true, ""},
		{"the mesh's own source to loopback", nil, pfMesh4, pfLoopback4, true, "accept via lo0"},
		{"the mesh's own source to loopback", nil, pfMesh6, pfLoopback6, true, "accept via lo0"},
		{"a stranger up an outside utun", first, stranger(false, 1), first4, true, ""},
		{"a stranger up an outside utun", first, stranger(true, 1), first6, true, ""},
	}
	pfNoAnchor(t, arms)
	run := startPF(t, mesh.name, t.TempDir())
	pfUnder(t, run.filter, arms)
	if err := run.stop(nil); err != nil {
		t.Fatal(err)
	}
	cfg := overlay(t, "192.0.2.0/24", "3fff:10::/32")
	rt := pfRuntime(mesh.name, t.TempDir(), nil)
	rt.Inside = []string{mesh.name}
	without := startPFWith(t, cfg, rt)
	pfUnder(t, without.filter, []pfArm{
		{"the mesh's own source to loopback with no lo0 pass", nil, pfMesh4, pfLoopback4, false, "drop ipv4 source 192.0.2.0/24"},
		{"the mesh's own source to loopback with no lo0 pass", nil, pfMesh6, pfLoopback6, false, "drop ipv6 source 3fff:10::/32"},
	})
}

// a carve-out on the real pf through the daemon's sets: an outside utun
// reaching the far end 192.0.2.129 and holding 3fff:10:2::1/64, which
// darwin's watch reports, an IPv4 address and its far end on a utun as hosts,
// so kernel.CarveOuts carves 192.0.2.129/32 and 3fff:10:2::/64 on it. A source
// inside the carve-out is passed up that utun by its accept, and up the other
// outside utun meets the overlay's drop. A mesh prefix inside the carve-out,
// which the test's table then routes to a peer, is dropped up the carve-out's
// own utun and counted on the carved drop, which comes ahead of every pass.
func TestPfBorderPassesACarveOut(t *testing.T) {
	requirePF(t)
	mesh, link, other := newPFUTUN(t), newPFUTUN(t), newPFUTUN(t)
	mesh.owned(t)
	mustRun(t, ifconfigBin, link.name, "inet", "198.51.100.1", "192.0.2.129", "alias")
	link.alias(t, netip.MustParsePrefix("3fff:10:2::1/64"))
	link.up(t)
	other4, other6 := other.outside(t, 2)
	routes := netstack.NewRouteTable()
	rt := pfDaemonRuntime(t, mesh.name, routes)
	cfg := overlay(t, "192.0.2.0/24", "3fff:10::/32")
	p := netip.MustParsePrefix
	want := []egress.CarveOut{{Link: link.name, Prefix: p("192.0.2.129/32")}, {Link: link.name, Prefix: p("3fff:10:2::/64")}}
	if !pfWithin(t, pfTwoPeriods, func() bool { return slices.Equal(rt.Sets(cfg).CarveOuts, want) }) {
		t.Fatalf("the watch's carve-outs read %v, want %v", rt.Sets(cfg).CarveOuts, want)
	}
	link4, link6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("3fff:10:2::1")
	inside4, inside6 := netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("3fff:10:2::77")
	arms := []pfArm{
		{"the carve-out's source up its link", link, inside4, link4, true, "accept via " + link.name + " source 192.0.2.129/32"},
		{"the carve-out's source up its link", link, inside6, link6, true, "accept via " + link.name + " source 3fff:10:2::/64"},
		{"the carve-out's source up another link", other, inside4, other4, false, "drop ipv4 source 192.0.2.0/24"},
		{"the carve-out's source up another link", other, inside6, other6, false, "drop ipv6 source 3fff:10::/32"},
	}
	pfNoAnchor(t, arms)
	run := startPFWith(t, cfg, rt)
	pfUnder(t, run.filter, arms)
	peer := &netstack.Peer{ID: "example/peer"}
	routes.Set(netip.Prefix{}, p("192.0.2.129/32"), peer)
	routes.Set(netip.Prefix{}, p("3fff:10:2:0:8000::/65"), peer)
	carved := func() bool {
		stats := run.filter.Stats()
		return stats.Ready && slices.ContainsFunc(stats.Sets, func(set egress.BorderSetReading) bool { return len(set.Elements) == 2 })
	}
	if !pfWithin(t, pfTwoPeriods, carved) {
		t.Fatalf("within %v of the routes the sets read %+v", pfTwoPeriods, run.filter.Stats().Sets)
	}
	pfUnder(t, run.filter, []pfArm{
		{"a carved mesh prefix up the carve-out's link", link, inside4, link4, false, "drop ipv4 source @carved4"},
		{"a carved mesh prefix up the carve-out's link", link, netip.MustParseAddr("3fff:10:2:0:8000::5"), link6, false, "drop ipv6 source @carved6"},
		{"the carve-out's other sources up its link", link, inside6, link6, true, "accept via " + link.name + " source 3fff:10:2::/64"},
	})
}

// the page's gateway G on the real pf, through the daemon's sets: the
// overlay of 203.0.113.0/24 and 3fff:a::/36, G's node address 203.0.113.1 on
// the mesh utun, its announced 203.0.113.0/25 exempt under the outside utun
// in eth1's place, another utun in eth0's, and the test's table routing
// another node's 203.0.113.96/28 to a peer. Each bullet, each first run with no
// anchor: the site's 203.0.113.65 is passed up eth1's utun by the exemption and
// dropped up eth0's on the overlay's drop, G's own address and the other
// node's prefix are dropped up eth1's utun on the carved drop, and
// antispoof.conflict came once. On a utun darwin's watch reports an IPv4
// address and its far end as hosts, so the carve-out variant gives eth1's
// utun the far end 203.0.113.65, whose carve-out's accept then passes it ahead
// of the exemption.
func TestPfBorderFollowsTheGatewayExample(t *testing.T) {
	requirePF(t)
	p := netip.MustParsePrefix
	mesh, eth0, eth1 := newPFUTUN(t), newPFUTUN(t), newPFUTUN(t)
	mesh.alias(t, p("203.0.113.1/32"))
	mesh.alias(t, p("3fff:a::1/128"))
	mesh.up(t)
	eth0Own, _ := eth0.outside(t, 2)
	eth1Own, _ := eth1.outside(t, 1)
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, p("203.0.113.0/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("203.0.113.1/32"), netstack.Assigned)
	routes.Set(netip.Prefix{}, p("203.0.113.96/28"), &netstack.Peer{ID: "example/peer"})
	gateway := func(eth1 string) *egress.Border {
		cfg := overlay(t, "203.0.113.0/24", "3fff:a::/36")
		cfg.Own, cfg.Addresses = []netip.Prefix{p("203.0.113.0/25")}, []netip.Prefix{p("203.0.113.1/32")}
		cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{eth1: {Exempt: prefixes(t, "203.0.113.0/25")}}}
		return cfg
	}
	site, own, other := netip.MustParseAddr("203.0.113.65"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.97")
	arms := []pfArm{
		{"the site's host up eth1", eth1, site, eth1Own, true, "accept exempt via " + eth1.name + " source 203.0.113.0/25"},
		{"the site's host up eth0", eth0, site, eth0Own, false, "drop ipv4 source 203.0.113.0/24"},
		{"G's own address up eth1", eth1, own, eth1Own, false, "drop ipv4 source @carved4"},
		{"the other node's source up eth1", eth1, other, eth1Own, false, "drop ipv4 source @carved4"},
	}
	pfNoAnchor(t, arms)
	run := startPFWith(t, gateway(eth1.name), pfDaemonRuntime(t, mesh.name, routes))
	pfUnder(t, run.filter, arms)
	if n := run.recorded("antispoof.conflict"); n != 1 {
		t.Errorf("recorded %d antispoof.conflict, want one", n)
	}
	if err := run.stop(nil); err != nil {
		t.Fatal(err)
	}

	variant := newPFUTUN(t)
	mustRun(t, ifconfigBin, variant.name, "inet", "198.51.100.3", site.String(), "alias")
	variant.up(t)
	rt := pfDaemonRuntime(t, mesh.name, routes)
	carveOut := egress.CarveOut{Link: variant.name, Prefix: p("203.0.113.65/32")}
	if !pfWithin(t, pfTwoPeriods, func() bool { return slices.Contains(rt.Sets(gateway(variant.name)).CarveOuts, carveOut) }) {
		t.Fatalf("the watch's carve-outs read %v, want %v among them", rt.Sets(gateway(variant.name)).CarveOuts, carveOut)
	}
	arm := []pfArm{{"the site's host up the carve-out", variant, site, netip.MustParseAddr("198.51.100.3"), true, "accept via " + variant.name + " source 203.0.113.65/32"}}
	pfNoAnchor(t, arm)
	pfUnder(t, startPFWith(t, gateway(variant.name), rt).filter, arm)
}

// an exemption under utun* on the real pf, through the daemon's sets: pf
// matches a name by its exact name alone, so the anchor holds one pass per
// utun the watch reports outside the mesh, the exempt source passing up each
// outside utun and the anchor holding no pass on the mesh utun. A third utun
// the test makes after the first pass drops the exempt source by the overlay's
// drop until a pass hands the filter its link, then passes it once the pass
// its link gets writes its pass, within two periods. The test holds the third
// utun out of the filter's links until it has seen the drop, as the watch's
// wake would race the injection.
func TestPfBorderExpandsAWildcardExemption(t *testing.T) {
	ctl := requirePF(t)
	mesh, first, second := newPFUTUN(t), newPFUTUN(t), newPFUTUN(t)
	mesh.owned(t)
	first4, first6 := first.outside(t, 1)
	second4, second6 := second.outside(t, 2)
	cfg := overlay(t, "192.0.2.0/24", "3fff:10::/32")
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"utun*": {Exempt: prefixes(t, "192.0.2.32/27", "3fff:10:1::/48")}}}
	rt := pfDaemonRuntime(t, mesh.name, netstack.NewRouteTable())
	watched := rt.Sets
	var mu sync.Mutex
	hidden := ""
	rt.Sets = func(cfg *egress.Border) egress.BorderSets {
		out := watched(cfg)
		mu.Lock()
		defer mu.Unlock()
		out.Links = slices.DeleteFunc(out.Links, func(name string) bool { return name == hidden })
		return out
	}
	listed := func(names ...string) bool {
		links := rt.Sets(cfg).Links
		return !slices.Contains(links, mesh.name) && !slices.ContainsFunc(names, func(name string) bool { return !slices.Contains(links, name) })
	}
	if !pfWithin(t, pfTwoPeriods, func() bool { return listed(first.name, second.name) }) {
		t.Fatalf("the watch's links read %v, want %s and %s and not %s", rt.Sets(cfg).Links, first.name, second.name, mesh.name)
	}
	exempt4, exempt6 := netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("3fff:10:1::5")
	arms := []pfArm{
		{"the exempt source up the first utun", first, exempt4, first4, true, "accept exempt via " + first.name + " source 192.0.2.32/27"},
		{"the exempt source up the first utun", first, exempt6, first6, true, "accept exempt via " + first.name + " source 3fff:10:1::/48"},
		{"the exempt source up the second utun", second, exempt4, second4, true, "accept exempt via " + second.name + " source 192.0.2.32/27"},
		{"the exempt source up the second utun", second, exempt6, second6, true, "accept exempt via " + second.name + " source 3fff:10:1::/48"},
	}
	pfNoAnchor(t, arms)
	run := startPFWith(t, cfg, rt)
	pfUnder(t, run.filter, arms)
	read, err := ctl.Read(pfAnchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range read.Rules {
		if rule.Rule.Interface == mesh.name && !rule.Rule.NotInterface {
			t.Errorf("the anchor holds %q on the mesh utun", rule.Rule)
		}
	}
	third := newPFUTUN(t)
	mu.Lock()
	hidden = third.name
	mu.Unlock()
	third4, _ := third.outside(t, 3)
	if !pfWithin(t, pfTwoPeriods, func() bool { return slices.Contains(watched(cfg).Links, third.name) }) {
		t.Fatalf("the watch's links read %v, want %s among them", watched(cfg).Links, third.name)
	}
	pfUnder(t, run.filter, []pfArm{{"the exempt source up the third utun before a pass hands the filter its link", third, exempt4, third4, false, "drop ipv4 source 192.0.2.0/24"}})
	mu.Lock()
	hidden = ""
	mu.Unlock()
	if !pfWithin(t, pfTwoPeriods, func() bool { return pfReached(t, third, exempt4, third4) }) {
		t.Fatalf("within %v of %s reaching the filter the exempt source up it did not arrive, the anchor holding %v", pfTwoPeriods, third.name, pfCounted(t, run.filter))
	}
	if read, err = ctl.Read(pfAnchor); err != nil || !slices.ContainsFunc(read.Rules, func(rule pf.Counted) bool {
		return rule.Rule.Label == "accept exempt via "+third.name+" source 192.0.2.32/27"
	}) {
		t.Errorf("the anchor holds no pass of the exempt source on %s: %+v (%v)", third.name, read.Rules, err)
	}
}

// another process ends the filter's reference with pfctl -X, and within two
// periods pf lists a new one under this process, the record holds it alone,
// one antispoof.pf came with the new token and whether pf was off, and the
// anchor reads back. The first arm finds pf off where nothing else held it
// before the start, as the release then stops it. The second arm holds a
// reference of its own throughout, which keeps pf running, so only the
// reference's listing tells the pass it ended, and pf was not off.
func TestPfBorderTakesItsReferenceAgain(t *testing.T) {
	ctl := requirePF(t)
	for _, arm := range []struct {
		name    string
		holding bool
	}{{"the filter's reference alone", false}, {"beside the test's own reference", true}} {
		t.Run(arm.name, func(t *testing.T) {
			if arm.holding {
				own, err := pf.Take(ctl, filepath.Join(t.TempDir(), "own.json"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := own.Release(); err != nil {
						t.Error(err)
					}
				})
			}
			mesh := newPFUTUN(t)
			mesh.owned(t)
			dir := t.TempDir()
			// pf off before the filter's reference stops at its release, and
			// one running then keeps running under its other holder
			off := !pfRunning(t)
			t.Logf("pf off at the release: %v", off)
			run := startPF(t, mesh.name, dir)
			ended := run.filter.Stats().PF.Token
			if err := ctl.Release(ended); err != nil {
				t.Fatal(err)
			}
			if arm.holding && (off || !pfRunning(t)) {
				t.Fatalf("pf ran %v before the start and stopped at the release while the test holds a reference", !off)
			}
			// the pass records antispoof.pf as it renews, and stores its status
			// only at its end, so until then the status still reads the ended
			// token, listed and ready, and the wait is for the status to read
			// the token the event names
			var token uint64
			renewed := pfWithin(t, pfTwoPeriods, func() bool {
				recorded := run.bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pf" }, 0)
				if len(recorded) == 0 {
					return false
				}
				token, _ = strconv.ParseUint(recorded[0].Attrs["token"], 10, 64)
				stats := run.filter.Stats()
				return stats.Ready && stats.PF != nil && stats.PF.Listed && stats.PF.Token == token
			})
			if stats := run.filter.Stats(); !renewed {
				t.Fatalf("within %v of the release the filter reads ready %v (%q), pf %+v, with %d antispoof.pf naming token %d", pfTwoPeriods, stats.Ready, stats.Unready, stats.PF, run.recorded("antispoof.pf"), token)
			}
			if !listedUnder(t, ctl, token) || !pfRunning(t) {
				t.Errorf("pf does not list the new token %d under this process, or does not run", token)
			}
			if got := heldRecord(t, dir); !slices.Equal(got, []pf.Enabler{{Token: token, PID: os.Getpid()}}) {
				t.Errorf("the record holds %+v, want the new token %d alone", got, token)
			}
			recorded := run.bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pf" }, 0)
			if len(recorded) != 1 || !anchorHolds(t, ctl) {
				t.Fatalf("%d antispoof.pf came, want 1, and the anchor holds its rules %v", len(recorded), anchorHolds(t, ctl))
			}
			if want := map[string]string{"token": fmt.Sprint(token), "pid": fmt.Sprint(os.Getpid()), "pf_off": fmt.Sprint(off)}; !maps.Equal(recorded[0].Attrs, want) {
				t.Errorf("antispoof.pf carries %v, want %v", recorded[0].Attrs, want)
			}
		})
	}
}

// a flush of the anchor by hand, and a stateful pass loaded in its place,
// which the parsers cannot read, are each put back within two periods, by a
// pass that records antispoof.pass
func TestPfBorderRestoresItsAnchor(t *testing.T) {
	ctl := requirePF(t)
	mesh := newPFUTUN(t)
	mesh.owned(t)
	run := startPF(t, mesh.name, t.TempDir())
	for _, arm := range []struct {
		name   string
		change func()
	}{
		{"flushed", func() {
			for _, what := range []string{"rules", "Tables"} {
				mustRun(t, pfctlBin, "-a", pfAnchor, "-F", what)
			}
			if read, err := ctl.Read(pfAnchor); err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
				t.Fatalf("the flush left %+v (%v)", read, err)
			}
		}},
		{"a stateful pass in its place", func() {
			load := exec.Command(pfctlBin, "-a", pfAnchor, "-f", "-")
			load.Stdin = strings.NewReader("pass out quick on " + mesh.name + " all\n")
			if out, err := load.CombinedOutput(); err != nil {
				t.Fatalf("load the pass: %v: %s", err, out)
			}
			if _, err := ctl.Read(pfAnchor); !errors.Is(err, pf.ErrUnreadable) {
				t.Fatalf("the stateful pass reads back as %v, want what the parsers cannot read", err)
			}
		}},
	} {
		passes := run.recorded("antispoof.pass")
		arm.change()
		restored := pfWithin(t, pfTwoPeriods, func() bool {
			return anchorHolds(t, ctl) && run.recorded("antispoof.pass") > passes && run.filter.Stats().Ready
		})
		if !restored {
			t.Errorf("%s: within %v the anchor holds its rules %v, %d passes recorded, ready %v",
				arm.name, pfTwoPeriods, anchorHolds(t, ctl), run.recorded("antispoof.pass")-passes, run.filter.Stats().Ready)
		}
	}
}

// a stop empties the anchor and the record, gives the reference back, and
// leaves pf running as it found it
func TestPfBorderWithdrawsOnStop(t *testing.T) {
	ctl := requirePF(t)
	was := pfRunning(t)
	mesh := newPFUTUN(t)
	mesh.owned(t)
	dir := t.TempDir()
	run := startPF(t, mesh.name, dir)
	token := run.filter.Stats().PF.Token
	if !pfRunning(t) || !anchorHolds(t, ctl) {
		t.Fatalf("the running filter leaves pf running %v and its anchor holding its rules %v", pfRunning(t), anchorHolds(t, ctl))
	}
	if err := run.stop(nil); err != nil {
		t.Fatal(err)
	}
	read, err := ctl.Read(pfAnchor)
	if err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
		t.Errorf("after the stop the anchor holds %+v (%v)", read, err)
	}
	if got := heldRecord(t, dir); len(got) != 0 || listedUnder(t, ctl, token) {
		t.Errorf("after the stop the record holds %+v and pf lists the token %v", got, listedUnder(t, ctl, token))
	}
	if running := pfRunning(t); running != was {
		t.Errorf("pf runs %v after the stop, %v before the filter", running, was)
	}
}

// Run ended by the mesh's failure leaves the anchor, the reference listed and
// recorded, and pf running. A second filter over the record then takes the
// anchor over, holds its own reference alone, listed and recorded, and once
// stopped empties the record, gives the reference back and leaves pf running
// as the test found it.
func TestPfBorderLeavesItsAnchorAfterTheMeshFailed(t *testing.T) {
	ctl := requirePF(t)
	was := pfRunning(t)
	mesh := newPFUTUN(t)
	mesh.owned(t)
	dir := t.TempDir()
	first := startPF(t, mesh.name, dir)
	earlier := first.filter.Stats().PF.Token
	if err := first.stop(meshkernel.ErrMeshFailed); err != nil {
		t.Fatal(err)
	}
	if !anchorHolds(t, ctl) || !listedUnder(t, ctl, earlier) || !pfRunning(t) {
		t.Errorf("after the mesh failed the anchor holds its rules %v, pf lists the token %v, and runs %v", anchorHolds(t, ctl), listedUnder(t, ctl, earlier), pfRunning(t))
	}
	if got := heldRecord(t, dir); !slices.Equal(got, []pf.Enabler{{Token: earlier, PID: os.Getpid()}}) {
		t.Errorf("after the mesh failed the record holds %+v, want the token %d", got, earlier)
	}
	second := startPF(t, mesh.name, dir)
	now := second.filter.Stats().PF.Token
	// the take runs while the earlier reference is held, so pf gives the new one another value
	if now == earlier || listedUnder(t, ctl, earlier) || !listedUnder(t, ctl, now) || !anchorHolds(t, ctl) || !second.filter.Stats().Ready {
		t.Errorf("the second filter took the token %d over the earlier %d, lists the earlier %v and its own %v, with the anchor holding its rules %v and ready %v",
			now, earlier, listedUnder(t, ctl, earlier), listedUnder(t, ctl, now), anchorHolds(t, ctl), second.filter.Stats().Ready)
	}
	if got := heldRecord(t, dir); !slices.Equal(got, []pf.Enabler{{Token: now, PID: os.Getpid()}}) {
		t.Errorf("the second filter's record holds %+v, want its token %d alone", got, now)
	}
	if err := second.stop(nil); err != nil {
		t.Fatal(err)
	}
	// the second took the earlier run's place, so its backend's close keeps
	// the reference and the stop's withdrawal alone gives it back
	if got := heldRecord(t, dir); len(got) != 0 || listedUnder(t, ctl, now) {
		t.Errorf("after the second filter stopped the record holds %+v and pf lists its token %v", got, listedUnder(t, ctl, now))
	}
	if running := pfRunning(t); running != was {
		t.Errorf("pf runs %v after the second filter stopped, %v before the first", running, was)
	}
}

// a child of com.apple sorting after the filter's anchor reopens nothing, since
// each quick rule of the anchor ends pf's evaluation first, and still sees what
// no rule of the anchor matched. With the shared exemption of 192.0.2.32/27,
// each arm first run under the sibling alone, pf held running by the test's
// own reference: beside a sibling passing every packet in, a forged overlay
// source up an outside utun is dropped and counted on its family's overlay
// drop, and beside a sibling dropping 192.0.2.32/27 up the mesh utun, that
// source up the mesh utun is still dropped, since the shared exemption passes
// it on every interface but the mesh utun, where it passes it up the outside
// utun.
func TestPfBorderHoldsAgainstALaterPass(t *testing.T) {
	ctl := requirePF(t)
	if read, err := ctl.Read(pfLaterAnchor); err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
		t.Skipf("%s holds %+v (%v) already", pfLaterAnchor, read, err)
	}
	pfHold(t, ctl)
	pfFlushAtEnd(t, pfLaterAnchor)
	mesh, out := newPFUTUN(t), newPFUTUN(t)
	mesh.owned(t)
	out4, out6 := out.outside(t, 1)
	cfg := overlay(t, "192.0.2.0/24", "3fff:10::/32")
	cfg.Antispoof = egress.Antispoof{Exempt: prefixes(t, "192.0.2.32/27")}
	exempt := netip.MustParseAddr("192.0.2.33")
	for _, arm := range []struct {
		name, sibling string
		alone, under  []pfArm
	}{
		{"beside a later pass", "pass in quick all no state label \"pass every packet in\"\n",
			[]pfArm{{"a forged source up the outside utun", out, pfForged4, out4, true, ""}, {"a forged source up the outside utun", out, pfForged6, out6, true, ""}},
			[]pfArm{
				{"a forged source up the outside utun", out, pfForged4, out4, false, "drop ipv4 source 192.0.2.0/24"},
				{"a forged source up the outside utun", out, pfForged6, out6, false, "drop ipv6 source 3fff:10::/32"},
			}},
		{"beside a later drop on the mesh utun", "block drop in quick on " + mesh.name + " inet from 192.0.2.32/27 to any label \"later drop\"\n",
			[]pfArm{{"the exempt source up the mesh utun", mesh, exempt, pfMesh4, false, ""}, {"the exempt source up the outside utun", out, exempt, out4, true, ""}},
			[]pfArm{
				{"the exempt source up the mesh utun", mesh, exempt, pfMesh4, false, ""},
				{"the exempt source up the outside utun", out, exempt, out4, true, "accept exempt source 192.0.2.32/27"},
			}},
	} {
		t.Run(arm.name, func(t *testing.T) {
			pfLoad(t, pfLaterAnchor, arm.sibling)
			for _, alone := range arm.alone {
				if alone.send(t) != alone.reached {
					t.Fatalf("under the sibling alone, %s from %s to %s arrived %v, so the arm shows nothing", alone.name, alone.source, alone.destination, !alone.reached)
				}
			}
			run := startPFWith(t, cfg, pfRuntime(mesh.name, t.TempDir(), nil))
			pfUnder(t, run.filter, arm.under)
		})
	}
}

// pf matches a packet against its state table before any rule, and a state
// floats across interfaces unless its rule is if-bound. XNU's input runs after
// pf, and with forwarding off and net.inet.ip.check_interface at 1 or 2 it
// drops a datagram for an address of a utun that came up another interface. A
// child of com.apple sorting after the filter's anchor holds a stateful pass
// out on the mesh utun, and a flow leaves by it from the outside utun's own
// address: the forged reply up the outside utun, an overlay source, reaches
// the flow's socket on that state with no rule of the anchor meeting it, and
// under keep state (if-bound) the state is the mesh utun's alone and the
// anchor's drop takes the same reply. A flow from the mesh's own address
// under a state that floats passes pf the same way, and XNU then drops the
// reply, counted among netstat's input packets with no interface address
// match. The main ruleset is the host's own throughout, and no sysctl changes.
func TestPfStateOfAPassOutFloatsUnlessIfBound(t *testing.T) {
	ctl := requirePF(t)
	if read, err := ctl.Read(pfLaterAnchor); err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
		t.Skipf("%s holds %+v (%v) already", pfLaterAnchor, read, err)
	}
	pfFlushAtEnd(t, pfLaterAnchor)
	mesh, out := newPFUTUN(t), newPFUTUN(t)
	peer := netip.MustParseAddr("192.0.2.50")
	mustRun(t, ifconfigBin, mesh.name, "inet", pfMesh4.String(), peer.String(), "alias")
	mesh.up(t)
	out4, _ := out.outside(t, 1)
	run := startPF(t, mesh.name, t.TempDir())
	// reached is whether the flow's socket reads the reply, rule the anchor's
	// rule whose counter alone moves, none where empty, and unmatched whether
	// XNU's input drops the reply pf passed
	for _, arm := range []struct {
		name, state        string
		local              netip.Addr
		reached, unmatched bool
		rule               string
	}{
		{"a state that floats", "keep state", out4, true, false, ""},
		{"a state bound to the mesh utun", "keep state (if-bound)", out4, false, false, "drop ipv4 source 192.0.2.0/24"},
		{"a flow from the mesh's own address", "keep state", pfMesh4, false, true, ""},
	} {
		t.Run(arm.name, func(t *testing.T) {
			if arm.unmatched {
				checked, checkedErr := unix.SysctlUint32("net.inet.ip.check_interface")
				forwarding, forwardingErr := unix.SysctlUint32("net.inet.ip.forwarding")
				if err := errors.Join(checkedErr, forwardingErr); err != nil {
					t.Fatalf("read net.inet.ip.check_interface and net.inet.ip.forwarding: %v", err)
				}
				if (checked != 1 && checked != 2) || forwarding != 0 {
					t.Skipf("net.inet.ip.check_interface reads %d and net.inet.ip.forwarding %d, where XNU takes a datagram for any address of the host", checked, forwarding)
				}
			}
			pfLoad(t, pfLaterAnchor, "pass out quick on "+mesh.name+" inet proto udp from "+arm.local.String()+" to "+peer.String()+" "+arm.state+" label \"later stateful pass out\"\n")
			fd, flow := pfFlowOut(t, arm.local, peer)
			reply := []byte("a forged reply up " + out.name)
			before, dropped := pfCounted(t, run.filter), xnuUnmatched(t)
			out.inject(t, udpBetween(netip.AddrPortFrom(peer, pfPort), flow, reply))
			reached := pfGot(fd, reply)
			after, now := pfCounted(t, run.filter), xnuUnmatched(t)
			met := pfQuiet(before, after)
			if arm.rule != "" {
				met = pfCounts(before, after, arm.rule)
			}
			if reached != arm.reached || !met {
				t.Errorf("the reply to %s up %s arrived %v, want %v, the anchor's counters moving from %v to %v, want %q alone", flow, out.name, reached, arm.reached, before, after, arm.rule)
			}
			t.Logf("netstat counts %d input packets with no interface address match before the reply and %d after", dropped, now)
			if arm.unmatched && now <= dropped {
				t.Error("want that count moved by the reply")
			}
		})
	}
}

// pfFlowOut binds a UDP socket to local and sends one datagram from it to
// peer with SO_DONTROUTE, which takes the utun whose far end peer is and
// selects no source, and gives the socket and the flow's local address. XNU
// refuses a send held to that utun by IP_BOUND_IF from another interface's
// address.
func pfFlowOut(t *testing.T, local, peer netip.Addr) (int, netip.AddrPort) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: local.As4()}); err != nil {
		t.Fatalf("bind %s: %v", local, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DONTROUTE, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(fd, []byte("out"), 0, &unix.SockaddrInet4{Addr: peer.As4(), Port: pfPort}); err != nil {
		t.Fatalf("send from %s to %s: %v", local, peer, err)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return fd, netip.AddrPortFrom(local, uint16(name.(*unix.SockaddrInet4).Port))
}

// xnuUnmatched is the count XNU's input keeps of the datagrams it dropped for
// matching no address of the interface they came up, from netstat's ip table
// alone, since its ip6 table prints the same words
func xnuUnmatched(t *testing.T) uint64 {
	t.Helper()
	out, err := exec.Command(netstatBin, "-s", "-p", "ip").Output()
	if err != nil {
		t.Fatalf("netstat -s -p ip: %v", err)
	}
	table := ""
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			table = line
			continue
		}
		count, what, _ := strings.Cut(strings.TrimSpace(line), " ")
		if table == "ip:" && strings.HasSuffix(what, "with no interface address match") {
			n, err := strconv.ParseUint(count, 10, 64)
			if err != nil {
				t.Fatalf("netstat -s -p ip prints %q", line)
			}
			return n
		}
	}
	t.Fatalf("netstat -s -p ip prints no line of its ip table counting input packets with no interface address match: %s", out)
	return 0
}

// a start without overlay over the record the mesh's failure left, as a
// crash leaves it, empties the anchor, gives back the recorded reference and
// empties the record, and runs no filter
func TestPfBorderStartWithoutOverlayGivesBackWhatAnEarlierRunLeft(t *testing.T) {
	ctl := requirePF(t)
	mesh := newPFUTUN(t)
	mesh.owned(t)
	dir := t.TempDir()
	first := startPF(t, mesh.name, dir)
	earlier := first.filter.Stats().PF.Token
	if err := first.stop(meshkernel.ErrMeshFailed); err != nil {
		t.Fatal(err)
	}
	if !anchorHolds(t, ctl) || !listedUnder(t, ctl, earlier) {
		t.Fatalf("after the mesh failed the anchor holds its rules %v and pf lists the token %v", anchorHolds(t, ctl), listedUnder(t, ctl, earlier))
	}
	if f, err := NewBorderFilter(nil, pfRuntime(mesh.name, dir, nil)); f != nil || err != nil {
		t.Fatalf("the start without overlay returned %v (%v), want no filter", f, err)
	}
	read, err := ctl.Read(pfAnchor)
	if err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 {
		t.Errorf("after the start without overlay the anchor holds %+v (%v)", read, err)
	}
	if got := heldRecord(t, dir); len(got) != 0 || listedUnder(t, ctl, earlier) {
		t.Errorf("after the start without overlay the record holds %+v and pf lists the earlier token %v", got, listedUnder(t, ctl, earlier))
	}
}

// pfFlushAtEnd empties anchor's rules when the test ends
func pfFlushAtEnd(t *testing.T, anchor string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := exec.Command(pfctlBin, "-a", anchor, "-F", "rules").CombinedOutput(); err != nil {
			t.Errorf("flush the rules of %s: %v: %s", anchor, err, out)
		}
	})
}

// pfLoad replaces what anchor holds with text
func pfLoad(t *testing.T, anchor, text string) {
	t.Helper()
	load := exec.Command(pfctlBin, "-a", anchor, "-f", "-")
	load.Stdin = strings.NewReader(text)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("load %q into %s: %v: %s", text, anchor, err, out)
	}
}

// pfHold holds a reference of the test's own on pf until the test ends, so pf
// runs while the test reads what it evaluates. The record's directory comes
// first and the release next, so the release runs after every later cleanup
// and before the directory goes, since cleanups run last in, first out.
func pfHold(t *testing.T, ctl pf.Ctl) {
	t.Helper()
	dir := t.TempDir()
	var own *pf.Reference
	t.Cleanup(func() {
		if own != nil {
			if err := own.Release(); err != nil {
				t.Error(err)
			}
		}
	})
	var err error
	if own, err = pf.Take(ctl, filepath.Join(dir, "own.json")); err != nil {
		t.Fatal(err)
	}
}

// reachedBy reports, for each family, whether a stranger's datagram up the
// outside utun reaches the utun's own address
func reachedBy(t *testing.T, out *pfUTUN, own4, own6 netip.Addr) (v4, v6 bool) {
	t.Helper()
	return pfReached(t, out, stranger(false, 1), own4), pfReached(t, out, stranger(true, 1), own6)
}

// each form of a call into com.apple/* with pfctl as the oracle, the call
// loaded into a child of com.apple, where it names the children of that
// child's com.apple, one of which drops every packet in on an outside utun:
// the line pfctl prints back reads as a call only for the stock form and the
// same with in, pf evaluating the probe for both families under each, and
// every form naming a direction out, an interface, a family, a protocol or an
// address reads as no call, pf leaving some datagrams out of the probe under
// each but the one naming the outside utun itself. Then a main ruleset whose
// only call sits inside an inline anchor reads as no call, pf leaving every
// datagram out of the probe, and the main ruleset is put back as the test
// found it.
func TestPfMainCallReadsAsPfEvaluatesIt(t *testing.T) {
	ctl := requirePF(t)
	for _, anchor := range []string{pfCallAnchor, pfProbeAnchor} {
		if out, err := exec.Command(pfctlBin, "-a", anchor, "-sr").Output(); err != nil || strings.TrimSpace(string(out)) != "" {
			t.Skipf("%s holds %q (%v) already", anchor, out, err)
		}
	}
	pfHold(t, ctl)
	out, other := newPFUTUN(t), newPFUTUN(t)
	own4, own6 := out.outside(t, 1)
	other.outside(t, 2)
	pfFlushAtEnd(t, pfProbeAnchor)
	pfFlushAtEnd(t, pfCallAnchor)
	pfLoad(t, pfProbeAnchor, "block drop in quick on "+out.name+" all label \"probe\"\n")
	if v4, v6 := reachedBy(t, out, own4, own6); !v4 || !v6 {
		t.Fatalf("with no call into the probe the datagrams up %s arrived: IPv4 %v, IPv6 %v", out.name, v4, v6)
	}
	for _, form := range []struct {
		qualifier      string
		called, e4, e6 bool
	}{
		{"", true, true, true},
		{" in", true, true, true},
		{" out", false, false, false},
		{" on " + other.name, false, false, false},
		{" on " + out.name, false, true, true},
		{" inet", false, true, false},
		{" inet6", false, false, true},
		{" proto tcp", false, false, false},
		{" to " + own4.String(), false, true, false},
	} {
		line := `anchor "com.apple/*"` + form.qualifier
		pfLoad(t, pfCallAnchor, line+"\n")
		printed, err := exec.Command(pfctlBin, "-a", pfCallAnchor, "-sr").Output()
		if err != nil {
			t.Fatalf("read %s back: %v", pfCallAnchor, err)
		}
		t.Logf("pfctl prints %q as %q", line, strings.TrimSpace(string(printed)))
		v4, v6 := reachedBy(t, out, own4, own6)
		if called := pf.ParseCalls(string(printed), "com.apple/*"); called != form.called || v4 == form.e4 || v6 == form.e6 {
			t.Errorf("%q, printed %q, reads as a call %v, want %v, and pf evaluated the probe for IPv4 %v and IPv6 %v, want %v and %v",
				line, strings.TrimSpace(string(printed)), called, form.called, !v4, !v6, form.e4, form.e6)
		}
	}
	// a main ruleset whose only call sits inside an unnamed inline anchor: pf
	// resolves it relative to that inline anchor, so com.apple's children, the
	// call anchor among them, are never evaluated, and pfctl prints the call
	// indented between the inline anchor's braces
	pfLoad(t, pfCallAnchor, "anchor \"com.apple/*\"\n")
	if v4, v6 := reachedBy(t, out, own4, own6); v4 || v6 {
		t.Fatalf("under the stock main ruleset and call the datagrams up %s arrived: IPv4 %v, IPv6 %v", out.name, v4, v6)
	}
	pfMainAtEnd(t)
	inline := "anchor in {\n\tanchor \"com.apple/*\"\n}\n"
	load := exec.Command(pfctlBin, "-R", "-f", "-")
	load.Stdin = strings.NewReader(inline)
	if printed, err := load.CombinedOutput(); err != nil {
		t.Fatalf("load the main ruleset %q: %v: %s", inline, err, printed)
	}
	printed, err := exec.Command(pfctlBin, "-sr").Output()
	if err != nil {
		t.Fatalf("read the main ruleset back: %v", err)
	}
	t.Logf("pfctl prints the main ruleset %q as %q", inline, printed)
	v4, v6 := reachedBy(t, out, own4, own6)
	if called := pf.ParseCalls(string(printed), "com.apple/*"); called || !v4 || !v6 {
		t.Errorf("the main ruleset %q, printed %q, reads as a call %v, want none, and pf evaluated the probe for IPv4 %v and IPv6 %v, want neither",
			inline, printed, called, !v4, !v6)
	}
}

// pfMainAtEnd puts back the main ruleset's filter rules, as pfctl prints them
// now, when the test ends, with pfctl -R, which loads them alone and leaves
// the main ruleset's options, translation rules and skips as they are
func pfMainAtEnd(t *testing.T) {
	t.Helper()
	found, err := exec.Command(pfctlBin, "-sr").Output()
	if err != nil {
		t.Fatalf("read the main ruleset: %v", err)
	}
	t.Cleanup(func() {
		restore := exec.Command(pfctlBin, "-R", "-f", "-")
		restore.Stdin = strings.NewReader(string(found))
		if out, err := restore.CombinedOutput(); err != nil {
			t.Errorf("put the main ruleset %q back: %v: %s, and pfctl -f /etc/pf.conf loads the stock one", found, err, out)
			return
		}
		if now, err := exec.Command(pfctlBin, "-sr").Output(); err != nil || string(now) != string(found) {
			t.Errorf("the main ruleset reads %q (%v) after its restore, %q before the test", now, err, found)
		}
	})
}

// pfSetSkip sets pf's skip flag on the interface name, as a set skip loaded
// with the main ruleset does, or clears it, through DIOCSETIFFLAG and
// DIOCCLRIFFLAG, which touch the interface of that exact name alone
// (pfi_set_flags, pfi_skip_if, bsd_net_pf_if.c:714-769)
func pfSetSkip(name string, skip bool) error {
	const (
		// _IOWR('D', 89 and 90, struct pfioc_iface), bsd/net/pfvar.h, 40 bytes
		// in a 64-bit process, the flags at 36
		diocSetIfFlag = 0xC0284459
		diocClrIfFlag = 0xC028445A
		pfiIflagSkip  = 0x0100
	)
	fd, err := unix.Open("/dev/pf", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var iface [40]byte
	copy(iface[:unix.IFNAMSIZ-1], name)
	binary.NativeEndian.PutUint32(iface[36:], pfiIflagSkip)
	request := uintptr(diocClrIfFlag)
	if skip {
		request = diocSetIfFlag
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&iface[0]))); errno != 0 {
		return errno
	}
	return nil
}

// with pfctl as the oracle: once pf skips an outside utun, pfctl's listing
// reads it skipped and a datagram up it passes an anchor that drops every
// packet in there, and a start over it is refused, naming the skip, then
// cleared the listing reads it not skipped and the drop holds again. A skip of
// the mesh utun, inside the mesh, leaves no drop of the filter's unevaluated,
// and a start over it runs.
func TestPfBorderStartRefusesASkippedLink(t *testing.T) {
	ctl := requirePF(t)
	if out, err := exec.Command(pfctlBin, "-a", pfCallAnchor, "-sr").Output(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Skipf("%s holds %q (%v) already", pfCallAnchor, out, err)
	}
	pfHold(t, ctl)
	mesh, out := newPFUTUN(t), newPFUTUN(t)
	mesh.owned(t)
	own4, own6 := out.outside(t, 1)
	pfFlushAtEnd(t, pfCallAnchor)
	pfLoad(t, pfCallAnchor, "block drop in quick on "+out.name+" all label \"probe\"\n")
	if v4, v6 := reachedBy(t, out, own4, own6); v4 || v6 {
		t.Fatalf("under the probe the datagrams up %s arrived: IPv4 %v, IPv6 %v", out.name, v4, v6)
	}
	// registered after the utuns, so each runs before they close and no flag outlives the test
	for _, name := range []string{mesh.name, out.name} {
		t.Cleanup(func() {
			if err := pfSetSkip(name, false); err != nil {
				t.Errorf("clear the skip on %s: %v", name, err)
			}
		})
	}
	if err := pfSetSkip(out.name, true); err != nil {
		t.Fatalf("skip %s: %v", out.name, err)
	}
	printed, _ := exec.Command(pfctlBin, "-s", "Interfaces", "-v").Output()
	t.Logf("pfctl -s Interfaces -v prints %q", printed)
	skipped, err := ctl.Skipped()
	v4, v6 := reachedBy(t, out, own4, own6)
	if err != nil || !slices.Contains(skipped, out.name) || !v4 || !v6 {
		t.Errorf("with %s skipped pfctl reads skipped %q (%v), and the datagrams arrived IPv4 %v, IPv6 %v", out.name, skipped, err, v4, v6)
	}
	_, err = NewBorderFilter(overlay(t, "192.0.2.0/24", "3fff:10::/32"), pfRuntime(mesh.name, t.TempDir(), nil))
	if err == nil || !strings.Contains(err.Error(), "pf skips "+out.name) {
		t.Errorf("the start over a skipped outside utun returned %v, want the skip named", err)
	}
	if err := pfSetSkip(out.name, false); err != nil {
		t.Fatal(err)
	}
	skipped, err = ctl.Skipped()
	v4, v6 = reachedBy(t, out, own4, own6)
	if err != nil || slices.Contains(skipped, out.name) || v4 || v6 {
		t.Errorf("with the skip cleared pfctl reads skipped %q (%v), and the datagrams arrived IPv4 %v, IPv6 %v", skipped, err, v4, v6)
	}
	if err := pfSetSkip(mesh.name, true); err != nil {
		t.Fatalf("skip %s: %v", mesh.name, err)
	}
	if run := startPF(t, mesh.name, t.TempDir()); !run.filter.Stats().Ready {
		t.Errorf("the filter over a skipped mesh utun reads not ready: %q", run.filter.Stats().Unready)
	}
}
