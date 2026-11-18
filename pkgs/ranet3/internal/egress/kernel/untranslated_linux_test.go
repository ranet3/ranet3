// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// invalidSegment is a TCP segment from port 4000 to port 80 carrying SYN and
// FIN at once and no checksum, which conntrack takes as invalid on either count
var invalidSegment = []byte{0x0f, 0xa0, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x03, 0x04, 0x00, 0, 0, 0, 0}

// farPorts are the ports the far end takes the first and the second flow of
// each source on
var farPorts = [2]uint16{4791, 4792}

// farListener is a socket of the far end and the payloads it has taken
type farListener struct {
	conn *net.UDPConn
	seen map[string]bool
}

// await reports whether the listener takes payload within wait
func (l *farListener) await(t *testing.T, payload string, wait time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(wait)
	buf := make([]byte, 128)
	for !l.seen[payload] {
		if err := l.conn.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		n, err := l.conn.Read(buf)
		if err != nil {
			return false
		}
		l.seen[string(buf[:n])] = true
	}
	return true
}

// sockaddr is addr with no port, as a raw socket takes it
func sockaddr(addr netip.Addr) unix.Sockaddr {
	if addr.Is4() {
		return &unix.SockaddrInet4{Addr: addr.As4()}
	}
	return &unix.SockaddrInet6{Addr: addr.As16()}
}

// sendSegment sends invalidSegment from from to to in the leaf's namespace
func sendSegment(leaf *netnstest.Thread, from, to netip.Addr) error {
	return leaf.Do(func() error {
		domain := unix.AF_INET6
		if from.Is4() {
			domain = unix.AF_INET
		}
		fd, err := unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, sockaddr(from)); err != nil {
			return err
		}
		return unix.Sendto(fd, invalidSegment, 0, sockaddr(to))
	})
}

// dialFrom is a UDP socket of the leaf's namespace from from to to
func dialFrom(leaf *netnstest.Thread, from netip.Addr, to netip.AddrPort) (conn *net.UDPConn, err error) {
	err = leaf.Do(func() error {
		conn, err = net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 0)), net.UDPAddrFromAddrPort(to))
		return err
	})
	return conn, err
}

// screenPackets is the packets the line of chain commented spec counted, as
// nft lists it
func screenPackets(t *testing.T, run func(...string) string, chain, spec string) uint64 {
	t.Helper()
	line := regexp.MustCompile(`packets (\d+) bytes \d+ [^\n]*comment "` + regexp.QuoteMeta(spec) + `"`).FindStringSubmatch(run("list", "chain", "inet", nftables.Table, chain))
	if line == nil {
		t.Fatalf("chain %s holds no line commented %q", chain, spec)
	}
	packets, err := strconv.ParseUint(line[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

// A table written under nested classes of both families, a class that
// translates inside a class of none with a class of none inside it and a
// host's class of none inside a class that translates, holds in untranslated4
// and untranslated6 the sources whose longest covering class is none, adjacent
// ranges as one. From a source inside each kind of range, and from one no
// class covers, the leaf sends across the exit's forward hook, from ranet0 to
// its uplink, an invalid TCP segment, then two UDP flows under a share of one
// flow a source. From a source whose class is none both flows reach the far
// end and no screen counts a packet. From one whose class translates or that
// no class covers the drop of untracked packets counts the segment and the
// limit refuses the second flow, each once.
func TestNftablesPassesTheUntranslatedSourcesAlonePastTheScreens(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	sources := []struct {
		addr netip.Addr
		none bool
	}{
		{a("192.0.2.200"), true}, {a("192.0.2.100"), false}, {a("192.0.2.40"), true}, {a("192.0.2.10"), false}, {a("192.0.2.5"), true},
		{a("3fff:0:8000::1"), true}, {a("3fff:0:0:8000::1"), false}, {a("3fff::2"), true}, {a("3fff::1"), false},
		// no class covers these, addresses of the leaf's link beside its own
		{a("198.51.100.50"), false}, {a("2001:db8:2::50"), false},
	}
	// the exit's links: ranet0 to the leaf, which routes every source to it,
	// and up0 to the far end
	exit, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	for _, link := range []struct {
		name, far string
		thread    *netnstest.Thread
		here      []netip.Prefix
		there     []netip.Prefix
	}{
		{"ranet0", "leaf0", leaf, []netip.Prefix{p("198.51.100.1/24"), p("2001:db8:2::1/64")}, []netip.Prefix{p("198.51.100.2/24"), p("2001:db8:2::2/64")}},
		{"up0", "far0", far, []netip.Prefix{p("203.0.113.1/24"), p("2001:db8:1::1/64")}, []netip.Prefix{p("203.0.113.9/24"), p("2001:db8:1::9/64")}},
	} {
		if err := exit.AddVeth(link.name, link.far, 0, link.thread.Path); err != nil {
			t.Fatalf("make %s: %v", link.name, err)
		}
		if err := exit.AddAddresses(link.name, link.here...); err != nil {
			t.Fatal(err)
		}
		there := link.there
		if link.thread == leaf {
			for _, source := range sources {
				there = append(there, netip.PrefixFrom(source.addr, source.addr.BitLen()))
			}
		}
		if err := link.thread.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if err := netlink.AddAddresses(link.far, there...); err != nil {
				return err
			}
			end, err := net.InterfaceByName(link.far)
			if err != nil {
				return err
			}
			// the far end routes back through the exit too, so its reverse path
			// filter takes a source the exit leaves untranslated
			return errors.Join(netlink.RouteVia(end.Index, p("0.0.0.0/0"), link.here[0].Addr()), netlink.RouteVia(end.Index, p("::/0"), link.here[1].Addr()))
		}); err != nil {
			t.Fatalf("address and route %s: %v", link.far, err)
		}
	}
	ranet0, err := net.InterfaceByName("ranet0")
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(exit.RouteVia(ranet0.Index, p("192.0.2.0/24"), a("198.51.100.2")), exit.RouteVia(ranet0.Index, p("3fff::/20"), a("2001:db8:2::2"))); err != nil {
		t.Fatalf("route the sources to the leaf: %v", err)
	}
	for _, path := range []string{"/proc/sys/net/ipv4/conf/all/forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	var listeners [2]*farListener
	for i, port := range farPorts {
		if err := far.Do(func() error {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
			listeners[i] = &farListener{conn: conn, seen: map[string]bool{}}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listeners[i].conn.Close() })
	}

	cfg := egress.Egress{FlowsPerSource: 1, Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/27"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("192.0.2.5/32"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("3fff::/32"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("3fff::/48"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("3fff::/64"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("3fff::1/128"), To: egress.Translation{Auto: true}},
	}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	if err := newTranslator(cfg, rt, be).reconcile(); err != nil {
		t.Fatalf("the pass: %v", err)
	}
	for set, want := range map[string]string{
		untranslatedSet + "4": "192.0.2.5, 192.0.2.32/27, 192.0.2.128/25",
		untranslatedSet + "6": "3fff::, 3fff::2-3fff::ffff:ffff:ffff:ffff, 3fff:0:1::-3fff:0:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		if listing := strings.Join(strings.Fields(run("list", "set", "inet", nftables.Table, set)), " "); !strings.Contains(listing, "elements = { "+want+" }") {
			t.Errorf("nft lists %s, want its elements { %s }", listing, want)
		}
	}

	// the first datagrams may meet a veth whose carrier is not up yet, and one
	// socket of the leaf's own address keeps them one flow
	for _, probe := range []struct{ from, to netip.Addr }{{a("198.51.100.2"), a("203.0.113.9")}, {a("2001:db8:2::2"), a("2001:db8:1::9")}} {
		conn, err := dialFrom(leaf, probe.from, netip.AddrPortFrom(probe.to, farPorts[0]))
		if err != nil {
			t.Fatal(err)
		}
		payload := "probe " + probe.from.String()
		for deadline := time.Now().Add(siteWait); !listeners[0].await(t, payload, siteProbeWait); {
			if time.Now().After(deadline) {
				t.Fatalf("no datagram from %s reached the far end within %s", probe.from, siteWait)
			}
			if _, err := conn.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
		}
		_ = conn.Close()
	}

	for _, source := range sources {
		family, chain, to := "ipv4", LimitChain, a("203.0.113.9")
		if source.addr.Is6() {
			family, chain, to = "ipv6", forward6.Name, a("2001:db8:1::9")
		}
		screens := []string{"out via ranet0 " + family + " untracked dropped", "out via ranet0 " + family + " limit 1"}
		counted := func() (packets [2]uint64) {
			for i, spec := range screens {
				packets[i] = screenPackets(t, run, chain, spec)
			}
			return packets
		}
		before := counted()
		if err := sendSegment(leaf, source.addr, to); err != nil {
			t.Fatalf("send a segment from %s: %v", source.addr, err)
		}
		for i, port := range farPorts {
			conn, err := dialFrom(leaf, source.addr, netip.AddrPortFrom(to, port))
			if err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf("flow %d from %s", i+1, source.addr)
			if _, err := conn.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			switch {
			// the first flow follows the segment through the hook, so its
			// arrival has the segment counted where a screen meets it
			case i == 0 || source.none:
				if !listeners[i].await(t, payload, siteWait) {
					t.Errorf("%s did not reach the far end within %s", payload, siteWait)
				}
			default:
				for deadline := time.Now().Add(siteWait); counted()[1] == before[1] && time.Now().Before(deadline); time.Sleep(siteProbeWait) {
				}
			}
		}
		after := counted()
		want := uint64(1)
		if source.none {
			want = 0
		}
		for i, spec := range screens {
			if after[i]-before[i] != want {
				t.Errorf("from %s, whose class is none: %v, %q counted %d packets, want %d", source.addr, source.none, spec, after[i]-before[i], want)
			}
		}
	}
	listeners[1].await(t, "", quietFor)
	for _, source := range sources {
		if payload := fmt.Sprintf("flow 2 from %s", source.addr); !source.none && listeners[1].seen[payload] {
			t.Errorf("%s reached the far end past the limit", payload)
		}
	}
}

// A pass writes untranslated4 and untranslated6 to either end of their family:
// the whole family under a class of none at /0, ranges from the address past
// the first and up to the last with the last host on its own, the last host
// alone and the first host alone, each configuration taken over from the one
// before by a new instance. nft lists each set as the classes say, holds each
// end the set holds and refuses its neighbor outside it, both families read
// ready, and a second pass rewrites no line.
func TestNftablesWritesTheUntranslatedSetsToEachEndOfTheFamily(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	none := func(prefix string) egress.Class {
		return egress.Class{From: schema.MustPrefix(prefix), To: egress.Translation{None: true}}
	}
	auto := func(prefix string) egress.Class {
		return egress.Class{From: schema.MustPrefix(prefix), To: egress.Translation{Auto: true}}
	}
	const last4, last6 = "255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	handles := regexp.MustCompile(`# handle \d+`)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	var previous backend
	defer func() {
		if previous != nil {
			_ = previous.Close()
		}
	}()
	for _, c := range []struct {
		name    string
		classes []egress.Class
		// listed is each family's elements as nft lists them
		listed [2]string
		// held and refused are addresses the sets hold and do not
		held, refused []string
	}{
		{"the whole family", []egress.Class{none("0.0.0.0/0"), none("::/0")},
			[2]string{"0.0.0.0/0", "::/0"},
			[]string{"0.0.0.0", last4, "::", last6}, nil},
		{"from past the first address up to the last", []egress.Class{
			none("0.0.0.0/8"), auto("0.0.0.0/32"), none("128.0.0.0/1"), auto("255.255.255.0/24"), none(last4 + "/32"),
			none("::/1"), auto("::/128"), none(last6 + "/128")},
			[2]string{"0.0.0.1-0.255.255.255, 128.0.0.0-255.255.254.255, 255.255.255.255", "::1-7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, " + last6},
			[]string{"0.0.0.1", "255.255.254.255", last4, "::1", last6},
			[]string{"0.0.0.0", "255.255.255.254", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"}},
		{"the last host alone", []egress.Class{none(last4 + "/32"), none(last6 + "/128")},
			[2]string{last4, last6},
			[]string{last4, last6}, []string{"255.255.255.254", "0.0.0.0", "::"}},
		{"the first host alone", []egress.Class{none("0.0.0.0/32"), none("::/128")},
			[2]string{"0.0.0.0", "::"},
			[]string{"0.0.0.0", "::"}, []string{"0.0.0.1", "::1"}},
		{"the whole family again", []egress.Class{none("0.0.0.0/0"), none("::/0")},
			[2]string{"0.0.0.0/0", "::/0"},
			[]string{"0.0.0.0", last4}, nil},
	} {
		cfg := egress.Egress{Translate: c.classes}
		if previous != nil {
			_ = previous.Close()
		}
		be, err := newBackend(cfg, rt)
		if err != nil {
			t.Fatalf("%s: open the nftables backend: %v", c.name, err)
		}
		previous = be
		tr := newTranslator(cfg, rt, be)
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the first pass: %v\n%s", c.name, err, run("list", "table", "inet", nftables.Table))
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: after the first pass the translator reads %+v, want both families ready", c.name, s)
		}
		for i, set := range []string{untranslatedSet + "4", untranslatedSet + "6"} {
			if listing := strings.Join(strings.Fields(run("list", "set", "inet", nftables.Table, set)), " "); !strings.Contains(listing, "elements = { "+c.listed[i]+" }") {
				t.Errorf("%s: nft lists %s, want its elements { %s }", c.name, listing, c.listed[i])
			}
		}
		for _, addr := range slices.Concat(c.held, c.refused) {
			set := untranslatedSet + "4"
			if netip.MustParseAddr(addr).Is6() {
				set = untranslatedSet + "6"
			}
			out, err := exec.Command(nft, "get", "element", "inet", nftables.Table, set, "{", addr, "}").CombinedOutput()
			if held := slices.Contains(c.held, addr); (err == nil) != held {
				t.Errorf("%s: nft get element %s of %s: %v, want held %v\n%s", c.name, addr, set, err, held, out)
			}
		}
		before := handles.FindAllString(run("-a", "list", "table", "inet", nftables.Table), -1)
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the second pass: %v", c.name, err)
		}
		after := handles.FindAllString(run("-a", "list", "table", "inet", nftables.Table), -1)
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 || !slices.Equal(before, after) {
			t.Errorf("%s: after the second pass the translator reads %+v, and the handles are %v, want both families ready and %v", c.name, s, after, before)
		}
	}
}
