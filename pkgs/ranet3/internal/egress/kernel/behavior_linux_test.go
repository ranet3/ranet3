// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// noTranslationPerEndpoint is why the kernel exit neither filters by address
// alone nor hairpins
const noTranslationPerEndpoint = "an external endpoint can name several leaves at once, and a map entry keeps the value it was made with, so no destination translation per endpoint holds"

// the kernel exit meets rows 1 to 6 of the exit behavior suite in both
// families, translating to its uplink's address under auto and to an address
// of its own under the address class, and leaving the leaf's own address under
// none, carries every protocol it can translate and refuses DCCP and UDP-Lite
// under a class that translates, holding each source to the share of flows
// its capability names, the default or another, with no total of its own
// beside conntrack's table
// its stop leaves no table of its name in either family
// another writer's deletion of its tables is the change it is held to notice
// another writer's masquerade is a nat chain at srcnat made after the exit's, or one below the exit's
// the idle timers are each flow's conntrack entry as the namespace lists it
func TestKernelExitPassesTheExitBehaviorSuite(t *testing.T) {
	egresstest.Run(t, egresstest.Namespaces, egresstest.Arm{
		Classes: []egresstest.Class{egresstest.Auto, egresstest.Address, egresstest.None},
		Limits: udpLiteBefore71(t, map[egresstest.Limit]egresstest.Declared{
			egresstest.PortDependentFiltering: {
				Reason: noTranslationPerEndpoint,
				Row:    "RFC 4787 section 5, RFC 5382 section 4.3, RFC 6888 section 3 (REQ-7)",
			},
			egresstest.NoHairpinning: {
				Reason: noTranslationPerEndpoint,
				Row:    "RFC 4787 section 6, RFC 5382 section 7.2, RFC 5508 section 5",
			},
			egresstest.ResetsUnsolicitedSYN: {
				Reason: "the exit leaves the host's answer to a SYN as the host gives it, since a rule dropping a SYN no socket takes would silence the host's own closed ports too",
				Row:    "RFC 5382 section 4.3 (REQ-4), RFC 5382 section 4.2 (REQ-2a)",
			},
			egresstest.UnansweredIPv4DCCP: {
				Reason: "the kernel's reject answers a DCCP packet only where it verifies its checksum, and it verifies an IPv4 one without the pseudo-header the checksum covers",
				Row:    "RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1",
			},
		}),
		New:        newKernelExit,
		Holds:      kernelExitTables,
		Remove:     deleteKernelExitTables,
		Masquerade: masqueradeAsAnotherWriter,
		Flows:      conntrackFlows,
	})
}

// udpLiteBefore71 is limits with UDP-Lite declared unanswered on a kernel
// before 7.1
func udpLiteBefore71(t *testing.T, limits map[egresstest.Limit]egresstest.Declared) map[egresstest.Limit]egresstest.Declared {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("read the kernel's release: %v", err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("read the kernel's release %q: %v", release, err)
	}
	if major < 7 || major == 7 && minor < 1 {
		limits[egresstest.UnansweredUDPLite] = egresstest.Declared{
			Reason: "on a kernel before 7.1 connection tracking checks a UDP-Lite checksum against UDP's protocol number while nf_conntrack_checksum is on, its default, so it takes a valid packet for one no flow is tracked for, which the exit drops with no answer, and drops the reply into the mesh to one it carries under none",
			Row:    "RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1",
		}
	}
	return limits
}

// phases is RFC 5382 section 5's phase of each TCP state conntrack lists:
// opening until each end's SYN is acknowledged, established until a FIN has
// gone each way, so in FIN_WAIT and CLOSE_WAIT with one, and closing in
// LAST_ACK, with TIME_WAIT and CLOSE outside REQ-5
var phases = map[string]egresstest.Phase{
	"SYN_SENT": egresstest.Opening, "SYN_RECV": egresstest.Opening, "SYN_SENT2": egresstest.Opening,
	"ESTABLISHED": egresstest.Established, "FIN_WAIT": egresstest.Established, "CLOSE_WAIT": egresstest.Established,
	"LAST_ACK": egresstest.Closing,
}

// conntrackFlows reads the exit's conntrack table from the listing /proc keeps
// of it, which holds each entry's state and seconds left as a ctnetlink dump
// does, with no module to load for it
func conntrackFlows(host egresstest.Host) ([]egresstest.Flow, error) {
	var listing []byte
	if err := host.Do(func() (err error) {
		listing, err = os.ReadFile("/proc/thread-self/net/nf_conntrack")
		return err
	}); err != nil {
		return nil, err
	}
	var flows []egresstest.Flow
	for line := range strings.Lines(string(listing)) {
		flow, err := conntrackFlow(strings.Fields(line))
		if err != nil {
			return nil, fmt.Errorf("conntrack lists %q: %w", line, err)
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

// conntrackFlow reads one entry of the listing: its family's name and number,
// its protocol's name and number, the seconds left, a TCP entry's state, then
// the original direction's addresses and ports ahead of the reply's, an echo's
// identifier in place of the ports, and no port for a protocol without them
func conntrackFlow(fields []string) (egresstest.Flow, error) {
	if len(fields) < 6 {
		return egresstest.Flow{}, errors.New("too few fields")
	}
	original := map[string]string{}
	for _, field := range fields[5:] {
		if key, value, ok := strings.Cut(field, "="); ok {
			if _, seen := original[key]; !seen {
				original[key] = value
			}
		}
	}
	port := func(key string) (uint64, error) {
		if value, ok := original[key]; ok {
			return strconv.ParseUint(value, 10, 16)
		}
		return 0, nil
	}
	sport, dport := "sport", "dport"
	if _, ok := original["id"]; ok {
		sport, dport = "id", "id"
	}
	protocol, errProtocol := strconv.ParseUint(fields[3], 10, 8)
	seconds, errSeconds := strconv.ParseUint(fields[4], 10, 32)
	from, errFrom := netip.ParseAddr(original["src"])
	to, errTo := netip.ParseAddr(original["dst"])
	fromPort, errFromPort := port(sport)
	toPort, errToPort := port(dport)
	if err := errors.Join(errProtocol, errSeconds, errFrom, errTo, errFromPort, errToPort); err != nil {
		return egresstest.Flow{}, err
	}
	return egresstest.Flow{
		Protocol: byte(protocol),
		From:     netip.AddrPortFrom(from, uint16(fromPort)),
		To:       netip.AddrPortFrom(to, uint16(toPort)),
		Phase:    phases[fields[5]],
		Left:     time.Duration(seconds) * time.Second,
	}, nil
}

// srcnat is NF_IP_PRI_NAT_SRC, the priority a host's source translation runs
// at, where the kernel runs a chain made later ahead of those made before it,
// and the kernel exit's chain is one below it
const srcnat = 100

// masqueradeAsAnotherWriter adds another writer's table in each family whose
// nat chain masquerades every packet at postrouting, at srcnat, made after the
// exit's chain, or ahead of it below the exit's chain, where an operator who
// translates a mesh flow itself puts one, and returns what deletes the tables
func masqueradeAsAnotherWriter(host egresstest.Host, ahead bool) (func() error, error) {
	if ahead {
		return masqueradeAt(host, srcnat-2)
	}
	return masqueradeAt(host, srcnat)
}

func masqueradeAt(host egresstest.Host, priority int32) (func() error, error) {
	const table = "another"
	chain := nftables.Chain{Table: table, Name: "postrouting", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: priority}
	var requests []nftables.Request
	for _, proto := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
		rule, err := chain.Rule(proto, "masquerade", [][]byte{nftables.Expression("masq", nil)})
		if err != nil {
			return nil, err
		}
		requests = append(requests, nftables.NewTable(proto, table), chain.Create(proto), rule)
	}
	batch := func(requests []nftables.Request) error {
		return host.Do(func() error {
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			return conn.Batch(requests)
		})
	}
	undo := func() error {
		return batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_IPV4, table), nftables.DeleteTable(unix.NFPROTO_IPV6, table)})
	}
	return undo, batch(requests)
}

// newKernelExit builds the kernel exit as the daemon does, its reads of the
// host made in the exit's namespace, which Run's goroutine is not in
func newKernelExit(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
	t.Helper()
	inExit := func(f func()) { _ = host.Do(func() error { f(); return nil }) }
	var exit *kernelexit.Translator
	if err := host.Do(func() (err error) {
		exit, err = kernelexit.New(cfg, kernelexit.Runtime{
			Interface:     host.TUN,
			Write:         host.Write,
			MeshAddresses: host.Mesh,
			Forwarding:    func() (v4, v6 bool) { inExit(func() { v4, v6 = client.Forwarding() }); return v4, v6 },
			Lookup: func(lookups []kernelexit.Lookup) (answers []kernelexit.Answer, err error) {
				inExit(func() { answers, err = client.RouteLookups(lookups) })
				return answers, err
			},
			Sysctl:  func(path string) (value string) { inExit(func() { value = client.Sysctl(path) }); return value },
			Members: host.Members,
			Hooks:   hooks,
		})
		return err
	}); err != nil {
		t.Fatalf("build the kernel exit: %v", err)
	}
	return exit
}

// kernelExitTables names each table of the kernel exit's name in the exit's
// namespace, of either family it translates
func kernelExitTables(host egresstest.Host) ([]string, error) {
	var held []string
	err := host.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		tables, err := nftables.Tables(conn, kernelexit.TableName)
		if err != nil {
			return err
		}
		for family, name := range map[uint8]string{unix.NFPROTO_IPV4: "ip", unix.NFPROTO_IPV6: "ip6"} {
			if _, ok := tables[family]; ok {
				held = append(held, "table "+name+" "+kernelexit.TableName)
			}
		}
		return nil
	})
	slices.Sort(held)
	return held, err
}

// the socket is not the exit's, so the exit reads the deletion as another
// writer's
func deleteKernelExitTables(host egresstest.Host) error {
	return host.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.Batch([]nftables.Request{
			nftables.DeleteTable(unix.NFPROTO_IPV4, kernelexit.TableName),
			nftables.DeleteTable(unix.NFPROTO_IPV6, kernelexit.TableName),
		})
	})
}
