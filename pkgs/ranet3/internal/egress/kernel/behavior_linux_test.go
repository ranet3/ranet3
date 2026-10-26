// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// the kernel exit meets rows 1 to 5 of the exit behavior suite in both
// families, translating to its uplink's address under auto and to an address
// of its own under the address class, and leaving the leaf's own address under
// none, and carries every protocol with no limit of its own
// its stop leaves no table of its name in either family
// another writer's deletion of its tables is the change it is held to notice
// another writer's masquerade is a nat chain one priority behind srcnat or ahead of it
func TestKernelExitPassesTheExitBehaviorSuite(t *testing.T) {
	egresstest.Run(t, egresstest.Namespaces, egresstest.Arm{
		Classes:    []egresstest.Class{egresstest.Auto, egresstest.Address, egresstest.None},
		New:        newKernelExit,
		Holds:      kernelExitTables,
		Remove:     deleteKernelExitTables,
		Overtake:   overtakeAsAnotherWriter,
		Masquerade: masqueradeAsAnotherWriter,
	})
}

// srcnat is NF_IP_PRI_NAT_SRC, the priority source translation runs at, which
// the kernel exit's chain is held to here by a chain one either side of it and
// one at it, which the kernel runs ahead of every chain at srcnat made before it
const srcnat = 100

// masqueradeAsAnotherWriter adds another writer's table in each family whose
// nat chain masquerades every packet at postrouting, one priority behind
// srcnat or ahead of it, and returns what deletes the tables
func masqueradeAsAnotherWriter(host egresstest.Host, ahead bool) (func() error, error) {
	if ahead {
		return masqueradeAt(host, srcnat-1)
	}
	return masqueradeAt(host, srcnat+1)
}

// overtakeAsAnotherWriter is masqueradeAsAnotherWriter at srcnat itself
func overtakeAsAnotherWriter(host egresstest.Host) (func() error, error) {
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
