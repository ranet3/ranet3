// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egresstest

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// a backend that maps the leaf's ports to others of its own meets rows 1, 3
// and 5, which read the mapping as RFC 4787 and RFC 5382 define it, one
// outside endpoint toward every destination, and never against the leaf's port
func TestPortMappingBackendMeetsTheRowsThatReadTheMapping(t *testing.T) {
	fakeRows(t, Arm{New: fake{maps: true}.build, Holds: fakeTables}, func(t *testing.T, r *rows) {
		t.Run("the fake maps the leaf's port", func(t *testing.T) {
			to := netip.AddrPortFrom(r.family.Server, mappedCheckPort)
			server, leaf := r.listenUDP(t, to), r.dialUDP(t, to)
			sent := []byte("is the port mapped over " + r.family.Name)
			if from := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) }); from.Port() < mappedLow || from.Port() > mappedHigh {
				t.Fatalf("the server read the leaf's datagram from %s, want a port of %d to %d", from, mappedLow, mappedHigh)
			}
		})
		t.Run("what the server sees", r.serverSees)
		t.Run("path mtu", r.pathMTU)
		t.Run("port reuse", r.portReuse)
	})
}

// a backend that ends the leaf's TCP at the exit and opens its own toward the
// server meets row 3 with no too big of its own for the leaf's segments
func TestTerminatingBackendMeetsThePathMTURow(t *testing.T) {
	var built *fakeExit
	fakeRows(t, Arm{Terminates: true, New: func(t testing.TB, host Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
		built = fake{terminates: true}.build(t, host, cfg, hooks).(*fakeExit)
		return built
	}, Holds: fakeTables}, func(t *testing.T, r *rows) {
		relayed := built.relayed.Load()
		t.Run("path mtu", r.pathMTU)
		if built.relayed.Load() == relayed {
			t.Error("the fake relayed none of the transfer's connections, so the row met a forwarding backend")
		}
	})
}

// Run would run every row, and a fake is built to meet only the rows its test
// names
func fakeRows(t *testing.T, arm Arm, run func(t *testing.T, r *rows)) {
	network := Namespaces(t)
	exit := start(t, network, arm, Auto)
	for _, v6 := range []bool{false, true} {
		r := &rows{network: network, family: network.Family(v6), class: Auto, exit: exit, terminates: arm.Terminates}
		t.Run(r.family.Name, func(t *testing.T) { run(t, r) })
	}
	t.Run("stop", exit.stop)
}

type fake struct{ maps, terminates bool }

func (f fake) build(_ testing.TB, host Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
	return &fakeExit{host: host, cfg: cfg, hooks: hooks, maps: f.maps, terminates: f.terminates}
}

// fakeExit is a backend of a class no real one belongs to yet, for the suite's
// own tests. It writes what it takes to the mesh's tun and has nf_tables
// translate it out of the uplink, under maps to a port of mappedLow to
// mappedHigh, and under terminates it ends the leaf's TCP at a listener of its
// own and opens its own connection to where the leaf's was going.
type fakeExit struct {
	host             Host
	cfg              egress.Egress
	hooks            egress.Hooks
	maps, terminates bool
	announced        atomic.Pointer[[]netip.Prefix]
	ready            atomic.Bool
	listeners        []*net.TCPListener
	relays           sync.WaitGroup
	relayed          atomic.Int64
}

func (f *fakeExit) Run(ctx context.Context) error {
	if err := f.host.Do(f.install); err != nil {
		return err
	}
	f.ready.Store(true)
	f.hooks.Ready(true, true, true)
	var advertised []netip.Prefix
	for _, prefix := range f.cfg.Advertise {
		advertised = append(advertised, prefix.Prefix)
	}
	f.publish(advertised)
	<-ctx.Done()
	f.ready.Store(false)
	f.hooks.Ready(false, false, false)
	f.publish(nil)
	err := f.host.Do(f.withdraw)
	for _, listener := range f.listeners {
		_ = listener.Close()
	}
	f.relays.Wait()
	return err
}

// SetEnabled is no part of what a fake stands in for, and no test that builds one calls it
func (f *fakeExit) SetEnabled(bool) {}

func (f *fakeExit) Egress(frames [][]byte) { f.host.Write(frames) }

func (f *fakeExit) Announce() []netip.Prefix {
	if announced := f.announced.Load(); announced != nil {
		return *announced
	}
	return nil
}

func (f *fakeExit) Status() egress.Status {
	return egress.Status{Backend: "fake", Ready4: f.ready.Load(), Ready6: f.ready.Load(), Announced: f.Announce()}
}

func (f *fakeExit) publish(prefixes []netip.Prefix) {
	f.announced.Store(&prefixes)
	f.hooks.Republish()
}

var families = []struct{ proto, family uint8 }{
	{unix.NFPROTO_IPV4, egress.FamilyIPv4},
	{unix.NFPROTO_IPV6, egress.FamilyIPv6},
}

// install runs in the exit's namespace
func (f *fakeExit) install() error {
	conn, err := nftables.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	post := nftables.Chain{Table: fakeTable, Name: "post", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: 100}
	pre := nftables.Chain{Table: fakeTable, Name: "pre", Type: "nat", Hook: unix.NF_INET_PRE_ROUTING, Priority: -100}
	var batch []nftables.Request
	for _, family := range families {
		translate, err := post.Rule(family.proto, "translate", f.translation(family.proto, family.family))
		if err != nil {
			return err
		}
		batch = append(batch, nftables.NewTable(family.proto, fakeTable), post.Create(family.proto), translate)
		if f.terminates {
			terminate, err := pre.Rule(family.proto, "terminate", f.termination())
			if err != nil {
				return err
			}
			batch = append(batch, pre.Create(family.proto), terminate)
		}
	}
	if err := conn.Batch(batch); err != nil {
		return err
	}
	if !f.terminates {
		return nil
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		listener, err := net.ListenTCP(network, &net.TCPAddr{Port: terminatorPort})
		if err != nil {
			return err
		}
		f.listeners = append(f.listeners, listener)
		f.relays.Go(func() {
			for {
				leaf, err := listener.AcceptTCP()
				if err != nil {
					return
				}
				f.relays.Go(func() { f.relay(leaf) })
			}
		})
	}
	return nil
}

func (f *fakeExit) translation(proto, family uint8) [][]byte {
	expressions := slices.Concat(
		nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, f.host.TUN),
		nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_NEQ, f.host.TUN),
	)
	if f.maps {
		expressions = append(expressions, immediate(unix.NFT_REG_2, port(mappedLow)), immediate(unix.NFT_REG_3, port(mappedHigh)))
	}
	source := f.cfg.SourceOf(family).Addr
	if !source.IsValid() {
		var masq []byte
		if f.maps {
			// masquerade, unlike snat, takes its port registers as a range only where the flags say so
			masq = nftables.PutAttrBE32(masq, unix.NFTA_MASQ_FLAGS, unix.NF_NAT_RANGE_PROTO_SPECIFIED)
			masq = nftables.PutAttrBE32(masq, unix.NFTA_MASQ_REG_PROTO_MIN, unix.NFT_REG_2)
			masq = nftables.PutAttrBE32(masq, unix.NFTA_MASQ_REG_PROTO_MAX, unix.NFT_REG_3)
		}
		return append(expressions, nftables.Expression("masq", masq))
	}
	nat := nftables.PutAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT)
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(proto))
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	if f.maps {
		nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_REG_PROTO_MIN, unix.NFT_REG_2)
		nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_REG_PROTO_MAX, unix.NFT_REG_3)
	}
	return append(expressions, immediate(unix.NFT_REG_1, nftables.AddressBytes(source)), nftables.Expression("nat", nat))
}

func (f *fakeExit) termination() [][]byte {
	return slices.Concat(
		nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, f.host.TUN),
		nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{unix.IPPROTO_TCP}),
		[][]byte{
			immediate(unix.NFT_REG_1, port(terminatorPort)),
			nftables.Expression("redir", nftables.PutAttrBE32(nil, unix.NFTA_REDIR_REG_PROTO_MIN, unix.NFT_REG_1)),
		},
	)
}

func immediate(register uint32, value []byte) []byte {
	data := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, register)
	data = nftables.PutAttr(data, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, value))
	return nftables.Expression("immediate", data)
}

func port(p uint16) []byte { return binary.BigEndian.AppendUint16(nil, p) }

func (f *fakeExit) relay(leaf *net.TCPConn) {
	defer leaf.Close()
	to, err := originalDestination(leaf)
	if err != nil {
		return
	}
	dialer := net.Dialer{Timeout: stepBudget}
	if source := f.cfg.SourceOf(egress.AddressFamily(to.Addr())).Addr; source.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
	}
	var server *net.TCPConn
	if err := f.host.Do(func() error {
		conn, err := dialer.Dial("tcp", to.String())
		if err == nil {
			server = conn.(*net.TCPConn)
		}
		return err
	}); err != nil {
		_ = leaf.SetLinger(0)
		return
	}
	defer server.Close()
	f.relayed.Add(1)
	deadline := time.Now().Add(transferBudget)
	var ways sync.WaitGroup
	for _, way := range [][2]*net.TCPConn{{leaf, server}, {server, leaf}} {
		_ = way[0].SetDeadline(deadline)
		ways.Go(func() {
			_, _ = io.Copy(way[1], way[0])
			_ = way[1].CloseWrite()
		})
	}
	ways.Wait()
}

func originalDestination(conn *net.TCPConn) (netip.AddrPort, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var to netip.AddrPort
	var asked error
	if err := raw.Control(func(fd uintptr) {
		if addrPort(conn.LocalAddr()).Addr().Is4() {
			// a struct sockaddr_in, its port and address in network order after the family
			var mreq *unix.IPv6Mreq
			if mreq, asked = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST); asked == nil {
				to = netip.AddrPortFrom(netip.AddrFrom4([4]byte(mreq.Multiaddr[4:8])), binary.BigEndian.Uint16(mreq.Multiaddr[2:4]))
			}
			return
		}
		// IP6T_SO_ORIGINAL_DST shares SO_ORIGINAL_DST's number, and answers a struct sockaddr_in6
		var info *unix.IPv6MTUInfo
		if info, asked = unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, unix.SO_ORIGINAL_DST); asked == nil {
			to = netip.AddrPortFrom(netip.AddrFrom16(info.Addr.Addr), binary.BigEndian.Uint16(binary.NativeEndian.AppendUint16(nil, info.Addr.Port)))
		}
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return to, asked
}

// withdraw runs in the exit's namespace
func (f *fakeExit) withdraw() error {
	conn, err := nftables.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	var batch []nftables.Request
	for _, family := range families {
		batch = append(batch, nftables.DeleteTable(family.proto, fakeTable))
	}
	return conn.Batch(batch)
}

func fakeTables(host Host) ([]string, error) {
	var held []string
	err := host.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		tables, err := nftables.Tables(conn, fakeTable)
		for family := range tables {
			held = append(held, fmt.Sprintf("table of family %d %s", family, fakeTable))
		}
		return err
	})
	slices.Sort(held)
	return held, err
}
