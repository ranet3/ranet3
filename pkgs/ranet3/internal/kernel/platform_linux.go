// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// netlinkConn is everything this backend asks of a netlink socket. Reaching
// AddRoute, DelRoute or AddAddr without it means opening a real socket, which
// needs root, so the checks skip them and a change to what this backend writes
// goes unnoticed on the platform the fleet runs. darwin's rtSocket is the same
// seam.
type netlinkConn interface {
	execute(kind, flags uint16, body []byte) ([]nlMessage, error)
	link(index uint32, name string) (linkInfo, error)
	Close() error
}

// netlinkPlatform is the rtnetlink half of the reconciler. Nothing here
// decides what the kernel should hold. It only encodes the decision and
// enforces the ownership marker on the way back in, so a route without the
// reconciler's protocol, table and interface never reaches the diff.
type netlinkPlatform struct {
	table   Table
	rt      Runtime
	index   uint32
	conn    netlinkConn
	monitor *routeMonitor

	// occupied remembers routes already reported as held by another writer.
	// A foreign route on our key does not go away by itself, so every pass
	// would otherwise repeat the same warning. Only the reconcile loop touches
	// this, and it runs one pass at a time.
	//
	// refused holds the keys the current pass watched the kernel refuse, and
	// Routes swaps it into occupied once the next one has dumped. A foreign route is filtered
	// out of the dump by protocol, so it never reaches a delete list and
	// DelRoute is never called for it: when the mesh stops announcing that
	// prefix the record would have no exit at all.
	occupied map[Route]bool
	refused  map[Route]bool
}

// each optional half is reached only through a type assertion
// a method renamed on one side would drop it without a word
var (
	_ auditor     = (*netlinkPlatform)(nil)
	_ ruler       = (*netlinkPlatform)(nil)
	_ lengthKeyer = (*netlinkPlatform)(nil)
	_ looker      = (*netlinkPlatform)(nil)
)

func (p *netlinkPlatform) lookups(reads []RouteRead) ([]BatchAnswer, error) {
	return routeGetBatch(p.conn, reads)
}

// RefuseExitMode is nil here, where the reconciler's policy rules carry cap.exit
func RefuseExitMode() error { return nil }

// ipv4DevconfPromoteSecondaries is IPV4_DEVCONF_PROMOTE_SECONDARIES of linux/ip.h, which x/sys does not carry
const ipv4DevconfPromoteSecondaries = 20

func newPlatform(t Table, rt Runtime) (platform, error) {
	conn, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	// the index is resolved once: netstack owns the TUN for the whole
	// process lifetime, so a changed index means a different device and the
	// routes of the old one are already gone with it.
	tun, err := conn.link(0, rt.Interface)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kernel: look up interface %s: %w", rt.Interface, err)
	}
	if err := promoteSecondaries(conn, tun.index); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kernel: promote secondary addresses on %s: %w", rt.Interface, err)
	}
	monitor, err := newRouteMonitor(uint32(t.ID), t.Proto, tun.index)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &netlinkPlatform{table: t, rt: rt, index: tun.index, conn: conn, monitor: monitor,
		occupied: make(map[Route]bool), refused: make(map[Route]bool)}, nil
}

func (p *netlinkPlatform) Notify() <-chan struct{} { return p.monitor.signal }

func (p *netlinkPlatform) Close() error {
	return errors.Join(p.monitor.Close(), p.conn.Close())
}

func (p *netlinkPlatform) Routes() ([]Route, error) {
	var out []Route
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		// the kernel filters on the table and the protocol
		// decodeRoute holds every route to the whole marker all the same
		replies, err := p.dumpTable(family, p.table.Proto)
		if err != nil {
			return nil, err
		}
		for _, reply := range replies {
			if route, ok := p.decodeRoute(reply); ok {
				out = append(out, route)
			}
		}
	}
	// Rotated here rather than first, so a failed dump leaves the record
	// alone: it returns above without any AddRoute refilling it, and two such
	// passes would empty it and repeat every warning it exists to silence.
	// Routes starts every reconcile pass, the same way the darwin backend
	// rotates its own.
	p.occupied, p.refused = p.refused, make(map[Route]bool, len(p.refused))
	return out, nil
}

// dumpTable dumps one family's routes in this reconciler's table, only those of protocol when it is set
// the kernel filters the dump
// a host holding a full table in main then pays nothing for it here
// a table nothing has written yet does not exist
// its dump ends on ENOENT, which reads as empty here and in no other dump
func (p *netlinkPlatform) dumpTable(family, protocol uint8) ([]nlMessage, error) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = family
	body[5] = protocol
	body = putAttrU32(body, unix.RTA_TABLE, uint32(p.table.ID))
	replies, err := p.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return replies, err
}

// decodeRoute keeps only the routes this reconciler owns. Everything else in
// the dump belongs to somebody else, so it is dropped here and can never reach
// a delete list.
func (p *netlinkPlatform) decodeRoute(message nlMessage) (Route, bool) {
	if message.Kind != unix.RTM_NEWROUTE || len(message.Data) < unix.SizeofRtMsg {
		return Route{}, false
	}
	family, dstLen, srcLen := message.Data[0], message.Data[1], message.Data[2]
	table, protocol, kind := uint32(message.Data[4]), message.Data[5], message.Data[7]
	if protocol != p.table.Proto || (kind != unix.RTN_UNICAST && kind != unix.RTN_UNREACHABLE && kind != unix.RTN_THROW) {
		return Route{}, false
	}
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return Route{}, false
	}
	var destination, source netip.Addr
	var oif, metric uint32
	for attr, value := range message.attributes(unix.SizeofRtMsg) {
		switch attr {
		case unix.RTA_TABLE:
			// rtm_table is a byte, so a table above 255 only exists here.
			if len(value) == 4 {
				table = binary.NativeEndian.Uint32(value)
			}
		case unix.RTA_DST:
			destination, _ = addressFromBytes(value)
		case unix.RTA_SRC:
			source, _ = addressFromBytes(value)
		case unix.RTA_OIF:
			if len(value) == 4 {
				oif = binary.NativeEndian.Uint32(value)
			}
		case unix.RTA_PRIORITY:
			if len(value) == 4 {
				metric = binary.NativeEndian.Uint32(value)
			}
		}
	}
	// A hold or a throw names no device of ours, an IPv6 one dumping lo, so
	// only the table and the protocol identify it. Both are this reconciler's
	// own marker.
	if table != uint32(p.table.ID) || (kind == unix.RTN_UNICAST && oif != p.index) {
		return Route{}, false
	}
	if !destination.IsValid() {
		destination = unspecified(family) // an absent RTA_DST is the default route
	}
	if destination.Is4() != (family == unix.AF_INET) {
		return Route{}, false
	}
	prefix, ok := canonicalPrefix(netip.PrefixFrom(destination, int(dstLen)))
	if !ok {
		return Route{}, false
	}
	decoded := Route{
		Destination: prefix, Metric: metric,
		Unreachable: kind == unix.RTN_UNREACHABLE, Throw: kind == unix.RTN_THROW,
	}
	if srcLen > 0 {
		if !source.IsValid() {
			return Route{}, false
		}
		if decoded.Source, ok = canonicalPrefix(netip.PrefixFrom(source, int(srcLen))); !ok {
			return Route{}, false
		}
	}
	return decoded, true
}

// routeMessage encodes one RTM_NEWROUTE or RTM_DELROUTE body. A delete carries
// rtm_protocol deliberately: the kernel then matches on it, so even a bug in
// the diff cannot remove a route belonging to another protocol.
func (p *netlinkPlatform) routeMessage(route Route, del bool) []byte {
	family, scope := uint8(unix.AF_INET6), uint8(unix.RT_SCOPE_UNIVERSE)
	if route.Destination.Addr().Is4() {
		// an IPv4 route out of a device with no gateway is link scope, which
		// iproute2 sends and fib_check_nh expects.
		family, scope = unix.AF_INET, unix.RT_SCOPE_LINK
	}
	kind := uint8(unix.RTN_UNICAST)
	if route.Unreachable {
		// A hold, not a path. It has no output interface and no scope of its
		// own: fib_check_nh is not consulted for a route that resolves to an
		// error, and naming a device would make the kernel reject it.
		kind, scope = unix.RTN_UNREACHABLE, unix.RT_SCOPE_UNIVERSE
	}
	if route.Throw {
		// as a hold, a route with no device
		kind, scope = unix.RTN_THROW, unix.RT_SCOPE_UNIVERSE
	}
	if del {
		// RT_SCOPE_NOWHERE and RTN_UNSPEC are the kernel's wildcards in a
		// delete match, the way "ip route del" leaves them.
		scope, kind = unix.RT_SCOPE_NOWHERE, unix.RTN_UNSPEC
	}
	srcLen := 0
	if route.Source.IsValid() {
		srcLen = route.Source.Bits()
	}
	table := uint8(unix.RT_TABLE_UNSPEC)
	if uint32(p.table.ID) <= 255 {
		table = uint8(p.table.ID)
	}

	body := make([]byte, unix.SizeofRtMsg)
	body[0] = family
	body[1] = uint8(route.Destination.Bits())
	body[2] = uint8(srcLen)
	body[4] = table
	body[5] = p.table.Proto
	body[6] = scope
	body[7] = kind
	body = putAttrU32(body, unix.RTA_TABLE, uint32(p.table.ID))
	if route.Destination.Bits() > 0 {
		body = putAttr(body, unix.RTA_DST, addressBytes(route.Destination.Addr()))
	}
	if srcLen > 0 {
		body = putAttr(body, unix.RTA_SRC, addressBytes(route.Source.Addr()))
	}
	if !route.Unreachable && !route.Throw {
		body = putAttrU32(body, unix.RTA_OIF, p.index)
	}
	// the metric is always explicit: leaving it out would let the kernel pick
	// its own, and a delete has to name the same one to match the route.
	body = putAttrU32(body, unix.RTA_PRIORITY, route.Metric)
	return body
}

// where is the routing table this reconciler owns and the protocol it stamps,
// which together with the interface make a route on linux its own.
func (p *netlinkPlatform) where(t Table) string {
	return fmt.Sprintf("table %d protocol %d", uint32(t.ID), t.Proto)
}

func (p *netlinkPlatform) retable(t Table) { p.table = t }

func (p *netlinkPlatform) AddRoute(route Route) error {
	// EXCL rather than REPLACE. A replace takes over whatever sits first at the
	// same prefix, tos and priority no matter who wrote it: fib_table_insert
	// compares neither rtm_protocol nor the route type. Replacing another
	// writer's route would take it from that writer, and withdraw would not put
	// it back, because DelRoute matches on our protocol.
	//
	// Refusing instead costs an update that changes only a non-key attribute,
	// the type at an unchanged metric. applyRoutes withdraws before it installs
	// so that case arrives here as a plain add.
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	_, err := p.conn.execute(unix.RTM_NEWROUTE, flags, p.routeMessage(route, false))
	if errors.Is(err, unix.EEXIST) {
		// Keyed by the route rather than by its printed form, which omits the
		// scope: two routes differing only there would otherwise share one
		// record.
		p.refused[route] = true
		if !p.occupied[route] {
			p.occupied[route] = true
			slog.Warn("kernel is leaving a route that another writer holds",
				"route", route, "table", uint32(p.table.ID),
				"detail", "something else holds this prefix at this metric in this table, so it was not installed")
		}
		// Not a failure and not an install. Reported as an error it would put
		// the whole pass into backoff over a key no retry can free, once per
		// pass, forever.
		return errRouteSkipped
	}
	if err == nil {
		delete(p.occupied, route)
	}
	return err
}

func (p *netlinkPlatform) DelRoute(route Route) error {
	_, err := p.conn.execute(unix.RTM_DELROUTE, unix.NLM_F_ACK, p.routeMessage(route, true))
	if gone(err) {
		err = nil
	}
	if err == nil {
		// A route that left the desired set takes its warn-once record with
		// it, or the map keeps an entry for a key nothing asks about again.
		delete(p.occupied, route)
	}
	return err
}

func (p *netlinkPlatform) Addrs() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		body := make([]byte, unix.SizeofIfAddrmsg)
		body[0] = family
		replies, err := p.conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, body)
		if err != nil {
			return nil, err
		}
		for _, reply := range replies {
			if prefix, ok := p.decodeAddr(reply); ok {
				out = append(out, prefix)
			}
		}
	}
	return out, nil
}

func (p *netlinkPlatform) decodeAddr(message nlMessage) (netip.Prefix, bool) {
	if message.Kind != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
		return netip.Prefix{}, false
	}
	prefixLen := message.Data[1]
	if binary.NativeEndian.Uint32(message.Data[4:]) != p.index {
		return netip.Prefix{}, false
	}
	var local, address netip.Addr
	for attr, value := range message.attributes(unix.SizeofIfAddrmsg) {
		switch attr {
		case unix.IFA_LOCAL:
			local, _ = addressFromBytes(value)
		case unix.IFA_ADDRESS:
			address, _ = addressFromBytes(value)
		}
	}
	// IFA_LOCAL is the address on this end, while IFA_ADDRESS is the peer's on a
	// point-to-point link, and the same value everywhere else.
	if !local.IsValid() {
		local = address
	}
	if !local.IsValid() {
		return netip.Prefix{}, false
	}
	prefix := netip.PrefixFrom(local, int(prefixLen))
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func (p *netlinkPlatform) addrMessage(prefix netip.Prefix) []byte {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET6
	if prefix.Addr().Is4() {
		body[0] = unix.AF_INET
	}
	body[1] = uint8(prefix.Bits())
	body[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(body[4:], p.index)
	raw := addressBytes(prefix.Addr())
	// with no peer address the two attributes carry the same value, which is
	// what "ip addr add" sends. IPv4 reads IFA_LOCAL and IPv6 IFA_ADDRESS.
	body = putAttr(body, unix.IFA_LOCAL, raw)
	body = putAttr(body, unix.IFA_ADDRESS, raw)
	return body
}

func (p *netlinkPlatform) AddAddr(prefix netip.Prefix) error {
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_REPLACE | unix.NLM_F_ACK)
	_, err := p.conn.execute(unix.RTM_NEWADDR, flags, p.addrMessage(prefix))
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (p *netlinkPlatform) DelAddr(prefix netip.Prefix) error {
	_, err := p.conn.execute(unix.RTM_DELADDR, unix.NLM_F_ACK, p.addrMessage(prefix))
	if gone(err) {
		return nil
	}
	return err
}

// keysByLength holds for IPv4, whose entry linux matches by address and mask, and not for IPv6, whose it matches by address alone
func (p *netlinkPlatform) keysByLength(address netip.Addr) bool { return address.Is4() }

// promoteSecondaries has linux promote the next address of a subnet when its primary comes off the tun
// with it off the secondaries go with the primary, and a renumber within the subnet leaves the tun without IPv4
// a tun without IPv4 loses every IPv4 route through it, another writer's among them
func promoteSecondaries(conn netlinkConn, index uint32) error {
	conf := putAttrU32(nil, ipv4DevconfPromoteSecondaries, 1)
	// kernels that validate the devconf attributes against a policy parse IFLA_INET_CONF strictly
	// and refuse it with EINVAL unless it carries NLA_F_NESTED
	inet := putAttr(nil, unix.AF_INET, putAttr(nil, unix.IFLA_INET_CONF|unix.NLA_F_NESTED, conf))
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	body = putAttr(body, unix.IFLA_AF_SPEC, inet)
	_, err := conn.execute(unix.RTM_NEWLINK, unix.NLM_F_ACK, body)
	return err
}

// routeMonitor turns unsolicited route notifications into one coalesced
// wake-up. It parses just enough of each message to drop notifications for
// tables the reconciler does not own, which stops another daemon's
// route churn from waking it. Its own writes still wake it once, but the settle
// window in Run absorbs the burst and the following pass finds nothing to do.
// it wakes as well on a deleted rule carrying proto
// systemd-networkd removes every rule it did not ask for when it configures a link
// the network watch reads its own groups through the same type
type routeMonitor struct {
	file    *os.File
	wakesOn func(nlMessage) bool
	signal  chan struct{}
	done    chan struct{}
}

func newRouteMonitor(table uint32, proto uint8, tun uint32) (*routeMonitor, error) {
	return openMonitor("rtnetlink-monitor", reconcilerGroups, reconcilerWakes(table, proto, tun))
}

// reconcilerGroups is the notification groups the reconciler's monitor joins
// the IPv6 rule group has no RTMGRP_ name, its bit is its group number less one
const reconcilerGroups = uint32(unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_IPV4_RULE | 1<<(unix.RTNLGRP_IPV6_RULE-1) |
	unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR)

// openMonitor joins groups and wakes once per datagram holding a message wakesOn takes
func openMonitor(name string, groups uint32, wakesOn func(nlMessage) bool) (*routeMonitor, error) {
	fd, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("kernel: open %s socket: %w", name, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: join the notification groups of %s: %w", name, err)
	}
	// a large receive buffer keeps a route flood from costing an ENOBUFS,
	// which is survivable but forces a full resync.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, monitorReceiveBuffer)
	// the socket is nonblocking, so os.NewFile registers it with the runtime
	// poller and Close unblocks the reader without racing on the descriptor.
	monitor := &routeMonitor{
		file:    os.NewFile(uintptr(fd), name),
		wakesOn: wakesOn,
		signal:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go monitor.run()
	return monitor, nil
}

func (m *routeMonitor) run() {
	defer close(m.done)
	buf := make([]byte, monitorReadSize)
	for {
		n, err := m.file.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			// ENOBUFS means notifications were dropped, which is exactly when
			// a reconcile is most needed. Anything else is unexpected and
			// would spin, so it is reported and the monitor stops. The
			// periodic sweep in Run remains as the backstop.
			m.wake()
			if errors.Is(err, unix.ENOBUFS) {
				slog.Debug("kernel notifications dropped, resyncing", "socket", m.file.Name())
				continue
			}
			slog.Warn("kernel notifications stopped", "socket", m.file.Name(), "err", err)
			return
		}
		messages, err := parseMessages(buf[:n])
		if err != nil {
			m.wake() // a notification we could not parse still means something changed
			continue
		}
		if slices.ContainsFunc(messages, m.wakesOn) {
			m.wake()
		}
	}
}

// reconcilerWakes takes a notification touching what the reconciler owns
// a rule is woken on only when it goes, since the pass that follows puts it back
// an address is woken on only where it is the tun's, whoever wrote it, since mode 2's rules follow the tun's overlay addresses
func reconcilerWakes(table uint32, proto uint8, tun uint32) func(nlMessage) bool {
	return func(message nlMessage) bool {
		switch message.Kind {
		case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
			return notificationTable(message) == table
		case unix.RTM_DELRULE:
			return ruleProtocol(message) == proto
		case unix.RTM_NEWADDR, unix.RTM_DELADDR:
			return len(message.Data) >= unix.SizeofIfAddrmsg && binary.NativeEndian.Uint32(message.Data[4:]) == tun
		}
		return false
	}
}

// ruleProtocol is the FRA_PROTOCOL one rule notification carries, 0 where it carries none
func ruleProtocol(message nlMessage) uint8 {
	if len(message.Data) < sizeofFibRuleHdr {
		return 0
	}
	for attr, value := range message.attributes(sizeofFibRuleHdr) {
		if attr == unix.FRA_PROTOCOL && len(value) == 1 {
			return value[0]
		}
	}
	return 0
}

// wake never blocks: a reader that misses one coalesced signal sees the change
// on the next one, or on the periodic sweep.
func (m *routeMonitor) wake() {
	select {
	case m.signal <- struct{}{}:
	default:
	}
}

func (m *routeMonitor) Close() error {
	err := m.file.Close()
	<-m.done
	return err
}

func notificationTable(message nlMessage) uint32 {
	if len(message.Data) < unix.SizeofRtMsg {
		return 0
	}
	table := uint32(message.Data[4])
	for attr, value := range message.attributes(unix.SizeofRtMsg) {
		if attr == unix.RTA_TABLE && len(value) == 4 {
			return binary.NativeEndian.Uint32(value)
		}
	}
	return table
}

// foreignWriters names the routing protocols other than this reconciler's that
// already have unicast routes in the table it is about to take over.
//
// It exists because an install asks for the route exclusively and reports a key
// another writer already holds rather than taking it over, so a second writer
// in one table means routes the mesh wanted are silently not installed.
// Everything else on a host keeps to its own table: Tailscale
// uses 52, and BIRD on a ranet fleet node uses 200, which is exactly the table
// this reconciler is pointed at during a migration. Reporting it is the
// difference between a migration that looks fine and one that is visibly
// sharing a table.
func (p *netlinkPlatform) foreignWriters() ([]string, error) {
	seen := map[uint8]bool{}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		replies, err := p.dumpTable(family, 0)
		if err != nil {
			return nil, err
		}
		collectForeignWriters(replies, uint32(p.table.ID), p.table.Proto, seen)
	}
	// Labeled here rather than by the caller, because rt_proto is a linux
	// registry and kernel.go is the portable half. Returning the numbers bare
	// also renders them unreadably: slog's text handler quotes a []uint8 as a
	// byte string, so protocols 2 and 12 reach an operator as "\x02\f".
	labels := make([]string, 0, len(seen))
	for _, protocol := range slices.Sorted(maps.Keys(seen)) {
		labels = append(labels, protocolLabel(protocol))
	}
	return labels, nil
}

// protocolLabel names a routing protocol the way iproute2 prints it, from the
// rt_protos registry, and falls back to the bare number for one nothing has
// claimed. The one a fleet node meets in table 200 is bird, during a
// migration. The kernel's own entries appear there only when a VRF is bound to
// that table.
func protocolLabel(protocol uint8) string {
	var name string
	switch protocol {
	case unix.RTPROT_REDIRECT:
		name = "redirect"
	case unix.RTPROT_KERNEL:
		name = "kernel"
	case unix.RTPROT_BOOT:
		name = "boot"
	case unix.RTPROT_STATIC:
		name = "static"
	case unix.RTPROT_RA:
		name = "ra"
	case unix.RTPROT_ZEBRA:
		name = "zebra"
	case unix.RTPROT_BIRD:
		name = "bird"
	case unix.RTPROT_DHCP:
		name = "dhcp"
	case unix.RTPROT_KEEPALIVED:
		name = "keepalived"
	case unix.RTPROT_BABEL:
		name = "babel"
	case unix.RTPROT_OPENR:
		name = "openr"
	case unix.RTPROT_BGP:
		name = "bgp"
	case unix.RTPROT_ISIS:
		name = "isis"
	case unix.RTPROT_OSPF:
		name = "ospf"
	case unix.RTPROT_RIP:
		name = "rip"
	case unix.RTPROT_EIGRP:
		name = "eigrp"
	default:
		return strconv.Itoa(int(protocol))
	}
	return name + " (" + strconv.Itoa(int(protocol)) + ")"
}

// collectForeignWriters is the filter half of foreignWriters, split out so the
// rule can be tested without a netlink socket.
// replies hold the routes of table alone
// the kernel filtered the dump to it
func collectForeignWriters(replies []nlMessage, table uint32, ours uint8, seen map[uint8]bool) {
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWROUTE || len(reply.Data) < unix.SizeofRtMsg {
			continue
		}
		protocol, kind := reply.Data[5], reply.Data[7]
		if kind != unix.RTN_UNICAST || protocol == ours {
			continue
		}
		// RTPROT_KERNEL marks the kernel's own entries, and the main table
		// holds them by construction, as the plumbing for the machine's
		// addresses. Nothing is lost by leaving them out: an install asks for
		// its key exclusively and never takes one of these over, and a key it
		// is refused is reported on its own route. In any other table the same
		// entries mean a VRF is bound there.
		if protocol == unix.RTPROT_KERNEL && table == unix.RT_TABLE_MAIN {
			continue
		}
		seen[protocol] = true
	}
}
