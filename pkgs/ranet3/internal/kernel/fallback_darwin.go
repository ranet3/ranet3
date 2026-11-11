// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

var (
	_ switcher    = (*routePlatform)(nil)
	_ holdKeyer   = (*routePlatform)(nil)
	_ ownRewriter = (*routePlatform)(nil)
	_ fibLooker   = (*routePlatform)(nil)
)

// rejectsForm is the rejects on lo0 as a log line and a status read them. See
// routePlatform's "The kill switch".
var rejectsForm = fallbackForm{
	where:     "rejects on " + Loopback,
	fix:       `start ranet3 with cap.exit fallback = "uplink", which deletes them, or delete each with route -n delete`,
	unheld:    "the host's unbound traffic leaves by the host's own routes at each key no reject holds",
	keys:      rejectKeys,
	uncounted: true,
}

func (p *routePlatform) form() fallbackForm { return rejectsForm }

// loopFlags are the flags of a route in the rejects' shape, and loopApart the
// flags it never carries
const (
	loopFlags = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_REJECT | unix.RTF_GATEWAY
	loopApart = unix.RTF_IFSCOPE | unix.RTF_HOST | unix.RTF_WASCLONED | unix.RTF_LLINFO | unix.RTF_BLACKHOLE
)

// loopGateway is the next hop of a route in the rejects' shape, the loopback
// address of its family, through which the kernel takes lo0
func loopGateway(destination netip.Prefix) netip.Addr {
	if destination.Addr().Is4() {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

// loopMessage encodes the RTM_ADD or RTM_DELETE of a route in the rejects'
// shape at destination. It names no interface, which the kernel takes from
// the gateway.
func loopMessage(kind int, destination netip.Prefix) (*route.RouteMessage, error) {
	mask, ok := prefixMask(destination)
	if !ok {
		return nil, fmt.Errorf("%s has no netmask", destination)
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination.Addr())
	addrs[unix.RTAX_GATEWAY] = routeAddr(loopGateway(destination))
	addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	return &route.RouteMessage{Type: kind, Flags: loopFlags, Addrs: addrs}, nil
}

// loopShaped is the destination of one dumped route in the rejects' shape on
// the interface at loopback, false for a route of any other shape
func loopShaped(rm *route.RouteMessage, loopback int) (netip.Prefix, bool) {
	if loopback == 0 || rm.Type != unix.RTM_GET || rm.Index != loopback {
		return netip.Prefix{}, false
	}
	destination, ok := dumpedPrefix(rm)
	return destination, ok && loopFlagged(rm, destination)
}

// loopFlagged reports one route message at destination carrying the rejects'
// flags and gateway, which put it on lo0
func loopFlagged(rm *route.RouteMessage, destination netip.Prefix) bool {
	if rm.Flags&loopFlags != loopFlags || rm.Flags&loopApart != 0 || len(rm.Addrs) <= unix.RTAX_GATEWAY {
		return false
	}
	gateway, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_GATEWAY])
	return ok && gateway == loopGateway(destination)
}

// readLoop records in loops the unscoped route one dumped message holds at a
// key of the switch's, where it holds one. A scoped route is keyed apart from
// a reject and meets none.
func (p *routePlatform) readLoop(message route.Message) {
	rm, ok := message.(*route.RouteMessage)
	if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_UP == 0 || rm.Flags&(unix.RTF_IFSCOPE|unix.RTF_WASCLONED) != 0 {
		return
	}
	destination, ok := dumpedPrefix(rm)
	if !ok || !slices.Contains(rejectKeys, destination) {
		return
	}
	var gateway netip.Addr
	if len(rm.Addrs) > unix.RTAX_GATEWAY {
		gateway, _ = addressFromRouteAddr(rm.Addrs[unix.RTAX_GATEWAY])
	}
	kind := rowOther
	switch _, shaped := loopShaped(rm, p.loopback); {
	case shaped:
		kind = rowShaped
	case rm.Index == p.loopback:
		kind = rowLoopback
	case rm.Index == p.index:
		kind = rowTun
	}
	p.loops.record(destination, kind, func() string { return p.describe(destination, gateway, rm.Index) })
}

// errNoLoopDump is a read of the switch in a pass whose dump failed
var errNoLoopDump = errors.New("kernel: no dump of this pass to read the rejects from")

// readFallback reads the rejects from the pass's dump, as its writes left them
func (p *routePlatform) readFallback(fallbackSets) (fallbackRead, error) {
	if p.loops == nil {
		return fallbackRead{}, errNoLoopDump
	}
	return fallbackRead{fault: p.loops.fault(rejectsForm.keys)}, nil
}

// writeFallback adds each reject the pass's dump did not find, a key another
// route holds refusing it with EEXIST
func (p *routePlatform) writeFallback(fallbackSets, bool) error {
	if p.loops == nil {
		return errNoLoopDump
	}
	return p.loops.write(rejectsForm.keys, func(key netip.Prefix) error {
		message, err := loopMessage(unix.RTM_ADD, key)
		if err != nil {
			return err
		}
		err = p.sock.WriteRoute(message)
		if errors.Is(err, unix.EEXIST) {
			return errKeyTaken
		}
		return err
	}, p.holder)
}

// deleteFallback deletes every reject of the switch's shape a dump of its own
// finds, since the pass that runs it has not dumped yet
func (p *routePlatform) deleteFallback() error {
	p.loops = nil
	return deleteLoops(p.host, p.sock, p.loopback, rejectKeys)
}

func (p *routePlatform) holdsFallback() (bool, error) {
	held, err := loopRows(p.host, p.loopback)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(rejectKeys, func(key netip.Prefix) bool { return held[key] }), nil
}

// loopRows is each key a dump of host holds a route in the rejects' shape at
// on the interface at loopback
func loopRows(host Host, loopback int) (map[netip.Prefix]bool, error) {
	rib, err := host.Dump()
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the routing table: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("kernel: parse the route dump: %w", err)
	}
	held := make(map[netip.Prefix]bool)
	for _, message := range messages {
		if rm, ok := message.(*route.RouteMessage); ok {
			if destination, ok := loopShaped(rm, loopback); ok {
				held[destination] = true
			}
		}
	}
	return held, nil
}

// deleteLoops deletes each route in the rejects' shape on the interface at
// loopback at one of keys that a dump of host finds, whoever wrote it, and
// leaves a route of any other shape. The dump comes first, since RTM_DELETE
// finds a route by its key alone, whatever its gateway (rtrequest_common_locked
// in bsd/net/route.c).
func deleteLoops(host Host, sock rtSocket, loopback int, keys []netip.Prefix) error {
	held, err := loopRows(host, loopback)
	if err != nil {
		return err
	}
	var errs []error
	for _, key := range keys {
		if !held[key] {
			continue
		}
		message, err := loopMessage(unix.RTM_DELETE, key)
		if err == nil {
			err = sock.WriteRoute(message)
		}
		if err != nil && !gone(err) {
			errs = append(errs, fmt.Errorf("delete the reject at %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// DeleteFallback deletes the rejects an earlier instance left, and its holds
// at the keys of overlay, for a start that runs no reconciler to delete them
func DeleteFallback(overlay []schema.Prefix) {
	if err := deleteRejects(runningKernel{}, slices.Concat(rejectKeys, overlayKeys(overlay))); err != nil {
		warnFallbackLeft(rejectsForm, err)
	}
}

// deleteRejects deletes the routes of the rejects' shape on host's lo0 at keys
func deleteRejects(host Host, keys []netip.Prefix) error {
	loopback, err := host.InterfaceIndex(Loopback)
	if err != nil {
		return err
	}
	sock, err := routeSocket(host)
	if err != nil {
		return err
	}
	defer sock.Close()
	return deleteLoops(host, sock, loopback, keys)
}

// ResolvedLinkServers has no systemd-resolved to ask here
func ResolvedLinkServers() ([]LinkResolver, error) { return nil, nil }

// ReadFallback reads the rejects for debug rules
func ReadFallback() (FallbackDebug, error) {
	return readRejects(runningKernel{})
}

func readRejects(host Host) (FallbackDebug, error) {
	out := FallbackDebug{Where: rejectsForm.where}
	loopback, err := host.InterfaceIndex(Loopback)
	if err != nil {
		return out, err
	}
	held, err := loopRows(host, loopback)
	if err != nil {
		return out, err
	}
	for _, key := range rejectKeys {
		if held[key] {
			out.Rules = append(out.Rules, FallbackDebugRule{Spec: fmt.Sprintf("%s via %s reject", key, loopGateway(key))})
		}
	}
	out.Held = len(out.Rules) > 0
	return out, nil
}
