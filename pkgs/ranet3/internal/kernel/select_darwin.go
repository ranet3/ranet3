// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Selection answers which interface an underlay datagram names: the one
// the host's own routes send it by with ranet3's interface left out, which is
// where a lookup carrying linux's underlay mark ends. It reads one dump of the
// routing table into a snapshot, and reads it again once the routing messages
// of its own watcher settle.
type Selection struct {
	host Host
	mesh int
	// watcher reports every routing change but those on ranet3's own interface and this process's refused writes
	// a route this process writes on another interface is a route of the host the selection reads
	watcher Watcher
	// current is replaced whole by follow and loaded by every answer without a lock
	current   atomic.Pointer[selectionSnapshot]
	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

// selectionSnapshot is the candidate routes of one dump, never written once published, and the generation that names it
type selectionSnapshot struct {
	generation uint64
	routes     []hostRoute
}

// OpenSelection reads the host's routing table with mesh, ranet3's own interface, left out, and follows it until Close
// mesh is empty on a node without one, which leaves no interface out
// host is the machine it reads, nil for the one this process runs on
// a table it cannot read refuses the start, since a host that cannot read its table cannot run its reconciler either
func OpenSelection(host Host, mesh string) (*Selection, error) {
	host = hostOr(host)
	index := 0
	if mesh != "" {
		var err error
		if index, err = host.InterfaceIndex(mesh); err != nil {
			return nil, err
		}
	}
	// opened before the first dump, so a change between the two is read again
	watcher, err := host.Watch(0, index, false)
	if err != nil {
		return nil, err
	}
	s := &Selection{host: host, mesh: index, watcher: watcher, done: make(chan struct{}), stopped: make(chan struct{})}
	if err := s.read(); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	go s.follow()
	return s, nil
}

// Interface is the index of the interface a datagram to addr names, zero where no route holds it,
// and the generation of the snapshot that answer comes from
func (s *Selection) Interface(addr netip.Addr) (int, uint64) {
	snapshot := s.current.Load()
	r, ok := selectRoute(snapshot.routes, s.mesh, addr, s.zoneIndex(addr.Zone()))
	if !ok {
		return 0, snapshot.generation
	}
	return r.index, snapshot.generation
}

// Generation names the snapshot the answers come from, and moves on when a dump finds the candidate routes changed
func (s *Selection) Generation() uint64 { return s.current.Load().generation }

// Route is the route Interface answers addr from and the name of its interface, or the index where the host names none
// a link-local destination's zone answers with its interface and no route, and false is no route at all
func (s *Selection) Route(addr netip.Addr) (netip.Prefix, string, bool) {
	r, ok := selectRoute(s.current.Load().routes, s.mesh, addr, s.zoneIndex(addr.Zone()))
	if !ok {
		return netip.Prefix{}, "", false
	}
	name, err := s.host.InterfaceName(r.index)
	if err != nil {
		name = strconv.Itoa(r.index)
	}
	return r.destination, name, true
}

// zoneIndex is the interface a zone names, by index or by name, zero for none or one the host does not have
func (s *Selection) zoneIndex(zone string) int {
	if zone == "" {
		return 0
	}
	if index, err := strconv.Atoi(zone); err == nil {
		return index
	}
	index, err := s.host.InterfaceIndex(zone)
	if err != nil {
		return 0
	}
	return index
}

// read publishes the candidate routes of one dump, under the next generation where they changed
func (s *Selection) read() error {
	rib, err := s.host.Dump()
	if err != nil {
		return fmt.Errorf("kernel: dump the routing table for the underlay: %w", err)
	}
	routes, err := hostRoutes(rib)
	if err != nil {
		return fmt.Errorf("kernel: parse the routing table for the underlay: %w", err)
	}
	routes = slices.DeleteFunc(routes, func(r hostRoute) bool { return !r.candidate(s.mesh) })
	last := s.current.Load()
	if last == nil {
		s.current.Store(&selectionSnapshot{generation: 1, routes: routes})
		return nil
	}
	if !slices.Equal(last.routes, routes) {
		s.current.Store(&selectionSnapshot{generation: last.generation + 1, routes: routes})
	}
	return nil
}

// follow reads the table again after each settled run of changes until Close
// a dump that fails keeps the last snapshot, and says so once until one works
func (s *Selection) follow() {
	defer close(s.stopped)
	failing := false
	for s.settled() {
		err := s.read()
		switch {
		case err != nil && !failing:
			slog.Warn("kernel keeps the underlay's last selection, since it could not read the routing table", "err", err)
		case err == nil && failing:
			slog.Info("kernel reads the routing table for the underlay's selection again")
		}
		failing = err != nil
	}
}

// settled waits for a change and then for selectionSettle, and reports whether the selection is still open
func (s *Selection) settled() bool {
	changed := s.watcher.Changed()
	select {
	case <-s.done:
		return false
	case <-changed:
	}
	return settle(changed, s.done, selectionSettle)
}

// Close stops following the table and closes the watcher
func (s *Selection) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		<-s.stopped
		err = s.watcher.Close()
	})
	return err
}

// hostRoutes decodes every route of a dump that is up and names an address
func hostRoutes(rib []byte) ([]hostRoute, error) {
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var out []hostRoute
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_UP == 0 {
			continue
		}
		destination, ok := dumpedPrefix(rm)
		if !ok {
			continue
		}
		out = append(out, hostRoute{
			destination: destination,
			index:       rm.Index,
			scoped:      rm.Flags&unix.RTF_IFSCOPE != 0,
			cloned:      rm.Flags&unix.RTF_WASCLONED != 0,
			multicast:   rm.Flags&unix.RTF_MULTICAST != 0,
			broadcast:   rm.Flags&unix.RTF_BROADCAST != 0,
		})
	}
	return out, nil
}

// dumpedPrefix is the destination one dumped route names, masked the way a
// Route key is.
func dumpedPrefix(rm *route.RouteMessage) (netip.Prefix, bool) {
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return netip.Prefix{}, false
	}
	destination, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST])
	if !ok {
		return netip.Prefix{}, false
	}
	bits := destination.BitLen()
	if rm.Flags&unix.RTF_HOST == 0 {
		mask, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_NETMASK])
		if !ok || mask.BitLen() != destination.BitLen() {
			return netip.Prefix{}, false
		}
		if bits, ok = maskBits(mask); !ok {
			return netip.Prefix{}, false
		}
	}
	return canonicalPrefix(netip.PrefixFrom(destination, bits))
}
