// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

// RouteGetBatch answers each read as RouteGet does, through one rtnetlink
// socket rather than one a read. A read's failure is its own answer, and the
// batch fails whole only when the socket or an arrival device's lookup does, or
// a lookup naming a device by its index fails otherwise than with ENODEV, which
// leaves that device unnamed. Each device is named by a keyed
// RTM_GETLINK, which a change to the links never interrupts as it does a dump
func RouteGetBatch(reads []RouteRead) ([]BatchAnswer, error) {
	conn, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return routeGetBatch(conn, reads)
}

// routeGetBatch is RouteGetBatch on a socket the caller holds
func routeGetBatch(conn netlinkConn, reads []RouteRead) ([]BatchAnswer, error) {
	arrivals := make(map[string]uint32)
	for _, read := range reads {
		if _, ok := arrivals[read.IIF]; ok || read.IIF == "" {
			continue
		}
		link, err := conn.link(0, read.IIF)
		if err != nil {
			return nil, fmt.Errorf("kernel: look up interface %s: %w", read.IIF, err)
		}
		arrivals[read.IIF] = link.index
	}
	names := make(map[uint32]string)
	missing := make(map[uint32]bool)
	nameIndexes := func(indexes ...uint32) error {
		for _, index := range indexes {
			if _, held := names[index]; held || index == 0 || missing[index] {
				continue
			}
			link, err := conn.link(index, "")
			switch {
			case errors.Is(err, unix.ENODEV):
				missing[index] = true
			case err != nil:
				return fmt.Errorf("kernel: name interface %d: %w", index, err)
			default:
				names[index] = link.name
			}
		}
		return nil
	}
	for _, read := range reads {
		if err := nameIndexes(read.OIF); err != nil {
			return nil, err
		}
	}
	answers := make([]BatchAnswer, len(reads))
	unnamed := make([]batchIndexes, len(reads))
	for i, read := range reads {
		answer, indexes := &answers[i], &unnamed[i]
		// a read naming an interface no device holds answers ENODEV with no
		// request, but an IPv6 pair's, which is asked (ip6_datagram_send_ctl,
		// ip_route_output_key_hash_rcu, udpv6_sendmsg)
		if name, held := names[read.OIF]; read.OIF == 0 || held || read.Pair && read.Destination.Is6() {
			answer.OIF = name
			answer.Route, indexes.route, answer.Err = batchRead(conn, read.Source, read.Destination, arrivals[read.IIF], read.OIF, read.Mark)
		} else {
			answer.Err = fmt.Errorf("kernel: look up the route to %s out of interface %d: %w", read.Destination, read.OIF, unix.ENODEV)
		}
		if !read.Reply {
			continue
		}
		live := slices.IndexFunc(answer.Route.NextHops, func(hop NextHop) bool { return !hop.Dead && !hop.LinkDown })
		switch {
		case answer.Err != nil:
			answer.ReplyErr = replyUnread(read)
		case live < 0:
			answer.ReplyErr = fmt.Errorf("kernel: no reply lookup from %s to %s: the route to %s has no live next hop", read.Destination, read.Source, read.Destination)
		default:
			indexes.arrival = indexes.route[live]
			answer.Reply, indexes.reply, answer.ReplyErr = batchRead(conn, read.Destination, read.Source, indexes.arrival, 0, 0)
		}
	}
	// an interface no device held at its read may be a device made since, so a
	// hop naming it is asked again
	clear(missing)
	for _, indexes := range unnamed {
		if err := nameIndexes(indexes.route...); err != nil {
			return nil, err
		}
		if err := nameIndexes(indexes.reply...); err != nil {
			return nil, err
		}
	}
	for i, read := range reads {
		answer, indexes := &answers[i], unnamed[i]
		if answer.Err == nil {
			answer.Route, answer.Err = nameHops(answer.Route, indexes.route, names)
		}
		switch {
		case indexes.arrival == 0:
		case answer.Err != nil:
			// a device of the forward route is gone since its lookup, and the
			// reply read's arrival may be that one
			answer.Reply, answer.ReplyErr = MatchedRoute{}, replyUnread(read)
		default:
			answer.ReplyIIF = names[indexes.arrival]
			if answer.ReplyErr == nil {
				answer.Reply, answer.ReplyErr = nameHops(answer.Reply, indexes.reply, names)
			}
		}
	}
	return answers, nil
}

// batchIndexes holds one read's next hop indexes until the batch names them, and
// the index its reply read arrived on, 0 where none was made
type batchIndexes struct {
	route, reply []uint32
	arrival      uint32
}

func batchRead(c netlinkConn, src, dst netip.Addr, arrival, leaving, mark uint32) (MatchedRoute, []uint32, error) {
	if err := refuseRouteLookup(src, dst); err != nil {
		return MatchedRoute{}, nil, err
	}
	return matchedRoute(c, src, dst, arrival, leaving, mark)
}

func replyUnread(read RouteRead) error {
	return fmt.Errorf("kernel: no reply lookup from %s to %s: the forward lookup failed", read.Destination, read.Source)
}

// nameHops names each next hop of route from names, indexes holding their
// interface indexes in order. An index that names lacks is a device gone since
// its lookup, and answers ENODEV as RouteGet's naming of it would
func nameHops(route MatchedRoute, indexes []uint32, names map[uint32]string) (MatchedRoute, error) {
	for i, index := range indexes {
		name, ok := names[index]
		if !ok {
			return MatchedRoute{}, fmt.Errorf("kernel: name interface %d: %w", index, unix.ENODEV)
		}
		route.NextHops[i].Device = name
	}
	return route, nil
}
