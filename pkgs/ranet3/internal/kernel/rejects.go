// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
)

// rejectRows is the unscoped route at each key of a switch written as reject
// routes, as one pass's dump read it and its writes left it: empty for a
// reject of the switch's shape, the fault a read names for any other route,
// absent where none is held. A scoped route is keyed apart and meets no
// reject, so it has no row.
type rejectRows map[netip.Prefix]string

// errKeyTaken is an add the kernel refused since another route holds its key
var errKeyTaken = errors.New("kernel: another route holds the key")

// rowKind is where the unscoped route a dump found at a key of the switch's
// sits: in the rejects' shape, which is the switch's whoever wrote it, on the
// loopback link in another shape, out of the tun, or out of another interface
type rowKind int

const (
	rowShaped rowKind = iota
	rowLoopback
	rowTun
	rowOther
)

// record notes the unscoped route a dump found at key, of kind, and names any
// but the switch's as the fault, which describe, called for a fault alone,
// names the route in
func (rows rejectRows) record(key netip.Prefix, kind rowKind, describe func() string) {
	switch kind {
	case rowShaped:
		rows[key] = ""
	case rowLoopback:
		rows[key] = fmt.Sprintf("the route %s is no reject of the switch's shape", describe())
	case rowTun:
		rows[key] = fmt.Sprintf("this node's own route %s holds a key of the switch's until it goes in as its halves", describe())
	default:
		rows[key] = fmt.Sprintf("another program's route %s holds a key of the switch's", describe())
	}
}

// fault names the first of keys whose reject is missing or whose key another
// route holds, empty where the switch's reject holds each
func (rows rejectRows) fault(keys []netip.Prefix) string {
	for _, key := range keys {
		held, ok := rows[key]
		if !ok {
			return fmt.Sprintf("the reject at %s is missing", key)
		}
		if held != "" {
			return held
		}
	}
	return ""
}

// write adds through add each reject of keys rows does not hold as the
// switch's. add answers errKeyTaken for a key another route holds, which
// stays that route's, never taken over, and holder names it where the dump
// did not.
func (rows rejectRows) write(keys []netip.Prefix, add func(netip.Prefix) error, holder func(netip.Prefix) string) error {
	var errs []error
	for _, key := range keys {
		held, ok := rows[key]
		if ok && held == "" {
			continue
		}
		switch err := add(key); {
		case errors.Is(err, errKeyTaken):
			if !ok {
				rows.record(key, rowOther, func() string { return holder(key) })
			}
		case err != nil:
			errs = append(errs, fmt.Errorf("add the reject at %s: %w", key, err))
		default:
			rows[key] = ""
		}
	}
	return errors.Join(errs...)
}
