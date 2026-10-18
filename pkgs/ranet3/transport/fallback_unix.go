// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// unpinnable reports whether err is the kernel refusing a pinned source address or interface that a send without the pin may get past
// a source the host no longer holds draws EADDRNOTAVAIL, and a source whose interface holds no route to the peer EHOSTUNREACH
func unpinnable(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL)
}

// pinFallback records whether sends to an endpoint left the pin it arrived with, and why
type pinFallback struct {
	// unpinned records a fallback that worked and is never cleared
	unpinned atomic.Bool
	// unroutedUntil is when unroutedHold ends after the kernel refused the pin for want of a route from it to the peer
	// it is nil before such a refusal, and set before unpinned
	unroutedUntil atomic.Pointer[time.Time]
}

// unpin records a fallback from the pin the kernel refused with refused, and reports whether it is the endpoint's first
func (f *pinFallback) unpin(refused error) bool {
	if errors.Is(refused, unix.EHOSTUNREACH) {
		f.unroutedUntil.Store(new(time.Now().Add(unroutedHold)))
	}
	return f.unpinned.CompareAndSwap(false, true)
}

// arrival is control while it tells the endpoint apart from others: before a fallback, and until unroutedUntil after one for want of a route
// a request that reaches a pin with no route to the peer within the hold is the same destination, whose sends would only fall back again
// one after the hold, or one that reaches an address the host lost and holds again, moves the session back onto the pin
func (f *pinFallback) arrival(control []byte) []byte {
	if f.unpinned.Load() {
		if until := f.unroutedUntil.Load(); until == nil || !time.Now().Before(*until) {
			return nil
		}
	}
	return control
}

// unpinned logs and records that sends to ep left the address its datagram arrived on, after the kernel refused it with err
func unpinned(events func(string, ...slog.Attr), ep Endpoint, err error) {
	fellBack(events, ep, "transport.endpoint.unpinned", "transport stopped sending to an endpoint from the address its datagram arrived on", err)
}

// fellBack logs and records a fallback a send to ep took after the kernel refused it with err
func fellBack(events func(string, ...slog.Attr), ep Endpoint, kind, message string, err error) {
	errno, _ := errors.AsType[unix.Errno](err)
	attrs := []slog.Attr{slog.String("endpoint", ep.String()), slog.String("errno", unix.ErrnoName(errno))}
	slog.LogAttrs(context.Background(), slog.LevelInfo, message, attrs...)
	if events != nil {
		events(kind, attrs...)
	}
}
