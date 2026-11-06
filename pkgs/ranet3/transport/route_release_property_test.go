// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// cachedRoute is the one route a socket caches as XNU keeps it: a write keeps it while its destination is the write's, whatever interface the write names,
// and otherwise takes the interface it names and caches that route, where a pin no interface holds is refused and caches none
// in_pcbladdr and ip_output in bsd/netinet, selectroute and in6_selectsrc in bsd/netinet6
type cachedRoute struct {
	held bool
	to   int
	by   int64
}

// write is the key of the interface a datagram to to naming key leaves by, false where the kernel refuses it
func (r *cachedRoute) write(to int, key int64) (int64, bool) {
	if r.held && r.to == to {
		return r.by, true
	}
	r.held = false
	if key == unheldPin {
		return 0, false
	}
	*r = cachedRoute{held: true, to: to, by: key}
	return key, true
}

// routeSend is one send of a case, run on a goroutine of its own that pauses wherever another send may step in:
// before its check, before and after each release, before its write and before its check after
type routeSend struct {
	to  int
	key int64
	// from and until are the positions of the schedule it began and ended at
	from, until int
	by          int64
	left        bool
	err         error
	resume      chan struct{}
	// paused carries false at each pause and true once the send ended
	paused chan bool
}

func (s *routeSend) pause() {
	s.paused <- false
	<-s.resume
}

// exact reports whether s's datagram left as one sent alone does: by its key's interface, and nowhere from a pin no interface holds
func (s *routeSend) exact() bool {
	if s.key == unheldPin {
		return !s.left
	}
	return s.left && s.by == s.key
}

// routeKeys are the keys a case draws from: two interfaces and a pin no interface holds
var routeKeys = []int64{1, 2, unheldPin}

// the shared socket's record against a model of the route the kernel caches, over two or three sends to two addresses interleaved as drawn at every pause:
// a datagram leaves by another interface than its send names, or leaves from a pin no interface holds, only while its send overlaps another send,
// and once every send has ended the next leaves by the interface it names
func TestDarwinSharedSocketRecordAgainstTheKernelsCachedRoute(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		route := &cachedRoute{}
		var running *routeSend
		bind := &darwinBind{dropRoute: func(*darwinSocket) error {
			running.pause()
			route.held = false
			running.pause()
			return nil
		}}
		socket := &darwinSocket{}
		position := 0
		// run runs sends to their ends, resuming one of those not ended at each step as drawn
		run := func(sends ...*routeSend) {
			for _, s := range sends {
				s.resume, s.paused = make(chan struct{}), make(chan bool)
				go func() {
					<-s.resume
					if s.err = bind.beforeWrite(socket, s.key); s.err == nil {
						s.pause()
						s.by, s.left = route.write(s.to, s.key)
						s.pause()
						s.err = bind.afterWrite(socket, s.key)
					}
					s.paused <- true
				}()
			}
			pending, started := slices.Clone(sends), make(map[*routeSend]bool)
			for ; len(pending) > 0; position++ {
				i := hegel.Draw(ht, pbt.Spanning(0, len(pending)-1))
				running = pending[i]
				if !started[running] {
					started[running], running.from = true, position
				}
				running.resume <- struct{}{}
				if <-running.paused {
					running.until = position
					pending = slices.Delete(pending, i, i+1)
				}
			}
		}
		draw := func() *routeSend {
			return &routeSend{to: hegel.Draw(ht, hegel.Integers(0, 1)), key: hegel.Draw(ht, hegel.SampledFrom(routeKeys))}
		}
		sends := []*routeSend{draw(), draw()}
		if hegel.Draw(ht, hegel.Booleans()) {
			sends = append(sends, draw())
		}
		run(sends...)
		for i, s := range sends {
			if s.err != nil {
				ht.Fatalf("send %d, to %d keyed %d: %v", i, s.to, s.key, s.err)
			}
			if s.exact() {
				continue
			}
			overlaps := false
			for j, o := range sends {
				overlaps = overlaps || j != i && s.from < o.until && o.from < s.until
			}
			if !overlaps {
				ht.Fatalf("send %d, to %d keyed %d and overlapping no other, left %v by %d", i, s.to, s.key, s.left, s.by)
			}
		}
		last := draw()
		run(last)
		if !last.exact() {
			ht.Fatalf("once every send ended, the send to %d keyed %d left %v by %d", last.to, last.key, last.left, last.by)
		}
	})
}
