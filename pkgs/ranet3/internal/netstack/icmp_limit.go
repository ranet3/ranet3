// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"container/list"
	"net/netip"
	"sync"
	"sync/atomic"
)

// icmpLimit decides which of the ICMP errors this node would send go out, as the kernel's icmp_global_allow and inet_peer_xrlim_allow decide
// every answer draws one from the node's cap, and every answer but packet too big and fragmentation needed one from the bucket of its offending packet's source
// so one source's flood of expired or refused packets spends its own bucket, while one sender's packets past their session at the cap's rate hold back every answer
// the zero value holds no source and a full cap
type icmpLimit struct {
	mu   sync.Mutex
	node icmpBucket
	// sources holds the buckets by address, and order holds them from the most recent draw to the least
	sources map[netip.Addr]*list.Element
	order   list.List
	_       [linePad]byte
	// spentUntil is the instant the cap next holds a token, stored under mu by each draw the cap withholds
	// nothing but time changes the cap until it lets an answer out, so take withholds a draw from before that instant without waiting for mu
	// a draw whose clock reading trails one the cap let out since is withheld at its own reading, where under mu it would be judged as of that later draw
	// which withholds at most an answer at the edge of a spent cap and never lets out one the cap does not hold
	spentUntil atomic.Int64
	_          [linePad]byte
}

// icmpVerdict is take's decision on one answer
type icmpVerdict uint8

const (
	icmpAllowed icmpVerdict = iota
	// icmpBySource and icmpByNode are an answer withheld by its source's bucket and by the node's cap
	icmpBySource
	icmpByNode
)

// icmpBucket is a token bucket kept as the time its answers cost, so the zero value is full
// spent is the cost not yet earned back as of last, both in nanoseconds on the limit's clock
type icmpBucket struct {
	spent, last int64
}

// icmpSource is one source's bucket in the limit's table
type icmpSource struct {
	addr   netip.Addr
	bucket icmpBucket
}

// allows earns back the time since last and reports whether cost fits within most, the bucket's whole burst
func (b *icmpBucket) allows(now, cost, most int64) bool {
	// callers read the clock before they wait for the lock, so now may trail last
	if elapsed := now - b.last; elapsed > 0 {
		b.spent, b.last = max(0, b.spent-elapsed), now
	}
	return b.spent+cost <= most
}

// readyAt is the instant the bucket next allows cost within most, as of its last draw
func (b *icmpBucket) readyAt(cost, most int64) int64 {
	return b.last + b.spent + cost - most
}

// take decides whether an answer to a packet from source may go out at now, nanoseconds on a monotonic clock, and spends its cost if so
// source is the zero Addr for packet too big and fragmentation needed, which only the cap holds back
func (l *icmpLimit) take(now int64, source netip.Addr) icmpVerdict {
	if now < l.spentUntil.Load() {
		return icmpByNode
	}
	cost := int64(icmpNodeCost)
	l.mu.Lock()
	defer l.mu.Unlock()
	// the cap is read first, so an answer it withholds spends nothing of its source's bucket
	if !l.node.allows(now, cost, icmpNodeBurst*cost) {
		l.spentUntil.Store(l.node.readyAt(cost, icmpNodeBurst*cost))
		return icmpByNode
	}
	if source.IsValid() {
		interval := int64(icmpSourceInterval6)
		if source.Is4() {
			interval = int64(icmpSourceInterval4)
		}
		bucket := l.bucket(source)
		if !bucket.allows(now, interval, icmpSourceBurst*interval) {
			return icmpBySource
		}
		bucket.spent += interval
	}
	l.node.spent += cost
	return icmpAllowed
}

// bucket is source's, full for a source the table does not hold, and moved to the front of order
func (l *icmpLimit) bucket(source netip.Addr) *icmpBucket {
	if l.sources == nil {
		l.sources = make(map[netip.Addr]*list.Element)
	}
	if element, ok := l.sources[source]; ok {
		l.order.MoveToFront(element)
		return &element.Value.(*icmpSource).bucket
	}
	if len(l.sources) < icmpSources {
		entry := &icmpSource{addr: source}
		l.sources[source] = l.order.PushFront(entry)
		return &entry.bucket
	}
	element := l.order.Back()
	entry := element.Value.(*icmpSource)
	delete(l.sources, entry.addr)
	*entry = icmpSource{addr: source}
	l.sources[source] = element
	l.order.MoveToFront(element)
	return &entry.bucket
}
