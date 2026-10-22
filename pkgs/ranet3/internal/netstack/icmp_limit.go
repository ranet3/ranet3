// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
)

// icmpSeed keys the mix that spreads sources over the limit's shards, a word for each half of the address, so no sender can choose addresses that share one shard
// it is made once a process from the system's randomness and held in memory alone
var icmpSeed = func() [2]uint64 {
	var seed [16]byte
	// Read fills the whole of seed and never fails, crashing the program where the system gives no randomness
	_, _ = rand.Read(seed[:])
	return [2]uint64{binary.LittleEndian.Uint64(seed[:8]), binary.LittleEndian.Uint64(seed[8:])}
}()

// icmpLimit decides which of the ICMP errors this node would send go out, as the kernel's icmp_global_allow and inet_peer_xrlim_allow decide
// every answer draws one from the node's cap, and every answer but packet too big and fragmentation needed one from the bucket of its offending packet's source
// so one source's flood of expired or refused packets spends its own bucket, while one sender's packets past their session at the cap's rate hold back every answer
// the sources lie in shards by a seeded mix of their address, each with its own lock, order and share of the table, and the cap takes no lock
// a draw holds at most one shard's lock and takes no other
// the zero value holds no source and a full cap
type icmpLimit struct {
	_      [linePad]byte
	node   icmpCap
	_      [linePad]byte
	shards [icmpShards]icmpShard
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

// icmpCap is the node's cap, an icmpBucket kept as two instants so a draw reads it with no lock
// full is the instant it has earned back all it spent, last plus spent, and last the latest draw it let out
// a draw spends by swapping full for a later one, and full only grows, so a swap lands only on the full its draw judged
type icmpCap struct {
	full, last atomic.Int64
}

// icmpShard holds the buckets of the sources the mix puts in it, and counts the draws each limit withheld
type icmpShard struct {
	mu sync.Mutex
	// sources holds the buckets by address, and order holds them from the most recent draw to the least
	sources map[netip.Addr]*list.Element
	order   list.List
	// withheld counts by source and by node, indexed by the verdict less icmpBySource
	// a draw the cap withholds before any bucket is read, and a too-big draw, which no shard's bucket holds, count on the shard their clock reading picks
	withheld [2]atomic.Uint64
	_        [linePad]byte
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

// holds reports whether the cap holds an answer at now, judged as of the latest answer it let out when now trails that one
// with full as it read it and the instant it judged at
// full and at are compared by their difference alone, which stays exact where a reading near the clock's end would carry a sum past it
func (c *icmpCap) holds(now int64) (full, at int64, ok bool) {
	at = max(now, c.last.Load())
	full = c.full.Load()
	return full, at, full-at <= (icmpNodeBurst-1)*int64(icmpNodeCost)
}

// spend lets one answer out at now if the cap holds it, judged again whenever another draw spent between the read and the swap
func (c *icmpCap) spend(now int64) bool {
	for {
		full, at, ok := c.holds(now)
		if !ok {
			return false
		}
		// a cap that has earned back all it spent by at spends from at
		// read by the difference, as holds reads it, so a full carried past the clock's end still counts as the later
		next := full
		if next-at < 0 {
			next = at
		}
		if c.full.CompareAndSwap(full, next+int64(icmpNodeCost)) {
			for last := c.last.Load(); last < at && !c.last.CompareAndSwap(last, at); last = c.last.Load() {
			}
			return true
		}
	}
}

// take decides whether an answer to a packet from source may go out at now, nanoseconds on a monotonic clock, spends its cost if so and counts it if not
// source is the zero Addr for packet too big and fragmentation needed, which only the cap holds back
// the cap is read first and with no lock, so a draw it withholds waits for nothing and spends nothing of its source's bucket
// such a draw counts on the shard its clock reading picks, so it computes no mix of its address
func (l *icmpLimit) take(now int64, source netip.Addr) icmpVerdict {
	if _, _, ok := l.node.holds(now); !ok {
		return l.counter(now).withhold(icmpByNode)
	}
	if !source.IsValid() {
		if !l.node.spend(now) {
			return l.counter(now).withhold(icmpByNode)
		}
		return icmpAllowed
	}
	interval := int64(icmpSourceInterval6)
	if source.Is4() {
		interval = int64(icmpSourceInterval4)
	}
	shard := l.shard(source)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	element := shard.sources[source]
	var entry *icmpSource
	var bucket icmpBucket
	if element != nil {
		entry = element.Value.(*icmpSource)
		bucket = entry.bucket
	}
	// the bucket is judged on a copy and the cap read again, so a draw the cap withholds here leaves the table as it found it
	verdict := icmpAllowed
	if !bucket.allows(now, interval, icmpSourceBurst*interval) {
		if _, _, ok := l.node.holds(now); !ok {
			return shard.withhold(icmpByNode)
		}
		verdict = shard.withhold(icmpBySource)
	} else if !l.node.spend(now) {
		return shard.withhold(icmpByNode)
	} else {
		bucket.spent += interval
	}
	shard.keep(source, element, entry, bucket)
	return verdict
}

// shard is the one source's bucket lies in, picked by a seeded mix of its address's two halves
// the halves, each keyed by its own word of the seed, multiply into 128 bits whose halves fold into one word, and its top bits pick the shard
func (l *icmpLimit) shard(source netip.Addr) *icmpShard {
	address := source.As16()
	hi, lo := bits.Mul64(binary.BigEndian.Uint64(address[:8])^icmpSeed[0], binary.BigEndian.Uint64(address[8:])^icmpSeed[1])
	index, _ := bits.Mul64(hi^lo, icmpShards)
	// index is below icmpShards already, and the modulo only spares the bounds check
	return &l.shards[index%icmpShards]
}

// counter is the shard a draw with no bucket of its own counts on, the one its clock reading picks
func (l *icmpLimit) counter(now int64) *icmpShard {
	return &l.shards[uint64(now)%icmpShards]
}

// withhold counts a draw limit withheld and returns limit
func (s *icmpShard) withhold(limit icmpVerdict) icmpVerdict {
	s.withheld[limit-icmpBySource].Add(1)
	return limit
}

// keep stores bucket as source's at the front of order, element and entry being source's or nil for a source the shard does not hold
// a full shard gives the place of its own least recent source, which returns full like a new one
func (s *icmpShard) keep(source netip.Addr, element *list.Element, entry *icmpSource, bucket icmpBucket) {
	if element == nil {
		if s.sources == nil {
			s.sources = make(map[netip.Addr]*list.Element)
		}
		if len(s.sources) < icmpSources/icmpShards {
			s.sources[source] = s.order.PushFront(&icmpSource{addr: source, bucket: bucket})
			return
		}
		element = s.order.Back()
		entry = element.Value.(*icmpSource)
		delete(s.sources, entry.addr)
		s.sources[source] = element
		entry.addr = source
	}
	entry.bucket = bucket
	s.order.MoveToFront(element)
}

// withheld is how many draws limit withheld, summed over the shards
func (l *icmpLimit) withheld(limit icmpVerdict) uint64 {
	var total uint64
	for i := range l.shards {
		total += l.shards[i].withheld[limit-icmpBySource].Load()
	}
	return total
}
