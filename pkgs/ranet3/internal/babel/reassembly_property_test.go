// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// streamSteps is how many fragments, clock steps and sweeps a stream runs at most
const streamSteps = 100

// cutStyles are the ways a packet is cut into fragments, each drawn outright
// whole sends it as one atomic fragment, finest cuts it at every 8-octet boundary, stack into fragments of one size as a sender's stack does, and any at boundaries picked at random
var cutStyles = []string{"whole", "finest", "stack", "any"}

// fragmentOrders are the orders the fragments arrive in, each drawn outright
var fragmentOrders = []string{"in order", "reversed", "shuffled"}

// any Babel packet up to the largest RFC 8966 section 4 allows, cut at 8-octet boundaries and delivered in any order with copies, is read as itself once, as its last fragment first arrives
// the fragments after the first carry another traffic class, flow label, hop limit and Next Header
// the packet read takes them from the first, RFC 8200 section 4.5
// a datagram read keeps its place, so a second delivery of every fragment reads nothing
// an atomic fragment is a whole packet, read each time it arrives, RFC 6946 section 4
func TestFragmentedBabelPacketIsReadAsItselfOnce(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		size := hegel.Draw(ht, pbt.Spanning(ipv6HeaderLen+udpHeaderLen+4, math.MaxUint16))
		source := rand.NewChaCha8([32]byte(hegel.Draw(ht, hegel.Binary(32, 32))))
		random := rand.New(source)
		// a Babel packet header, RFC 8966 section 4.2, and a body of random octets
		payload := make([]byte, size-ipv6HeaderLen-udpHeaderLen)
		payload[0], payload[1] = 42, 2
		binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)-4))
		source.Read(payload[4:])
		src, dst := hegel.Draw(ht, linkLocals()), multicastGroup
		if hegel.Draw(ht, hegel.Booleans()) {
			dst = hegel.Draw(ht, linkLocals())
		}
		packet := buildPacket(src, dst, payload)
		// the traffic class, flow label and hop limit any sender may set
		binary.BigEndian.PutUint32(packet[0:4], 6<<28|hegel.Draw(ht, hegel.Integers[uint32](0, 1<<28-1)))
		packet[7] = hegel.Draw(ht, hegel.Integers[byte](0, math.MaxUint8))

		fragmentable := size - ipv6HeaderLen
		boundaries := (fragmentable - 1) / 8
		var cuts []int
		switch hegel.Draw(ht, hegel.SampledFrom(cutStyles)) {
		case "finest":
			for at := 8; at < fragmentable; at += 8 {
				cuts = append(cuts, at)
			}
		case "stack":
			step := 8 * hegel.Draw(ht, pbt.Spanning(1, boundaries))
			for at := step; at < fragmentable; at += step {
				cuts = append(cuts, at)
			}
		case "any":
			for _, boundary := range random.Perm(boundaries)[:hegel.Draw(ht, pbt.Spanning(1, boundaries))] {
				cuts = append(cuts, 8*(boundary+1))
			}
			slices.Sort(cuts)
		}
		fragments := fragment(packet, hegel.Draw(ht, pbt.Spanning[uint32](0, math.MaxUint32)), cuts...)
		flow, hops := hegel.Draw(ht, pbt.Spanning[uint32](1, 1<<28-1)), hegel.Draw(ht, pbt.Spanning[byte](1, math.MaxUint8))
		// any Next Header but UDP
		later := hegel.Draw(ht, pbt.Spanning[byte](0, math.MaxUint8-1))
		if later >= nextHeaderUDP {
			later++
		}
		for _, f := range fragments[1:] {
			binary.BigEndian.PutUint32(f[0:4], binary.BigEndian.Uint32(f[0:4])^flow)
			f[7] ^= hops
			f[ipv6HeaderLen] = later
		}

		order := make([]int, len(fragments))
		for i := range order {
			order[i] = i
		}
		switch hegel.Draw(ht, hegel.SampledFrom(fragmentOrders)) {
		case "reversed":
			slices.Reverse(order)
		case "shuffled":
			random.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		}
		for range hegel.Draw(ht, pbt.Spanning(0, 16)) {
			order = slices.Insert(order, random.IntN(len(order)+1), random.IntN(len(fragments)))
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			order = slices.Concat(order, order)
		}

		var r reassembly
		now := time.Now()
		arrived, missing, complete := make([]bool, len(fragments)), len(fragments), -1
		var read []int
		for at, i := range order {
			if !arrived[i] {
				arrived[i] = true
				if missing--; missing == 0 {
					complete = at
				}
			}
			whole := r.add(fragments[i], src, dst, now)
			if whole == nil {
				continue
			}
			if !bytes.Equal(whole, packet) {
				ht.Fatalf("delivery %d of %d read %d octets unlike the packet of %d", at, len(order), len(whole), size)
			}
			read = append(read, at)
		}
		if r.held != 0 || r.stats.Dropped != [len(FragmentDrops)]uint64{} {
			ht.Fatalf("after %d deliveries the reassembly holds %d octets and dropped %v, want neither", len(order), r.held, r.stats.Dropped)
		}
		if len(fragments) == 1 {
			if len(read) != len(order) {
				ht.Fatalf("an atomic fragment delivered %d times was read %d times", len(order), len(read))
			}
			return
		}
		if len(read) != 1 || read[0] != complete {
			ht.Fatalf("the packet of %d octets in %d fragments was read at deliveries %v of %d, want once at %d, as its last fragment first arrived",
				size, len(fragments), read, len(order), complete)
		}
	})
}

// streamSources and streamDestinations are where a stream's fragments come from and go to
// the Babel group and the speaker are among the second
var (
	streamSources      = []netip.Addr{netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fe80::3")}
	streamDestinations = []netip.Addr{multicastGroup, netip.MustParseAddr("fe80::1")}
)

// streamClock are the steps a stream's clock takes, each drawn outright
// together they bring datagrams of any age across minFragmentAge and maxFragmentAge
var streamClock = []time.Duration{time.Nanosecond, minFragmentAge - time.Nanosecond, minFragmentAge, maxFragmentAge - minFragmentAge, maxFragmentAge - time.Nanosecond, maxFragmentAge}

// streamFills name the octets a fragment of any shape carries, each drawn outright
// zeros as storage not yet written holds, the octets its key's cut packet holds at its place, or octets at random
var streamFills = []string{"zeros", "the packet's", "random"}

// streamKey is a datagram's source, destination and identification
type streamKey struct {
	src, dst netip.Addr
	id       uint32
}

// String is the key as a failure names it
func (k streamKey) String() string {
	return fmt.Sprintf("%v to %v, identification %d", k.src, k.dst, k.id)
}

// keyOf is the key of fragment f
func keyOf(f []byte) streamKey {
	return streamKey{netip.AddrFrom16([16]byte(f[8:24])), netip.AddrFrom16([16]byte(f[24:40])), binary.BigEndian.Uint32(f[44:48])}
}

// fragmentShape is the offset fragment f's octets go to, and whether f is atomic
// an atomic fragment is at offset 0 with no more to come
func fragmentShape(f []byte) (offset int, atomic bool) {
	field := binary.BigEndian.Uint16(f[42:44])
	return int(field &^ 7), field&^7 == 0 && field&1 == 0
}

// streamCut is the Babel packet cut for a key and its fragments
type streamCut struct {
	packet    []byte
	fragments [][]byte
}

// streamKept is the key of a datagram the reassembly keeps at one step, and whether it is done
type streamKept struct {
	key  streamKey
	done bool
}

// streamLife is a datagram the reassembly kept, since the step it first appeared
type streamLife struct {
	born time.Time
	read bool
}

// fragmentStream drives one neighbor's reassembly with fragments of any shape in any order, beside a record that checks each step
type fragmentStream struct {
	r      reassembly
	now    time.Time
	source *rand.ChaCha8
	// sent is every fragment delivered, in order
	sent [][]byte
	// lives are the datagrams the reassembly keeps, by their bookkeeping
	lives map[*datagram]streamLife
	cuts  map[streamKey]streamCut
	// fresh numbers the identifications no other fragment has
	fresh uint32
}

// drawKey draws a key among a few
// fragments of one datagram then meet
func drawKey(tc hegel.TestCase) streamKey {
	return streamKey{streamSources[hegel.Draw(tc, hegel.Integers(0, 1))], streamDestinations[hegel.Draw(tc, hegel.Integers(0, 1))],
		hegel.Draw(tc, pbt.Spanning[uint32](0, 24))}
}

// RuleCut sends one fragment of the Babel packet cut for a key
func (m *fragmentStream) RuleCut(tc hegel.TestCase) {
	fragments := m.cut(tc, drawKey(tc))
	m.deliver(tc, bytes.Clone(fragments[hegel.Draw(tc, pbt.Spanning(0, len(fragments)-1))]))
}

// RuleCutAll sends every fragment of the Babel packet cut for a key, in order, reversed or shuffled
func (m *fragmentStream) RuleCutAll(tc hegel.TestCase) {
	fragments := slices.Clone(m.cut(tc, drawKey(tc)))
	switch hegel.Draw(tc, hegel.SampledFrom(fragmentOrders)) {
	case "reversed":
		slices.Reverse(fragments)
	case "shuffled":
		rand.New(m.source).Shuffle(len(fragments), func(i, j int) { fragments[i], fragments[j] = fragments[j], fragments[i] })
	}
	for _, f := range fragments {
		m.deliver(tc, bytes.Clone(f))
	}
}

// cut is the fragments of the Babel packet cut for key
// the packet is made and cut the first time the key is drawn
// fragments after the first carry another traffic class, flow label, hop limit and Next Header
func (m *fragmentStream) cut(tc hegel.TestCase, key streamKey) [][]byte {
	if cut, ok := m.cuts[key]; ok {
		return cut.fragments
	}
	size := hegel.Draw(tc, pbt.Spanning(ipv6HeaderLen+udpHeaderLen+4, math.MaxUint16))
	payload := make([]byte, size-ipv6HeaderLen-udpHeaderLen)
	m.source.Read(payload)
	packet := buildPacket(key.src, key.dst, payload)
	fragmentable := size - ipv6HeaderLen
	step := (fragmentable/hegel.Draw(tc, pbt.Spanning(1, 4)) + 7) &^ 7
	var at []int
	for boundary := step; boundary < fragmentable; boundary += step {
		at = append(at, boundary)
	}
	fragments := fragment(packet, key.id, at...)
	for _, f := range fragments[1:] {
		binary.BigEndian.PutUint32(f[0:4], binary.BigEndian.Uint32(f[0:4])^1)
		f[7]++
		f[ipv6HeaderLen] = 59
	}
	m.cuts[key] = streamCut{packet, fragments}
	return fragments
}

// RuleAnyShape sends a fragment of any offset, length, M flag and Next Header for a key
// its octets are zeros, those of the key's cut packet, or random
// one at offset 0 may begin with a UDP header to the Babel port
func (m *fragmentStream) RuleAnyShape(tc hegel.TestCase) {
	m.anyShape(tc, drawKey(tc))
}

// RuleFreshBurst sends fragments of any shape, each under an identification no other fragment had
// they fill the neighbor's places and storage
func (m *fragmentStream) RuleFreshBurst(tc hegel.TestCase) {
	for range hegel.Draw(tc, pbt.Spanning(1, maxFragmentedDatagrams)) {
		m.fresh++
		key := drawKey(tc)
		key.id = math.MaxUint16 + m.fresh
		m.anyShape(tc, key)
	}
}

func (m *fragmentStream) anyShape(tc hegel.TestCase, key streamKey) {
	offset := 8 * hegel.Draw(tc, pbt.Spanning(0, math.MaxUint16/8))
	// whole 8-octet blocks and the octets past them, each drawn outright
	// a fragment with more to come is then often well formed
	data := make([]byte, 8*hegel.Draw(tc, pbt.Spanning(0, 1500/8))+hegel.Draw(tc, pbt.Spanning(0, 7)))
	more := hegel.Draw(tc, hegel.Booleans())
	nextHeader := hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderUDP, 58}))
	switch hegel.Draw(tc, hegel.SampledFrom(streamFills)) {
	case "the packet's":
		if cut, ok := m.cuts[key]; ok && ipv6HeaderLen+offset < len(cut.packet) {
			copy(data, cut.packet[ipv6HeaderLen+offset:])
		}
	case "random":
		m.source.Read(data)
	}
	if offset == 0 && len(data) >= udpHeaderLen && hegel.Draw(tc, hegel.Booleans()) {
		binary.BigEndian.PutUint16(data[2:4], Port)
	}
	m.deliver(tc, shaped(key, offset, more, nextHeader, data))
}

// RuleCopy sends a fragment sent before again, octet for octet
func (m *fragmentStream) RuleCopy(tc hegel.TestCase) {
	tc.Assume(len(m.sent) > 0)
	m.deliver(tc, bytes.Clone(m.sent[hegel.Draw(tc, hegel.Integers(0, len(m.sent)-1))]))
}

// RuleStretch sends a fragment sent before with zeros after its octets, a multiple of 8 octets with more to come
// it overlaps what the datagram holds, past it within the datagram's storage or beyond that storage
func (m *fragmentStream) RuleStretch(tc hegel.TestCase) {
	tc.Assume(len(m.sent) > 0)
	f := m.sent[hegel.Draw(tc, hegel.Integers(0, len(m.sent)-1))]
	offset, _ := fragmentShape(f)
	data := f[ipv6HeaderLen+fragmentHeaderLen:]
	stretched := make([]byte, (len(data)+7)&^7+8*hegel.Draw(tc, pbt.Spanning(1, 1024)))
	copy(stretched, data)
	m.deliver(tc, shaped(keyOf(f), offset, true, f[ipv6HeaderLen], stretched))
}

// RuleClock moves the clock on
func (m *fragmentStream) RuleClock(tc hegel.TestCase) {
	m.now = m.now.Add(hegel.Draw(tc, hegel.SampledFrom(streamClock)))
}

// RuleSweep runs the speaker's sweep over the reassembly
func (m *fragmentStream) RuleSweep(tc hegel.TestCase) {
	kept, counted := m.snapshot()
	m.r.expire(m.now)
	m.check(tc, kept, counted, nil, false, nil)
}

// InvariantStorageAndPlacesStayInBounds holds held to the storage of the datagrams under way and within maxFragmentOctets
// a datagram done holds no storage
// the places stay within maxFragmentedDatagrams
func (m *fragmentStream) InvariantStorageAndPlacesStayInBounds(tc hegel.TestCase) {
	storage := 0
	for _, d := range m.r.datagrams {
		if d.done && d.packet != nil {
			tc.Errorf("datagram %d is done and holds %d octets", d.id, cap(d.packet))
		}
		storage += cap(d.packet)
	}
	if storage != m.r.held || m.r.held > maxFragmentOctets || len(m.r.datagrams) > maxFragmentedDatagrams {
		tc.Errorf("%d datagrams hold %d octets, counted as %d, against bounds of %d datagrams and %d octets",
			len(m.r.datagrams), storage, m.r.held, maxFragmentedDatagrams, maxFragmentOctets)
	}
}

// shaped is a fragment of key at offset carrying data, with more to come as given and nextHeader in its Fragment header
func shaped(key streamKey, offset int, more bool, nextHeader byte, data []byte) []byte {
	f := make([]byte, ipv6HeaderLen+fragmentHeaderLen+len(data))
	f[0], f[6], f[7], f[ipv6HeaderLen] = 6<<4, nextHeaderFragment, babelHopLimit, nextHeader
	binary.BigEndian.PutUint16(f[4:6], uint16(fragmentHeaderLen+len(data)))
	copy(f[8:24], key.src.AsSlice())
	copy(f[24:40], key.dst.AsSlice())
	field := uint16(offset)
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(f[42:44], field)
	binary.BigEndian.PutUint32(f[44:48], key.id)
	copy(f[ipv6HeaderLen+fragmentHeaderLen:], data)
	return f
}

// snapshot records each datagram the reassembly keeps, and how many it counted as dropped
func (m *fragmentStream) snapshot() (map[*datagram]streamKept, uint64) {
	kept := make(map[*datagram]streamKept, len(m.r.datagrams))
	for _, d := range m.r.datagrams {
		kept[d] = streamKept{streamKey{d.src, d.dst, d.id}, d.done}
	}
	var dropped uint64
	for _, n := range m.r.stats.Dropped {
		dropped += n
	}
	return kept, dropped
}

// deliver hands the reassembly fragment f and checks the step
func (m *fragmentStream) deliver(tc hegel.TestCase, f []byte) {
	m.sent = append(m.sent, f)
	key := keyOf(f)
	kept, counted := m.snapshot()
	whole := m.r.add(f, key.src, key.dst, m.now)
	_, atomic := fragmentShape(f)
	m.check(tc, kept, counted, &key, atomic, whole)
	if whole != nil {
		m.checkRead(tc, f, atomic, whole)
	}
}

// check compares what the reassembly keeps after a step with what it kept before, for the fragment of key own or for a sweep
// a datagram gives its place to another only once read or past minFragmentAge
// it ends under way before minFragmentAge only by a fragment of its own
// it is forgotten only past maxFragmentAge
// every datagram that ended is counted once, as read or dropped
// so is a fragment that took no place
func (m *fragmentStream) check(tc hegel.TestCase, before map[*datagram]streamKept, counted uint64, own *streamKey, atomic bool, whole []byte) {
	after, dropped := m.snapshot()
	ended := 0
	for d, was := range before {
		is, ok := after[d]
		if ok && is == was {
			continue
		}
		life := m.lives[d]
		age := m.now.Sub(life.born)
		switch {
		case !ok:
			if age < maxFragmentAge {
				tc.Errorf("datagram %v was forgotten %s after it appeared", was.key, age)
			}
		case is.key != was.key:
			if !life.read && age < minFragmentAge {
				tc.Errorf("datagram %v gave its place to %v %s after it appeared", was.key, is.key, age)
			}
		case !was.done && is.done:
			if (own == nil || was.key != *own) && age < minFragmentAge {
				tc.Errorf("datagram %v under way ended %s after it appeared, not by a fragment of its own", was.key, age)
			}
			if own != nil && was.key == *own && whole != nil && !atomic {
				m.lives[d] = streamLife{life.born, true}
			}
		default:
			tc.Errorf("datagram %v went from done %v to done %v", was.key, was.done, is.done)
		}
		if !was.done {
			ended++
		}
	}
	placed := false
	for d, is := range after {
		placed = placed || (own != nil && is.key == *own)
		if was, ok := before[d]; ok && was.key == is.key {
			if age := m.now.Sub(m.lives[d].born); age >= maxFragmentAge {
				tc.Errorf("datagram %v is kept %s after it appeared", is.key, age)
			}
			continue
		}
		m.lives[d] = streamLife{born: m.now}
		if is.done {
			ended++
		}
	}
	for d := range m.lives {
		if _, ok := after[d]; !ok {
			delete(m.lives, d)
		}
	}
	placeless := 0
	if own != nil && (atomic || !placed) {
		placeless = 1
	}
	read := uint64(0)
	if whole != nil {
		read = 1
	}
	if dropped-counted+read != uint64(ended+placeless) {
		tc.Errorf("a step counted %d datagrams read or dropped where %d ended and %d fragments took no place", dropped-counted+read, ended, placeless)
	}
}

// checkRead holds a packet read to a whole UDP packet to the Babel port that the fragments sent for its key carried
// its IPv6 header and Next Header are those of a first fragment
// each octet after them is one some fragment brought to its place
// an atomic fragment carries its packet alone, apart from any datagram of its key
func (m *fragmentStream) checkRead(tc hegel.TestCase, f []byte, atomic bool, whole []byte) {
	if len(whole) < ipv6HeaderLen+udpHeaderLen || whole[0]>>4 != 6 || int(binary.BigEndian.Uint16(whole[4:6])) != len(whole)-ipv6HeaderLen ||
		whole[6] != nextHeaderUDP || binary.BigEndian.Uint16(whole[ipv6HeaderLen+2:]) != Port {
		tc.Errorf("the packet read is no whole UDP packet to the Babel port: %x", whole[:min(len(whole), ipv6HeaderLen+udpHeaderLen)])
	}
	key, sources := keyOf(f), [][]byte{f}
	if !atomic {
		sources = nil
		for _, s := range m.sent {
			if _, isAtomic := fragmentShape(s); keyOf(s) == key && !isAtomic {
				sources = append(sources, s)
			}
		}
	}
	headed, carried := false, make([]bool, len(whole)-ipv6HeaderLen)
	for _, s := range sources {
		offset, _ := fragmentShape(s)
		headed = headed || (offset == 0 && bytes.Equal(s[0:4], whole[0:4]) && bytes.Equal(s[7:ipv6HeaderLen], whole[7:ipv6HeaderLen]) && s[ipv6HeaderLen] == whole[6])
		for i, octet := range s[ipv6HeaderLen+fragmentHeaderLen:] {
			if at := offset + i; at < len(carried) && whole[ipv6HeaderLen+at] == octet {
				carried[at] = true
			}
		}
	}
	if !headed || slices.Contains(carried, false) {
		tc.Errorf("the packet read for %v holds octets no fragment sent for it carried there", key)
	}
}

// any stream of fragments from one neighbor, of any offset, length, M flag and identification, with copies and overlaps, in any order
// the clock steps across minFragmentAge and maxFragmentAge, and the speaker's sweep runs now and then
// held stays the storage of the datagrams under way, within maxFragmentOctets
// the places stay within maxFragmentedDatagrams
// a datagram gives way to another only once read or past minFragmentAge
// it is forgotten only past maxFragmentAge
// every datagram that ends counts once, as read or dropped
// so does a fragment that takes no place
// every packet read is whole and carried by the fragments sent for it
// nothing panics
func TestAnyFragmentStreamKeepsTheReassemblyInItsBounds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := &fragmentStream{now: time.Now(), source: rand.NewChaCha8([32]byte(hegel.Draw(ht, hegel.Binary(32, 32)))),
			lives: make(map[*datagram]streamLife), cuts: make(map[streamKey]streamCut)}
		hegel.RunStateful(ht, m, hegel.WithStatefulStepCount(streamSteps), hegel.WithAlwaysCheckInvariants("InvariantStorageAndPlacesStayInBounds"))
	})
}
