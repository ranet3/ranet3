// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// espSuite is one encryption transform a ChildSA can carry, spelled the way
// the ChildSA spells it.
type espSuite struct {
	id, bits uint16
}

// keyLen is the length of the suite's key material with its four byte salt.
func (s espSuite) keyLen() int {
	if s.id == ENCRChaCha20Poly1305 {
		return 32 + 4
	}
	return int(s.bits)/8 + 4
}

// propertySuites is every suite newESPAEAD builds an SA for. ChaCha20-Poly1305
// appears under both key lengths a ChildSA may name it with.
var propertySuites = []espSuite{
	{ENCRAESGCM16, 128}, {ENCRAESGCM16, 192}, {ENCRAESGCM16, 256},
	{ENCRChaCha20Poly1305, 0}, {ENCRChaCha20Poly1305, 256},
}

// withEdges draws from gen half the time and one of edges the rest. A run
// draws the same 200 cases every time, so an edge a property depends on is
// named here rather than left to the sample to reach. gen comes first so a
// failure shrinks within it rather than to whichever edge is listed first.
func withEdges[T any](gen hegel.Generator[T], edges ...T) hegel.Generator[T] {
	return hegel.OneOf(gen, hegel.SampledFrom(edges))
}

// settle collects what the property engine left behind and lets the cleanups
// that free its native handles run before the next test starts. Those
// cleanups allocate, and TestSealAllocations and the batch reuse test count
// every allocation the process makes, so one landing in their window fails
// them. It returns once a collection and the millisecond after it pass
// without an allocation, or after twenty tries.
func settle() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	for range 20 {
		before := stats.Mallocs
		runtime.GC()
		time.Sleep(time.Millisecond)
		runtime.ReadMemStats(&stats)
		if stats.Mallocs == before {
			return
		}
	}
}

// drawLoopback draws a suite, a key and an SPI, and builds the outbound SA
// together with the inbound SA that receives what it sends.
func drawLoopback(ht *hegel.T) (*OutboundSA, *InboundSA) {
	suite := hegel.Draw(ht, hegel.SampledFrom(propertySuites))
	key := hegel.Draw(ht, hegel.Binary(suite.keyLen(), suite.keyLen()))
	spi := hegel.Draw(ht, withEdges(hegel.Integers[uint32](0, math.MaxUint32), 0, 1, math.MaxUint32))
	child := ChildSA{
		EncrID: suite.id, EncrKeyBits: suite.bits,
		LocalSPI: spi, RemoteSPI: spi,
		InboundKey: key, OutboundKey: key,
	}
	out, err := NewOutbound(child)
	if err != nil {
		ht.Fatalf("NewOutbound refused suite %d/%d: %v", suite.id, suite.bits, err)
	}
	in, err := NewInbound(child)
	if err != nil {
		ht.Fatalf("NewInbound refused suite %d/%d: %v", suite.id, suite.bits, err)
	}
	return out, in
}

// drawPayload draws an inner packet from empty to a full 1500 byte MTU. The
// length is drawn on its own, since a byte string the engine sizes itself
// rarely reaches a few hundred bytes, and the edges are the empty packet, the
// full one, and the lengths one to three, which with the empty one give each
// of the four padding lengths.
func drawPayload(tc hegel.TestCase) []byte {
	size := hegel.Draw(tc, withEdges(hegel.Integers(0, 1500), 0, 1, 2, 3, 1500))
	return hegel.Draw(tc, hegel.Binary(size, size))
}

// drawNextHeader draws any Next Header octet, the three this package names
// among the edges.
func drawNextHeader(tc hegel.TestCase) byte {
	return hegel.Draw(tc, withEdges(hegel.Integers[byte](0, 255), NextHeaderIPv4, NextHeaderIPv6, NextHeaderNone, 0, 255))
}

// drawFirstSequence draws where a run of count sequence numbers starts. The
// edges are one and two, the first numbers an SA sends, and the start that
// ends the run on 2^32-1, the last. Otherwise the run starts within a few
// dozen of that end, or anywhere.
func drawFirstSequence(tc hegel.TestCase, count int) uint32 {
	last := math.MaxUint32 - uint32(count-1)
	nearEnd := hegel.Integers(last-64, last)
	anywhere := hegel.Integers[uint32](1, last)
	return hegel.Draw(tc, withEdges(hegel.OneOf(nearEnd, anywhere), 1, 2, last))
}

// sequenceOf reads the sequence number off a sealed packet and holds its IV to
// the same number, which is how the package keeps every IV under one key
// unique. An IV used twice under one key is the AES-GCM failure. It gives away
// the authentication key and the XOR of the two plaintexts.
func sequenceOf(ht *hegel.T, packet []byte) uint64 {
	ht.Helper()
	seq := binary.BigEndian.Uint32(packet[4:8])
	if iv := binary.BigEndian.Uint64(packet[8:16]); iv != uint64(seq) {
		ht.Fatalf("the packet with sequence %d carries IV %#016x rather than its sequence number", seq, iv)
	}
	return uint64(seq)
}

// sealPaths are the two ways a sender makes ESP: one Seal per packet, and one
// reserved range sealed as a batch, which is how the data plane sends.
var sealPaths = []string{"Seal", "SealBatch"}

// openPaths are the three ways a receiver gets it back: Open, which checks
// and commits in one call, one packet authenticated in place and committed,
// and a batch authenticated in place and committed in order, which is how
// the data plane receives.
var openPaths = []string{"Open", "AuthenticateInPlace", "AuthenticateBatchInPlace"}

// sealVia seals every payload, in order, through one of sealPaths.
func sealVia(ht *hegel.T, path string, out *OutboundSA, payloads [][]byte, headers []byte) [][]byte {
	ht.Helper()
	if path == "Seal" {
		sealed := make([][]byte, len(payloads))
		for i := range payloads {
			packet, err := out.Seal(payloads[i], headers[i])
			if err != nil {
				ht.Fatalf("Seal refused packet %d: %v", i, err)
			}
			sealed[i] = packet
		}
		return sealed
	}
	r, err := out.ReserveSequenceRange(len(payloads))
	if err != nil {
		ht.Fatalf("reserving %d sequence numbers: %v", len(payloads), err)
	}
	sealed, err := r.SealBatch(payloads, headers)
	if err != nil {
		ht.Fatalf("SealBatch refused %d packets: %v", len(payloads), err)
	}
	return sealed
}

// opened holds the result one receive path made of one packet.
type opened struct {
	plain      []byte
	nextHeader byte
	err        error
}

// openVia opens every packet, in order, through one of openPaths. The in
// place paths decrypt over the packets they are given.
func openVia(path string, in *InboundSA, packets [][]byte) []opened {
	results := make([]opened, len(packets))
	switch path {
	case "Open":
		for i, packet := range packets {
			r := &results[i]
			r.plain, r.nextHeader, r.err = in.Open(packet)
		}
	case "AuthenticateInPlace":
		for i, packet := range packets {
			r := &results[i]
			authenticated, err := in.AuthenticateInPlace(packet)
			if err != nil {
				r.err = err
				continue
			}
			r.plain, r.nextHeader, r.err = authenticated.Commit()
		}
	default:
		batch := in.AuthenticateBatchInPlace(packets, nil)
		CommitBatch(batch)
		for i := range batch {
			r := &results[i]
			r.plain, r.nextHeader, r.err = batch[i].Plaintext()
		}
	}
	return results
}

// Open gives back exactly the payload and next header Seal was given, for
// every suite a Child SA can carry, any key and SPI, sequence numbers
// anywhere in the space, and payloads from empty to a full 1500 byte MTU.
// It goes through the single packet calls every tool uses and the batch calls
// the data plane uses, since a packet a node sends one way may reach a peer
// that reads it the other. Every packet carries its sequence number as its IV.
func TestSealOpenRoundTripsEverySuite(t *testing.T) {
	t.Cleanup(settle)
	pbt.Check(t, func(ht *hegel.T) {
		out, in := drawLoopback(ht)
		count := hegel.Draw(ht, withEdges(hegel.Integers(1, 3), 1, 3))
		payloads, headers := make([][]byte, count), make([]byte, count)
		for i := range count {
			payloads[i] = drawPayload(ht)
			headers[i] = drawNextHeader(ht)
		}
		first := drawFirstSequence(ht, count)
		out.seq.Store(uint64(first) - 1)
		sealPath := hegel.Draw(ht, hegel.SampledFrom(sealPaths))
		openPath := hegel.Draw(ht, hegel.SampledFrom(openPaths))

		sealed := sealVia(ht, sealPath, out, payloads, headers)
		for i, packet := range sealed {
			if got, want := sequenceOf(ht, packet), uint64(first)+uint64(i); got != want {
				ht.Fatalf("%s put sequence %d on packet %d, want %d", sealPath, got, i, want)
			}
		}
		for i, got := range openVia(openPath, in, sealed) {
			if got.err != nil {
				ht.Fatalf("%s refused packet %d from %s: %v", openPath, i, sealPath, got.err)
			}
			if !bytes.Equal(got.plain, payloads[i]) || got.nextHeader != headers[i] {
				ht.Fatalf("%s read packet %d from %s as next header %d and %x, want %d and %x",
					openPath, i, sealPath, got.nextHeader, got.plain, headers[i], payloads[i])
			}
		}
	})
}

// A sealed packet with any one byte changed does not open, whichever byte it
// is and whatever it was changed to: the SPI and sequence number are bound in
// as associated data, and the IV, ciphertext and tag by the AEAD itself. The
// refusal also costs nothing, so the packet as it was sealed still opens
// afterward. Otherwise an attacker who can flip one bit on the path could feed
// a node altered packets, or spend its sequence numbers.
func TestAnyChangedByteFailsToOpen(t *testing.T) {
	t.Cleanup(settle)
	pbt.Check(t, func(ht *hegel.T) {
		out, in := drawLoopback(ht)
		payload := drawPayload(ht)
		nextHeader := drawNextHeader(ht)
		seq := drawFirstSequence(ht, 1)
		out.seq.Store(uint64(seq) - 1)
		packet, err := out.Seal(payload, nextHeader)
		if err != nil {
			ht.Fatalf("Seal refused sequence %d: %v", seq, err)
		}
		// the edges are the first and last byte of the SPI, the sequence
		// number, the IV, the ciphertext and the tag
		last := len(packet) - 1
		at := hegel.Draw(ht, withEdges(hegel.Integers(0, last), 0, 3, 4, 7, 8, 15, 16, last-16, last-15, last))
		flip := hegel.Draw(ht, withEdges(hegel.Integers[byte](1, 255), 0x01, 0x80, 0xff))
		path := hegel.Draw(ht, hegel.SampledFrom(openPaths))

		changed := bytes.Clone(packet)
		changed[at] ^= flip
		if got := openVia(path, in, [][]byte{changed})[0]; got.err == nil {
			ht.Fatalf("%s took a %d byte packet with byte %d changed by %#02x, and read %d bytes out of it",
				path, len(packet), at, flip, len(got.plain))
		}
		got := openVia(path, in, [][]byte{packet})[0]
		if got.err != nil {
			ht.Fatalf("%s refused the packet as sealed after refusing it with byte %d changed: %v", path, at, got.err)
		}
		if !bytes.Equal(got.plain, payload) || got.nextHeader != nextHeader {
			ht.Fatalf("%s read the packet as sealed as next header %d and %x, want %d and %x",
				path, got.nextHeader, got.plain, nextHeader, payload)
		}
	})
}

// The sequence ranges one SA hands out never share a number and never go
// back. Each starts one past where the one before it ended, holds as many
// numbers as were asked for, and a range that would cross the end of the
// 32 bit space is refused, as is every range after it. Every packet's IV is
// its sequence number, so a number handed out twice is an IV used twice under
// one key, the AES-GCM failure, which gives away the authentication key and
// the XOR of the two plaintexts. The counts are the batch sizes the data
// plane reserves. Half the time the end of the space is placed within two
// numbers of where one of the reservations ends, on it and one past it among
// the edges, since that is where an off by one hands out a number twice or
// refuses the last one. Otherwise the SA starts fresh, one short of the end,
// at the end, or anywhere.
func TestReservedRangesNeitherOverlapNorGoBack(t *testing.T) {
	t.Cleanup(settle)
	pbt.Check(t, func(ht *hegel.T) {
		out, err := NewOutbound(testChild(ht.T))
		if err != nil {
			ht.Fatal(err)
		}
		reservations := hegel.Draw(ht, withEdges(hegel.Integers(1, 16), 1, 16))
		counts := make([]int, reservations)
		for i := range counts {
			counts[i] = hegel.Draw(ht, withEdges(hegel.Integers(1, 128), 1, 128))
		}
		var start uint64
		nearEnd := hegel.Draw(ht, hegel.Booleans())
		if nearEnd {
			reaching := hegel.Draw(ht, hegel.Integers(1, len(counts)))
			short := hegel.Draw(ht, withEdges(hegel.Integers(-2, 2), 0, 1))
			sum := 0
			for _, count := range counts[:reaching] {
				sum += count
			}
			start = uint64(int64(math.MaxUint32) - int64(sum) + int64(short))
		} else {
			start = hegel.Draw(ht, withEdges(hegel.Integers[uint64](0, math.MaxUint32), 0, math.MaxUint32-1, math.MaxUint32))
		}
		out.seq.Store(start)

		// next is the first number the next range has to start at
		next := start + 1
		for i, count := range counts {
			r, err := out.ReserveSequenceRange(count)
			end := next + uint64(count) - 1
			if end > math.MaxUint32 {
				if !errors.Is(err, ErrSequenceExhausted) {
					ht.Fatalf("reservation %d of %d numbers from %d crosses the end of the space and gave %v, want ErrSequenceExhausted",
						i, count, next, err)
				}
				next = end + 1
				continue
			}
			if err != nil {
				ht.Fatalf("reservation %d of %d numbers from %d was refused: %v", i, count, next, err)
			}
			sealed, err := r.SealBatch(make([][]byte, count), make([]byte, count))
			if err != nil {
				ht.Fatalf("sealing reservation %d of %d numbers: %v", i, count, err)
			}
			for j, packet := range sealed {
				if got, want := sequenceOf(ht, packet), next+uint64(j); got != want {
					ht.Fatalf("reservation %d of %d numbers put sequence %d on packet %d, want %d", i, count, got, j, want)
				}
			}
			if _, err := r.Seal(nil, NextHeaderIPv4); err == nil {
				ht.Fatalf("reservation %d sealed one packet more than the %d it holds", i, count)
			}
			next = end + 1
		}
	})
}

// Whatever counts a caller asks for, an SA hands out only numbers from 1 to
// 2^32-1 and none of them twice. The data plane asks for its batch sizes,
// which the property above holds, but ReserveSequenceRange takes any int, up
// to the whole space and past it. A count larger than the space once moved
// the 64 bit counter past 2^64 and the space was handed out again. A granted
// range is judged by its bounds rather than by sealing all of it, since one
// range can be most of the space, and its first packet has to carry its
// first number.
func TestNoCountHandsOutANumberTwice(t *testing.T) {
	t.Cleanup(settle)
	// the counts where the space runs out, as far as an int reaches here
	space := uint64(math.MaxUint32)
	edges := []int{1, 128, math.MaxInt}
	if uint64(math.MaxInt) > space {
		edges = append(edges, int(space), int(space+1))
	}
	pbt.Check(t, func(ht *hegel.T) {
		out, err := NewOutbound(testChild(ht.T))
		if err != nil {
			ht.Fatal(err)
		}
		reservations := hegel.Draw(ht, withEdges(hegel.Integers(1, 8), 1, 8))
		var granted [][2]uint64
		for i := range reservations {
			count := hegel.Draw(ht, withEdges(hegel.Integers(1, 128), edges...))
			r, err := out.ReserveSequenceRange(count)
			if err != nil {
				continue
			}
			first, last := r.next, r.end
			if first == 0 || first > last || last > math.MaxUint32 || last-first+1 != uint64(count) {
				ht.Fatalf("reservation %d of %d numbers was granted %d to %d", i, count, first, last)
			}
			for _, earlier := range granted {
				if first <= earlier[1] && earlier[0] <= last {
					ht.Fatalf("reservation %d of %d numbers was granted %d to %d, and %d to %d were granted before",
						i, count, first, last, earlier[0], earlier[1])
				}
			}
			granted = append(granted, [2]uint64{first, last})
			packet, err := r.Seal(nil, NextHeaderIPv4)
			if err != nil {
				ht.Fatalf("reservation %d of %d numbers would not seal: %v", i, count, err)
			}
			if seq := sequenceOf(ht, packet); seq != first {
				ht.Fatalf("reservation %d was granted %d to %d and sealed sequence %d first", i, first, last, seq)
			}
		}
	})
}

// Inner is the largest inner packet whose sealed form fits the path under the outer IP and UDP headers, for every suite
// held to a search of every length from the path's MTU down, which finds none on a path too narrow for an empty packet
// padding to 4 bytes gives four lengths one sealed size, so a path that is not a multiple of 4 past the headers gives back up to 3 bytes
func TestInnerIsTheLargestPacketAPathCarries(t *testing.T) {
	t.Cleanup(settle)
	pbt.Check(t, func(ht *hegel.T) {
		out, _ := drawLoopback(ht)
		header := hegel.Draw(ht, hegel.SampledFrom([]int{20, 40}))
		// the widest path an empty packet does not fit, the narrowest it does, the ones the configuration names, and the most a datagram holds
		wire := hegel.Draw(ht, withEdges(hegel.Integers(0, math.MaxUint16), 0, header+43, header+44, 1280, 1500, 9000, math.MaxUint16))
		largest := -1
		for n := wire; n >= 0; n-- {
			if header+8+out.sealedLen(n) <= wire {
				largest = n
				break
			}
		}
		got := Inner(wire, header)
		switch {
		case largest < 0 && got >= 0:
			ht.Fatalf("Inner gives %d bytes on a %d byte path under a %d byte header, where no packet fits", got, wire, header)
		case largest >= 0 && got != largest:
			ht.Fatalf("Inner gives %d bytes on a %d byte path under a %d byte header, and the largest that fits is %d", got, wire, header, largest)
		}
	})
}
