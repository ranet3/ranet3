// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package esp

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// pendingPacket is a packet that authenticated and has not been committed.
type pendingPacket struct {
	seq     uint32
	payload []byte
	packet  *AuthenticatedPacket
}

// replayMachine drives one inbound SA through the receive path a node runs
// and holds referenceWindow beside it. A packet is checked when it
// authenticates, which leaves the window as it was, and checked again when it
// commits, which moves it, and any number of other packets may commit in
// between. The rules authenticate and commit in every interleaving, singly and
// in batches, and every answer the SA gives has to be the model's.
type replayMachine struct {
	out    *OutboundSA
	in     *InboundSA
	window uint32
	model  *referenceWindow

	// pending holds what authenticated and is waiting for its commit, in the
	// order it authenticated
	pending []pendingPacket
	// committed holds every packet a commit has seen, taken or not
	committed []*AuthenticatedPacket
	// sealed holds every sequence number a packet was sealed with, so a rule
	// can come back to one
	sealed []uint32
}

// accepts is the model's answer for seq. A zero window turns replay
// checking off, which referenceWindow does not describe.
func (m *replayMachine) accepts(seq uint32) bool {
	return m.window == 0 || m.model.check(seq)
}

// record moves the model past a commit the SA took.
func (m *replayMachine) record(seq uint32) {
	if m.window != 0 {
		m.model.commit(seq)
	}
}

// guard makes one call into the package and turns whatever it panics with
// into a failure of the step, which hegel then shrinks and prints with the
// window and the steps that led to it. A rule runs on a worker goroutine of
// its own, where the panic would otherwise end the process before the case
// was printed. The recover covers that call alone and never a draw, an
// assumption or a failure, which hegel raises as panics of its own to steer
// the case and which have to reach it as they were raised.
func guard(tc hegel.TestCase, call func()) {
	defer func() {
		if r := recover(); r != nil {
			tc.Errorf("panicked: %v", r)
		}
	}()
	call()
}

// verdict names an answer in a failure message.
func verdict(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "refused"
}

// sequenceAnchors are the places the window changes its answer, which
// drawSequence draws a sequence number near.
var sequenceAnchors = []string{"highest", "trailing edge", "one window ahead", "already sealed", "anywhere"}

// drawSequence picks a sequence number near one of sequenceAnchors: the
// highest number committed, the trailing edge one window behind it, one whole
// window ahead of it, or anywhere in the space, zero, one and 2^32-1 among
// the edges. The offset from the anchor names one below, on and one above it.
// A number already sealed is taken as it is, so exact repeats come up often.
func (m *replayMachine) drawSequence(tc hegel.TestCase) uint32 {
	highest, window := int64(m.model.last), int64(m.window)
	var near int64
	anchor := hegel.Draw(tc, hegel.SampledFrom(sequenceAnchors))
	switch anchor {
	case "highest":
		near = highest
	case "trailing edge":
		near = highest - window
	case "one window ahead":
		near = highest + window
	case "already sealed":
		tc.Assume(len(m.sealed) > 0)
		return m.sealed[hegel.Draw(tc, hegel.Integers(0, len(m.sealed)-1))]
	default:
		near = int64(hegel.Draw(tc, withEdges(hegel.Integers[uint32](0, math.MaxUint32), 0, 1, math.MaxUint32)))
	}
	reach := 2*window + 2
	offset := hegel.Draw(tc, withEdges(hegel.Integers(-reach, reach), -1, 0, 1))
	return uint32(min(max(near+offset, 0), math.MaxUint32))
}

// seal makes one packet carrying seq, with a payload no other packet has,
// so a commit that hands back the wrong plaintext shows.
func (m *replayMachine) seal(tc hegel.TestCase, seq uint32) ([]byte, []byte) {
	payload := binary.BigEndian.AppendUint32(nil, uint32(len(m.sealed)))
	r := SequenceRange{sa: m.out, next: uint64(seq), end: uint64(seq)}
	var packet []byte
	var err error
	guard(tc, func() { packet, err = r.Seal(payload, NextHeaderIPv6) })
	if err != nil {
		tc.Errorf("sealing sequence %d: %v", seq, err)
	}
	m.sealed = append(m.sealed, seq)
	return packet, payload
}

// judgeCommit compares what one commit made of p with the model's answer.
func (m *replayMachine) judgeCommit(tc hegel.TestCase, p pendingPacket, want bool, plain []byte, err error) {
	if (err == nil) != want {
		tc.Errorf("committing sequence %d with %d the highest committed gave %v, and the model %s it",
			p.seq, m.model.last, err, verdict(want))
	}
	if err == nil && !bytes.Equal(plain, p.payload) {
		tc.Errorf("committing sequence %d gave back %x, want %x", p.seq, plain, p.payload)
	}
}

// RuleAuthenticate seals one packet and authenticates it on its own.
func (m *replayMachine) RuleAuthenticate(tc hegel.TestCase) {
	seq := m.drawSequence(tc)
	packet, payload := m.seal(tc, seq)
	var authenticated *AuthenticatedPacket
	var err error
	guard(tc, func() { authenticated, err = m.in.Authenticate(packet) })
	if want := m.accepts(seq); (err == nil) != want {
		tc.Errorf("authenticating sequence %d with %d the highest committed gave %v, and the model %s it",
			seq, m.model.last, err, verdict(want))
	}
	if err == nil {
		m.pending = append(m.pending, pendingPacket{seq, payload, authenticated})
	}
}

// RuleAuthenticateBatch authenticates several packets under one lock, as a
// receive worker does. Each is checked against the same window, so two
// packets carrying one number both pass here and only one of them may commit.
func (m *replayMachine) RuleAuthenticateBatch(tc hegel.TestCase) {
	count := hegel.Draw(tc, hegel.Integers(1, 4))
	seqs := make([]uint32, count)
	payloads := make([][]byte, count)
	packets := make([][]byte, count)
	for i := range count {
		seqs[i] = m.drawSequence(tc)
		packets[i], payloads[i] = m.seal(tc, seqs[i])
	}
	var results []AuthenticatedPacket
	guard(tc, func() { results = m.in.AuthenticateBatchInPlace(packets, nil) })
	for i := range results {
		err := results[i].Err
		if want := m.accepts(seqs[i]); (err == nil) != want {
			tc.Errorf("authenticating sequence %d in a batch with %d the highest committed gave %v, and the model %s it",
				seqs[i], m.model.last, err, verdict(want))
		}
		if err == nil {
			m.pending = append(m.pending, pendingPacket{seqs[i], payloads[i], &results[i]})
		}
	}
}

// RuleCommit commits one waiting packet, chosen in any order. The second
// check sees everything that committed since the first.
func (m *replayMachine) RuleCommit(tc hegel.TestCase) {
	tc.Assume(len(m.pending) > 0)
	i := hegel.Draw(tc, hegel.Integers(0, len(m.pending)-1))
	p := m.pending[i]
	m.pending = slices.Delete(m.pending, i, i+1)
	want := m.accepts(p.seq)
	var plain []byte
	var err error
	guard(tc, func() { plain, _, err = p.packet.Commit() })
	m.judgeCommit(tc, p, want, plain, err)
	if want {
		m.record(p.seq)
	}
	m.committed = append(m.committed, p.packet)
}

// RuleCommitBatch commits the oldest waiting packets in one CommitBatch, in
// the order they authenticated, as the ordered emitter does.
func (m *replayMachine) RuleCommitBatch(tc hegel.TestCase) {
	tc.Assume(len(m.pending) > 0)
	count := hegel.Draw(tc, hegel.Integers(1, len(m.pending)))
	batch := make([]AuthenticatedPacket, count)
	for i := range batch {
		batch[i] = *m.pending[i].packet
	}
	guard(tc, func() { CommitBatch(batch) })
	for i := range batch {
		p := m.pending[i]
		want := m.accepts(p.seq)
		var plain []byte
		var err error
		guard(tc, func() { plain, _, err = batch[i].Plaintext() })
		m.judgeCommit(tc, p, want, plain, err)
		if want {
			m.record(p.seq)
		}
		m.committed = append(m.committed, &batch[i])
	}
	m.pending = m.pending[count:]
}

// RuleOpen is the single packet path, which checks and commits in one call.
func (m *replayMachine) RuleOpen(tc hegel.TestCase) {
	seq := m.drawSequence(tc)
	packet, payload := m.seal(tc, seq)
	want := m.accepts(seq)
	var plain []byte
	var err error
	guard(tc, func() { plain, _, err = m.in.Open(packet) })
	m.judgeCommit(tc, pendingPacket{seq: seq, payload: payload}, want, plain, err)
	if want {
		m.record(seq)
	}
}

// RuleCommitAgain commits a packet a commit has already seen. Whatever the
// first commit said, the second is refused and moves nothing, which the
// invariant then holds the window to.
func (m *replayMachine) RuleCommitAgain(tc hegel.TestCase) {
	tc.Assume(len(m.committed) > 0)
	p := m.committed[hegel.Draw(tc, hegel.Integers(0, len(m.committed)-1))]
	var plain []byte
	var err error
	guard(tc, func() { plain, _, err = p.Commit() })
	if err == nil {
		tc.Errorf("a packet committed twice, the second time giving back %x", plain)
	}
}

// InvariantWindowAgreesWithModel asks the window, without authenticating
// anything, about every number sealed so far and the numbers around both of
// its edges, and compares each answer with the model's.
func (m *replayMachine) InvariantWindowAgreesWithModel(tc hegel.TestCase) {
	highest, window := int64(m.model.last), int64(m.window)
	probes := slices.Clone(m.sealed)
	for _, edge := range []int64{0, highest, highest - window, highest + window} {
		for offset := int64(-2); offset <= 2; offset++ {
			probes = append(probes, uint32(min(max(edge+offset, 0), math.MaxUint32)))
		}
	}
	m.in.mu.Lock()
	defer m.in.mu.Unlock()
	for _, seq := range probes {
		var got bool
		guard(tc, func() { got = m.in.window.check(seq) == nil })
		if want := m.accepts(seq); got != want {
			tc.Errorf("the window %s sequence %d with %d the highest committed, and the model %s it",
				verdict(got), seq, m.model.last, verdict(want))
		}
	}
}

// replayWindows are the widths the machine runs at: zero, which turns the
// check off, the narrowest windows, where every jump wraps the circular
// index, the sizes either side of a word of the bitmap, the default and the
// widest a node may configure.
var replayWindows = []uint32{0, 1, 2, 3, 63, 64, 65, 128, DefaultReplayWindow, MaxReplayWindow}

// The anti-replay window agrees with the RFC 4303 section 3.4.3 model, the
// highest number committed and the set of numbers seen within the window
// behind it, at every step of any interleaving of authentications and
// commits, at widths from zero, which turns the check off, to the widest a
// node can be configured with. A window that took a number the model refuses
// would let a captured packet be delivered twice, and one that refused a
// number the model takes would drop traffic a peer sent once, under exactly
// the reordering the wide default exists for.
func TestReplayWindowAgreesWithItsModel(t *testing.T) {
	t.Cleanup(settle)
	pbt.Check(t, func(ht *hegel.T) {
		window := hegel.Draw(ht, hegel.SampledFrom(replayWindows))
		child := testChild(ht.T)
		child.LocalSPI, child.InboundKey = child.RemoteSPI, child.OutboundKey
		out, err := NewOutbound(child)
		if err != nil {
			ht.Fatal(err)
		}
		// the default width is the one NewInbound builds when given no option
		var options []InboundOption
		if window != DefaultReplayWindow {
			options = append(options, WithReplayWindow(window))
		}
		in, err := NewInbound(child, options...)
		if err != nil {
			ht.Fatal(err)
		}
		hegel.RunStateful(ht, &replayMachine{
			out: out, in: in, window: window,
			model: &referenceWindow{window: window, seen: map[uint32]bool{}},
		}, hegel.WithAlwaysCheckInvariants("InvariantWindowAgreesWithModel"))
	})
}
