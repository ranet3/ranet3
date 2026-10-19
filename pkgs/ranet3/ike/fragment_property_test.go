// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"maps"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// drawSealing draws one of the AEAD suites an IKE SA runs and a key of its length
func drawSealing(ht *hegel.T) (SASuite, []byte) {
	drawn := hegel.Draw(ht, hegel.SampledFrom(skSuites))
	suite := SASuite{EncrID: drawn.id, EncrKeyBits: drawn.bits}
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		ht.Fatal(err)
	}
	return suite, hegel.Draw(ht, hegel.Binary(params.KeyLen+params.SaltLen, params.KeyLen+params.SaltLen))
}

// drawInner draws the inner payloads of a message, up to an ML-KEM-1024 KE payload's length among them so one spans many fragments
func drawInner(ht *hegel.T) []RawPayload {
	inner := drawPayloads(ht, chainTypes, 4)
	if hegel.Draw(ht, hegel.Booleans()) {
		inner = append(inner, RawPayload{Type: PayloadKE, Body: drawBytes(ht, 1572, 1092)})
	}
	return inner
}

// drawOutbound draws a message this end seals under an IKE SA, with any header and inner payloads, and its key
func drawOutbound(ht *hegel.T) (*outbound, []byte) {
	suite, key := drawSealing(ht)
	o, err := (&ikeContext{suite: suite}).seal(key, drawHeader(ht), drawInner(ht))
	if err != nil {
		ht.Fatalf("seal refused %+v: %v", suite, err)
	}
	return o, key
}

// drawRoom draws the octets of IKE message a datagram carries, from the least that holds one octet of the message's plaintext in a fragment to enough for all of it
// where held holds, the least is that whose fragments a receiver holds together under reassemblyLimit
func drawRoom(ht *hegel.T, o *outbound, held bool) int {
	around := len(o.whole) - len(o.inner) + 4
	least := around + 1
	if held {
		most := (reassemblyLimit - 1 - len(o.inner)) / around
		least = around + max(1, (len(o.inner)+most-1)/most)
	}
	return hegel.Draw(ht, pbt.Spanning(least, around+len(o.inner)+1))
}

// for any message this end seals and any room a threshold leaves, the IKE Fragment messages each fit the room and carry the message's header but for Length and Next Payload, and one Encrypted Fragment payload alone
// their Fragment Numbers run from 1 to a Total Fragments the same in each and never zero, fragment 1 names the first inner payload and the rest zero, and their contents in order are the message's plaintext
// the octets the message counts its fragments at are those they carry
// RFC 7383 section 2.5: "When prepending the IKE header to the IKE Fragment messages, it MUST be taken intact from the original message, except for the Length and Next Payload fields."
// RFC 7383 section 2.5: "As is the case for the Encrypted payload, the Encrypted Fragment payload, if present in a message, MUST be the last payload in the message."
// RFC 7383 section 2.5.3: "all unprotected payloads MUST be placed in the first fragment (with the Fragment Number field equal to 1), along with the Encrypted Fragment payload, which MUST be present in every IKE Fragment message and be the last payload in it."
// this end sends no unprotected payload after IKE_SA_INIT, so each IKE Fragment message carries the Encrypted Fragment payload alone
func TestFragmentsKeepTheHeaderAndCarryTheirEncryptedFragmentPayloadLast(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		o, key := drawOutbound(ht)
		room := drawRoom(ht, o, false)
		size := o.capacity(room)
		datagrams, err := o.fragments(size)
		if err != nil {
			ht.Fatalf("a message of %d octets was not cut into fragments of %d: %v", len(o.inner), size, err)
		}
		if want := max(1, (len(o.inner)+size-1)/size); len(datagrams) != want || o.total(size) != want {
			ht.Fatalf("a message of %d octets in fragments of %d took %d of them and is counted in %d, want %d", len(o.inner), size, len(datagrams), o.total(size), want)
		}
		if counted := o.octets(size); counted != octetsOf(datagrams) {
			ht.Fatalf("a message of %d octets in fragments of %d is counted as %d octets, and its fragments carry %d", len(o.inner), size, counted, octetsOf(datagrams))
		}
		var content []byte
		for i, raw := range datagrams {
			number := uint16(i + 1)
			if len(raw) > room {
				ht.Fatalf("fragment %d of %d octets is past the room of %d", number, len(raw), room)
			}
			m, err := DecodeMessage(raw)
			if err != nil {
				ht.Fatalf("fragment %d does not decode: %v", number, err)
			}
			if !bytes.Equal(raw[:16], o.whole[:16]) || !bytes.Equal(raw[17:24], o.whole[17:24]) || m.Header.NextPayload != PayloadSKF || m.Header.Length != uint32(len(raw)) {
				ht.Fatalf("fragment %d has header %x, want the message's %x with Next Payload SKF and its own Length", number, raw[:HeaderLen], o.whole[:HeaderLen])
			}
			if len(m.Payloads) != 1 || m.Payloads[0].Type != PayloadSKF || m.skHeaderOffset != HeaderLen {
				ht.Fatalf("fragment %d carries payload types %v, want the Encrypted Fragment payload alone", number, payloadTypes(m.Payloads))
			}
			// RFC 7383 section 2.5: "in the very first fragment (with Fragment Number equal to 1), this field MUST be set to the payload type of the first inner payload (the same as for the Encrypted payload)."
			// and: "In the rest of the Fragment messages (with Fragment Number greater than 1), this field MUST be set to zero."
			next := PayloadNone
			if number == 1 {
				next = o.first
			}
			// RFC 7383 section 2.5 of Fragment Number: "This field MUST be less than or equal to the next field (Total Fragments).  This field MUST NOT be zero."
			// and of Total Fragments: "This field MUST NOT be zero."
			if got, total := fragmentNumbers(m); raw[HeaderLen] != byte(next) || got != number || total != uint16(len(datagrams)) {
				ht.Fatalf("fragment %d names %d and is number %d of %d, want %d, %d of %d", number, raw[HeaderLen], got, total, next, number, len(datagrams))
			}
			plain, err := openFragment(o.ctx.suite, key, raw, HeaderLen)
			if err != nil {
				ht.Fatalf("fragment %d does not open under the key: %v", number, err)
			}
			chunk, err := unpadded(plain)
			if err != nil || len(chunk) > size {
				ht.Fatalf("fragment %d carries %d octets of plaintext (%v), want at most %d", number, len(chunk), err, size)
			}
			content = append(content, chunk...)
		}
		if !bytes.Equal(content, o.inner) {
			ht.Fatalf("the fragments carry %x, want the message's plaintext %x", content, o.inner)
		}
	})
}

// a message cut into fragments for any room whose fragments a receiver holds under reassemblyLimit, taken in any order past duplicates of the fragments already taken, is the message once its last fragment arrives and not before
// a repeat of any fragment after that draws the response again for fragment 1 alone
// RFC 7383 section 2.6: "When all IKE Fragment messages (as indicated in the Total Fragments field) are received, the decrypted content of all Encrypted Fragment payloads is merged together to form the content of the original Encrypted payload and, therefore, along with the IKE header and unprotected payloads (if any), the original message."
// RFC 7383 section 2.6.1: "If the responder receives a retransmitted fragment of a request when it has already processed that request and has sent back a response, that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
func TestSplitMessageReassemblesInAnyOrderPastDuplicates(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		o, key := drawOutbound(ht)
		datagrams, err := o.fragments(o.capacity(drawRoom(ht, o, true)))
		if err != nil {
			ht.Fatal(err)
		}
		messages := make([]*Message, len(datagrams))
		for i, raw := range datagrams {
			if messages[i], err = DecodeMessage(raw); err != nil {
				ht.Fatal(err)
			}
		}
		var q reassembly
		now := time.Now()
		unsent := make([]int, len(datagrams))
		for i := range unsent {
			unsent[i] = i
		}
		var sent []int
		var delivered *opened
		for len(unsent) > 0 {
			var i int
			if len(sent) > 0 && hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
				i = sent[hegel.Draw(ht, pbt.Spanning(0, len(sent)-1))]
			} else {
				at := hegel.Draw(ht, pbt.Spanning(0, len(unsent)-1))
				i = unsent[at]
				unsent = slices.Delete(unsent, at, at+1)
				sent = append(sent, i)
			}
			got, err := q.take(o.ctx.suite, key, datagrams[i], messages[i], now)
			if err != nil {
				ht.Fatalf("fragment %d of %d was refused: %v", i+1, len(datagrams), err)
			}
			if got != nil && (len(unsent) > 0 || delivered != nil) {
				ht.Fatalf("fragment %d of %d made a message with %d fragments unsent", i+1, len(datagrams), len(unsent))
			}
			if got != nil {
				delivered = got
			}
		}
		if delivered == nil {
			ht.Fatalf("all %d fragments made no message", len(datagrams))
		}
		header := o.header
		header.NextPayload, header.Length = PayloadSK, uint32(HeaderLen+genericPayloadHeaderLen+len(o.inner))
		if delivered.outer.Header != header || delivered.innerFirst != o.first || !bytes.Equal(delivered.plaintext, append(slices.Clone(o.inner), 0)) || int(delivered.total) != len(datagrams) {
			ht.Fatalf("the fragments made header %+v naming %d with plaintext %x in %d fragments, want %+v naming %d with %x in %d", delivered.outer.Header, delivered.innerFirst, delivered.plaintext, delivered.total, header, o.first, o.inner, len(datagrams))
		}
		s := &Session{fragments: true}
		for i, raw := range datagrams {
			if again := s.asksAgain(o.ctx.suite, key, raw, messages[i], delivered.total); again != (i == 0) {
				ht.Fatalf("a repeat of fragment %d of %d draws the response %v, want %v", i+1, len(datagrams), again, i == 0)
			}
		}
	})
}

// IntAuth's chunk of a message reassembled from fragments taken in any order is that of the message whole, whose Encrypted payload header has fragment 1's C bit and RESERVED, with the unprotected payloads of fragment 1
// the other fragments' octet of the C bit and RESERVED and any unprotected payloads they carry count for nothing
// RFC 9242 section 3.3.2: "If the message was received in fragmented form, it MUST be reconstructed before calculating the prf as if it were received unfragmented."
// RFC 9242 section 3.3.2: "While reconstructing, the RESERVED field in the reconstructed Encrypted payload header MUST be set to the value of the RESERVED field in the Encrypted Fragment payload header from the first fragment (with the Fragment Number field set to 1)."
func TestIntAuthOfAReassembledMessageIsThatOfTheMessageWhole(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		suite, key := drawSealing(ht)
		header := drawHeader(ht)
		cleartext := drawPayloads(ht, chainTypes, 2)
		payloads := drawInner(ht)
		inner := encodePayloadChain(payloads)
		first := PayloadNone
		if len(payloads) > 0 {
			first = payloads[0].Type
		}
		flags := drawOctet[byte](ht, 0x80, 0x7f)
		total := hegel.Draw(ht, pbt.Spanning(1, 8))
		size := max(1, (len(inner)+total-1)/total)
		datagrams := make([][]byte, total)
		for i := range datagrams {
			next, octet, before := first, flags, cleartext
			if i > 0 {
				next, octet, before = PayloadNone, drawOctet[byte](ht), drawPayloads(ht, chainTypes, 1)
			}
			chunk := inner[min(i*size, len(inner)):min((i+1)*size, len(inner))]
			raw, err := sealedFragment(suite, key, header, before, next, octet, uint16(i+1), uint16(total), chunk)
			if err != nil {
				ht.Fatal(err)
			}
			datagrams[i] = raw
		}
		var q reassembly
		var delivered *opened
		for _, at := range drawOrder(ht, total) {
			m, err := DecodeMessage(datagrams[at])
			if err != nil {
				ht.Fatal(err)
			}
			got, err := q.take(suite, key, datagrams[at], m, time.Now())
			if err != nil {
				ht.Fatal(err)
			}
			if got != nil {
				delivered = got
			}
		}
		if delivered == nil {
			ht.Fatalf("the %d fragments made no message", total)
		}
		whole, err := sealMessage(suite, key, header, cleartext, PayloadSK, []byte{byte(first), flags, 0, 0}, append(slices.Clone(inner), 0), make([]byte, 8))
		if err != nil {
			ht.Fatal(err)
		}
		m, err := DecodeMessage(whole)
		if err != nil {
			ht.Fatal(err)
		}
		plaintext, err := unpadded(delivered.plaintext)
		if err != nil {
			ht.Fatal(err)
		}
		got, err := intAuthChunk(delivered.raw, delivered.outer.skHeaderOffset, plaintext)
		if err != nil {
			ht.Fatal(err)
		}
		if want := modelChunk(whole, m.skHeaderOffset, inner); !bytes.Equal(got, want) {
			ht.Fatalf("IntAuth's chunk of the reassembled message is %x, want the whole message's %x", got, want)
		}
		if !samePayloads(delivered.outer.Payloads[:len(delivered.outer.Payloads)-1], cleartext) {
			ht.Fatalf("the reassembled message carries unprotected payloads %+v, want fragment 1's %+v", delivered.outer.Payloads, cleartext)
		}
	})
}

// drawOrder draws an order to take n fragments in
func drawOrder(ht *hegel.T, n int) []int {
	left := make([]int, n)
	for i := range left {
		left[i] = i
	}
	order := make([]int, 0, n)
	for len(left) > 0 {
		at := hegel.Draw(ht, pbt.Spanning(0, len(left)-1))
		order = append(order, left[at])
		left = slices.Delete(left, at, at+1)
	}
	return order
}

// queueModel is the reassembly queue as RFC 7383 sections 2.4, 2.6 and 5 and the limits of this end describe it
// largest is the octets of the largest datagram it holds, and foreign whether one it holds carries other content than its message's
type queueModel struct {
	held      bool
	messageID uint32
	total     uint16
	started   time.Time
	octets    int
	largest   int
	foreign   bool
	stored    map[uint16]bool
}

// modelFragment is one IKE Fragment message the model takes, its datagram of octets, carrying other content than its message's where foreign holds
type modelFragment struct {
	messageID     uint32
	number, total uint16
	octets        int
	authentic     bool
	negotiated    bool
	foreign       bool
}

// queueOutcome is how the queue takes one fragment
type queueOutcome string

const (
	discarded queueOutcome = "discarded"
	kept      queueOutcome = "kept"
	delivered queueOutcome = "delivered"
	refused   queueOutcome = "refused at the limit"
)

// take is the model's answer to f arriving at now, and the queue as it stood full where f made its message
func (m *queueModel) take(f modelFragment, now time.Time) (queueOutcome, queueModel) {
	// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
	if !f.negotiated {
		return discarded, queueModel{}
	}
	// RFC 7383 section 2.6: "If the receiver does not get all IKE fragments needed to reassemble the original message within a timeout interval, it MUST discard all IKE Fragment messages received so far for the exchange."
	if m.held && (!now.Before(m.started.Add(reassemblyTimeout)) || f.messageID != m.messageID) {
		*m = queueModel{}
	}
	// RFC 7383 section 2.6: "If any of these tests fail, the message MUST be silently discarded."
	if f.number == 0 || f.total == 0 || f.number > f.total || m.held && f.total < m.total {
		return discarded, queueModel{}
	}
	// RFC 7383 section 2.6: "If an IKE Fragment message with the same Message ID, Fragment Number, and Total Fragments fields is already present in the reassembling queue, this message is considered a replay and MUST be silently discarded."
	if m.held && m.stored[f.number] && f.total == m.total {
		return discarded, queueModel{}
	}
	// RFC 7383 section 2.6: "If the ICV check fails, the message MUST be silently discarded."
	if !f.authentic {
		return discarded, queueModel{}
	}
	// RFC 7383 section 2.6: "the receiver MUST discard all received fragments and start the reassembly process over with just the received IKE Fragment message."
	if m.held && f.total > m.total {
		*m = queueModel{}
	}
	// RFC 7383 section 5: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
	if m.octets+f.octets >= reassemblyLimit {
		*m = queueModel{}
		return refused, queueModel{}
	}
	if !m.held {
		*m = queueModel{held: true, messageID: f.messageID, total: f.total, started: now, stored: map[uint16]bool{}}
	}
	m.stored[f.number] = true
	m.octets, m.largest, m.foreign = m.octets+f.octets, max(m.largest, f.octets), m.foreign || f.foreign
	if len(m.stored) == int(m.total) {
		full := *m
		*m = queueModel{}
		return delivered, full
	}
	return kept, queueModel{}
}

// fragmentKinds are the IKE Fragment messages the queue's property draws, each drawn outright
var fragmentKinds = []string{
	"next missing", "any of the cut", "replayed", "larger Total", "smaller Total", "bad ICV",
	"zero Fragment Number", "zero Total Fragments", "Fragment Number past Total", "other Message ID",
	"past the timeout", "not negotiated", "to the limit",
}

// over drawn IKE Fragment messages of two messages at adjacent Message IDs, of contents up to past the limit in one fragment, the queue discards, keeps and delivers as its model does, and holds what the model holds after each
// a fragment that starts the queue over in a datagram one octet short of the limit or at it is drawn outright
// a fragment from a peer that did not negotiate fragments is discarded before the queue holds anything of it
func TestReassemblyQueueTakesFragmentsAsItsModelDoes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		suite, key := drawSealing(ht)
		ctx := &ikeContext{suite: suite, responder: true, skei: key}
		s := &Session{fragments: true}
		header := drawHeader(ht)
		header.MessageID = min(header.MessageID, 1<<32-2)
		var contents [2][]byte
		var firsts [2]PayloadType
		for i := range contents {
			contents[i] = drawBytes(ht, 3*reassemblyLimit/2, reassemblyLimit)
			firsts[i] = drawOctet[PayloadType](ht)
		}
		chunk := func(message int, number, total uint16) []byte {
			content := contents[message]
			if number == 0 || number > total {
				return nil
			}
			size := (len(content) + int(total) - 1) / int(total)
			return content[min(int(number-1)*size, len(content)):min(int(number)*size, len(content))]
		}
		var q reassembly
		var model queueModel
		now := time.Now()
		for range hegel.Draw(ht, pbt.Spanning(1, 24)) {
			kind := hegel.Draw(ht, hegel.SampledFrom(fragmentKinds))
			message := 0
			if model.held && model.messageID != header.MessageID {
				message = 1
			}
			total := model.total
			if !model.held {
				total = uint16(hegel.Draw(ht, pbt.Spanning(1, 6)))
			}
			missing := uint16(1)
			for model.stored[missing] {
				missing++
			}
			number := missing
			f := modelFragment{authentic: true, negotiated: true}
			switch kind {
			case "any of the cut":
				number = uint16(hegel.Draw(ht, pbt.Spanning(1, int(total))))
			case "replayed":
				if stored := slices.Sorted(maps.Keys(model.stored)); len(stored) > 0 {
					number = stored[hegel.Draw(ht, pbt.Spanning(0, len(stored)-1))]
				}
			case "larger Total":
				total += uint16(hegel.Draw(ht, pbt.Spanning(1, 3)))
				number = uint16(hegel.Draw(ht, pbt.Spanning(1, int(total))))
			case "smaller Total":
				total = max(1, total-1)
				number = uint16(hegel.Draw(ht, pbt.Spanning(1, int(total))))
			case "bad ICV":
				f.authentic = false
			case "zero Fragment Number":
				number = 0
			case "zero Total Fragments":
				number, total = 1, 0
			case "Fragment Number past Total":
				number = total + 1
			case "other Message ID":
				message = 1 - message
				total, number = uint16(hegel.Draw(ht, pbt.Spanning(1, 6))), 1
			case "past the timeout":
				now = now.Add(reassemblyTimeout)
			case "not negotiated":
				f.negotiated = false
			case "to the limit":
				total, number = total+1, 1
			}
			at := header
			at.MessageID += uint32(message)
			next := PayloadNone
			if number == 1 {
				next = firsts[message]
			}
			content := chunk(message, number, total)
			if kind == "to the limit" {
				empty, err := sealedFragment(suite, key, at, nil, next, 0, number, total, nil)
				if err != nil {
					ht.Fatal(err)
				}
				content = make([]byte, reassemblyLimit+hegel.Draw(ht, pbt.Spanning(-1, 0))-len(empty))
			}
			raw, err := sealedFragment(suite, key, at, nil, next, 0, number, total, content)
			if err != nil {
				ht.Fatal(err)
			}
			if !f.authentic {
				raw[len(raw)-1] ^= 1
			}
			f.messageID, f.number, f.total, f.octets = at.MessageID, number, total, len(raw)
			m, err := DecodeMessage(raw)
			if err != nil {
				ht.Fatal(err)
			}
			want, _ := model.take(f, now)
			var got *opened
			if f.negotiated {
				got, err = q.take(suite, key, raw, m, now)
			} else {
				s.fragments = false
				got, err = s.open(ctx, &q, raw, m)
				s.fragments = true
			}
			switch want {
			case delivered:
				if err != nil || got == nil || !bytes.Equal(got.plaintext, append(slices.Clone(contents[message]), 0)) || got.innerFirst != firsts[message] || got.outer.Header.MessageID != at.MessageID {
					ht.Fatalf("a %s fragment %d of %d at Message ID %d delivered %v (%v), want message %d naming %d", kind, number, total, at.MessageID, got != nil, err, message, firsts[message])
				}
			case refused:
				if err != errFragmentLimit || got != nil {
					ht.Fatalf("a %s fragment %d of %d at Message ID %d delivered %v (%v), want the limit's refusal", kind, number, total, at.MessageID, got != nil, err)
				}
			default:
				if err != nil || got != nil {
					ht.Fatalf("a %s fragment %d of %d at Message ID %d delivered %v (%v), want it %s", kind, number, total, at.MessageID, got != nil, err, want)
				}
			}
			if !queueHolds(&q, &model) {
				ht.Fatalf("after a %s fragment %d of %d the queue holds Message ID %d, %d of %d fragments in %d octets, want %+v", kind, number, total, q.messageID, len(q.chunks), q.total, q.held, model)
			}
		}
	})
}

// queueHolds reports whether q holds what the model holds
func queueHolds(q *reassembly, model *queueModel) bool {
	if !model.held {
		return q.chunks == nil && q.held == 0
	}
	return q.chunks != nil && q.messageID == model.messageID && q.total == model.total && q.held == model.octets && q.largest == model.largest &&
		len(q.chunks) == len(model.stored) && !slices.ContainsFunc(slices.Collect(maps.Keys(q.chunks)), func(number uint16) bool { return !model.stored[number] })
}
