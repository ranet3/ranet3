// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/transport"
)

const (
	// wholeAround is the octets of IKE message an AEAD suite's message whole carries past its plaintext, the IKE header, the Encrypted payload's header, an IV of 8 octets, the Pad Length and an ICV of 16
	wholeAround = HeaderLen + genericPayloadHeaderLen + 8 + 1 + 16
	// fragmentAround is those of an IKE Fragment message, which carries Fragment Number and Total Fragments too
	fragmentAround = wholeAround + 4
	// v4Around and v6Around are the octets each datagram to or from a place of that family carries past its IKE message: an IP header without options, the UDP header and the non-ESP marker
	v4Around = 20 + 8 + NonESPMarkerLen
	v6Around = 40 + 8 + NonESPMarkerLen
)

// answerModel is an answer as the repeat property's model has it, inner octets of plaintext whole, or in total fragments of chunk octets each but the last
type answerModel struct {
	inner, total, chunk int
}

// largest is the octets of IKE message the answer's largest datagram carries
func (m answerModel) largest() int {
	if m.total == 0 {
		return wholeAround + m.inner
	}
	return fragmentAround + min(m.chunk, m.inner)
}

// octets is the octets of IKE message all of the answer's datagrams carry
func (m answerModel) octets() int {
	if m.total == 0 {
		return wholeAround + m.inner
	}
	return m.total*fragmentAround + m.inner
}

// wire is the octets the answer's datagrams take on the wire to a place whose datagrams carry around octets past their IKE message
func (m answerModel) wire(around int) int {
	return m.octets() + max(1, m.total)*around
}

// cutTo is the answer in fragments of chunk octets of plaintext each
func (m answerModel) cutTo(chunk int) answerModel {
	return answerModel{inner: m.inner, total: max(1, (m.inner+chunk-1)/chunk), chunk: chunk}
}

// firstAnswer is the answer of inner octets to a request that came as request, on a path whose datagram carries room octets of IKE message
// it goes whole unless both ends negotiated fragments, and then in fragments where it does not fit or the request came so, within the request's largest datagram where the path is wider but never under the floor's
func firstAnswer(inner int, negotiated bool, room int, request form) answerModel {
	m := answerModel{inner: inner}
	if !negotiated {
		return m
	}
	if bound := max(request.largest, floorRoom); request.total > 0 && bound < room {
		room = bound
	}
	if request.total == 0 && m.largest() <= room {
		return m
	}
	return m.cutTo(room - fragmentAround)
}

// again is the answer m as a repeat whose largest datagram carried fit octets of IKE message draws it, fit zero for a repeat whole
// it goes as it stands where its datagrams fit within fit, or within the floor's where fit is smaller, and is otherwise cut within that into more fragments than it went in
func (m answerModel) again(negotiated bool, room, fit int) answerModel {
	bound := max(fit, floorRoom)
	if !negotiated || fit == 0 || bound >= room || m.largest() <= bound {
		return m
	}
	chunk := bound - fragmentAround
	if m.total > 0 {
		chunk = min(chunk, m.inner/(m.total+1))
	}
	if chunk <= 0 {
		return m
	}
	return m.cutTo(chunk)
}

// repeatRequest is a request of the repeat property, a KE payload at mid under key, whole and cut where the ends negotiated fragments, and the octets of the KE payload its answer carries
type repeatRequest struct {
	mid     uint32
	key     []byte
	inner   []RawPayload
	content []byte
	whole   []byte
	cut     [][]byte
	answer  int
}

// repeatDatagram is a datagram the repeat property sends, as the model reads it
// whole is a message whole and exact one bitwise the request as it came, number and total its Fragment Number and Total Fragments otherwise, and foreign that it carries other content than its message's
type repeatDatagram struct {
	whole, exact       bool
	number, total      uint16
	authentic, foreign bool
}

// repeatSite is one of the sites that resend a kept answer as the repeat property drives it, the half-open wait or one of takers, the session's answered request and queue and the model's of them
// places are the addresses repeats come from, the first the origin, conns the sockets behind them, which read what each address took, and around the octets each of their datagrams carries past its IKE message
type repeatSite struct {
	ht         *hegel.T
	site       string
	s          *Session
	places     []transport.Endpoint
	conns      []*transport.MemoryConn
	around     int
	negotiated bool
	room       int
	now        time.Time
	// queue is the model's of the queue the SA gathers the peer's requests in
	queue queueModel
	// r is the answered request, came its octets where it came whole, and form how it came as the model reads it
	r    *repeatRequest
	came []byte
	form form
	// inner is the answer's plaintext, or its octets at initSite and waitSite, answer the model's answer and went the datagrams it last went in
	inner  []byte
	answer answerModel
	went   [][]byte
	// answers is the repeats from the origin answered in the exchange, others the credits of the places other than the origin in the order the session keeps them, arrivals the datagrams those took, and last the place other than the origin a repeat last came from, as the model has them
	// sent and drawn are the octets on the wire each place sent at the answered Message ID and drew in the exchange
	answers, arrivals, last int
	others                  []creditModel
	sent, drawn             []int
	// at waitSite, waited closes once awaitAuthRequest returned waitErr, hubPort is the port the wait is reached at, and forgotten holds once it answered the IKE_INTERMEDIATE request
	waited    chan struct{}
	waitErr   error
	hubPort   int
	forgotten bool
}

// creditModel is the model's of the credit an exchange keeps for places[place]: the octets on the wire its repeats sent that answers there have not spent, the repeat it gathers, and the arrival of its last datagram
type creditModel struct {
	place, octets, last int
	queue               queueModel
}

// begin answers request, which came as r did, whole where whole holds, and starts the exchange's repeats
// the half-open wait keeps the answer as awaitAuthRequest does, and the sites past IKE_AUTH through keepAnswer, which moves the peer's window past it
func (h *repeatSite) begin(request *opened, r *repeatRequest, whole bool) {
	h.r, h.came, h.form = r, r.whole, form{}
	if !whole {
		h.came, h.form = nil, form{total: uint16(len(r.cut)), largest: largest(r.cut)}
	}
	if request.form != h.form {
		h.ht.Fatalf("the request at %d came as %+v, want %+v", r.mid, request.form, h.form)
	}
	ctx := h.s.current
	response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagResponse, MessageID: r.mid}, []RawPayload{{Type: PayloadKE, Body: make([]byte, r.answer)}})
	if err != nil {
		h.ht.Fatal(err)
	}
	var sent *transmission
	if h.site == halfOpenSite {
		if sent, err = h.s.transmit(response, request.form); err == nil {
			err = ctx.lastPeer.answered(request, r.key, sent)
		}
	} else {
		sent, err = h.s.keepAnswer(ctx, r.mid, response, request)
	}
	if err != nil {
		h.ht.Fatal(err)
	}
	h.inner, h.answer = response.inner, firstAnswer(len(response.inner), h.negotiated, h.room, h.form)
	h.wantAnswer("the first answer", sent.datagrams)
	h.went = sent.datagrams
	h.answers, h.arrivals, h.last, h.others = 0, 0, 0, nil
	h.sent, h.drawn = make([]int, len(h.places)), make([]int, len(h.places))
}

// wantAnswer fails the case unless datagrams carry the answer in the model's cut
func (h *repeatSite) wantAnswer(what string, datagrams [][]byte) {
	same := bytes.Equal(carried(h.s.current.localEncryptionKey(), datagrams), h.inner)
	if h.site == initSite || h.site == waitSite {
		same = len(datagrams) == 1 && bytes.Equal(datagrams[0], h.inner)
	}
	if len(datagrams) != max(1, h.answer.total) || largest(datagrams) != h.answer.largest() || octetsOf(datagrams) != h.answer.octets() || !same {
		h.ht.Fatalf("%s at %d went in %d datagrams of at most %d octets, %d in all, want the answer in %d of at most %d, %d in all", what, h.r.mid, len(datagrams), largest(datagrams), octetsOf(datagrams), max(1, h.answer.total), h.answer.largest(), h.answer.octets())
	}
}

// repeat hands raw, a datagram at the answered Message ID from places[place], to the site, to answerRepeat as awaitAuthRequest does in the half-open wait, to answerInitRepeat in its IKE_SA_INIT exchange or to awaitAuthRequest itself, and checks what each place takes against the model
// it reports whether the SA goes on
func (h *repeatSite) repeat(raw []byte, place int, d repeatDatagram) bool {
	source := h.places[place]
	var err error
	ended := false
	switch h.site {
	case initSite:
		err = h.s.answerInitRepeat(&h.s.current.lastPeer.repeatCredits, h.came, h.inner, raw, source)
		ended = err != nil
	case waitSite:
		h.send(raw, place)
	case halfOpenSite:
		if m, decoded := DecodeMessage(raw); decoded == nil {
			err = h.s.answerRepeat(h.s.current, raw, m, source)
			ended = err != nil
		}
	default:
		ended = takers[h.site](h.s, raw, source)
	}
	h.sent[place] += len(raw) + h.around
	was := h.answer
	draws, ends := h.model(len(raw), place, d)
	if ends != ended || err != nil && !errors.Is(err, errFragmentLimit) {
		h.ht.Fatalf("%+v of %d octets from place %d at %d in the %s ended the SA %v with %v, want it ended %v", d, len(raw), place, h.r.mid, h.site, ended, err, ends)
	}
	if ends {
		return false
	}
	want := 0
	if draws {
		want = max(1, h.answer.total)
	}
	took := h.took(place, want)
	back := took[place]
	// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
	for at, got := range took {
		if at != place && len(got) > 0 {
			h.ht.Fatalf("%+v from place %d at %d in the %s sent %d datagrams to place %d", d, place, h.r.mid, h.site, len(got), at)
		}
	}
	switch {
	case draws != (len(back) > 0):
		h.ht.Fatalf("%+v of %d octets from place %d at %d in the %s drew %d datagrams, want the answer %v, with %d answered and the credits %+v", d, len(raw), place, h.r.mid, h.site, len(back), draws, h.answers, h.others)
	case draws:
		h.drawn[place] += octetsOf(back) + len(back)*h.around
		if h.answer == was && !slices.EqualFunc(back, h.went, bytes.Equal) {
			h.ht.Fatalf("%+v of %d octets from place %d at %d drew %d datagrams of at most %d octets, want the answer as it went in %d of at most %d", d, len(raw), place, h.r.mid, len(back), largest(back), len(h.went), largest(h.went))
		}
		h.wantAnswer("the answer drawn again", back)
		h.went = back
	}
	// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
	// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
	if place > 0 && h.drawn[place] > h.sent[place] || place == 0 && draws && !(d.whole && d.exact || d.number == 1 && d.total >= h.form.total) || h.answers > maxRetransmitsWhileBusy {
		h.ht.Fatalf("place %d drew %d octets for the %d it sent at %d, and %d repeats drew the answer, the last %+v", place, h.drawn[place], h.sent[place], h.r.mid, h.answers, d)
	}
	// the wait keeps its queue and the IKE_SA_INIT exchange's credits to itself, so what each place took is all it shows
	if h.site == waitSite {
		return true
	}
	if q := &h.s.current.requestFragments; !queueHolds(q, &h.queue) {
		h.ht.Fatalf("after %+v from place %d at %d the queue holds Message ID %d, %d of %d fragments in %d octets, want %+v", d, place, h.r.mid, q.messageID, len(q.chunks), q.total, q.held, h.queue)
	}
	h.wantCredits(fmt.Sprintf("after %+v from place %d at %d", d, place, h.r.mid))
	return true
}

// wantCredits fails the case unless the session keeps the credits the model keeps, in its order, each for its place with its octets, its last arrival and its repeat
func (h *repeatSite) wantCredits(what string) {
	others := h.s.current.lastPeer.others
	same := len(others) == len(h.others)
	for i := 0; same && i < len(others); i++ {
		c, m := others[i], &h.others[i]
		same = c.from.AddrPort() == h.places[m.place].AddrPort() && c.octets == m.octets && c.last == m.last && queueHolds(&c.repeat, &m.queue)
	}
	if !same {
		var got []string
		for _, c := range others {
			got = append(got, fmt.Sprintf("%s: %d octets, last %d, Message ID %d with %d of %d fragments", c.from, c.octets, c.last, c.repeat.messageID, len(c.repeat.chunks), c.repeat.total))
		}
		h.ht.Fatalf("%s the session keeps the credits %q, want %+v", what, got, h.others)
	}
}

// took is the datagrams each place took since the last call, waiting at place for want of them
// an empty datagram, which no IKE message is, goes to each place after them and bounds what it took
func (h *repeatSite) took(place, want int) [][][]byte {
	got := make([][][]byte, len(h.places))
	buf := make([]byte, 65536)
	for at, conn := range h.conns {
		if err := h.s.mux.SendIKETo(nil, h.places[at]); err != nil {
			h.ht.Fatal(err)
		}
		for marked := false; !marked || at == place && len(got[at]) < want; {
			if err := conn.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
				h.ht.Fatal(err)
			}
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				h.ht.Fatalf("place %d took %d datagrams, want %d, and the empty one after them %v, within %v: %v", at, len(got[at]), want, marked, answerBudget, err)
			}
			if marked = marked || n == NonESPMarkerLen; n > NonESPMarkerLen {
				got[at] = append(got[at], slices.Clone(buf[NonESPMarkerLen:n]))
			}
		}
	}
	return got
}

// send writes raw from places[place] to the hub awaitAuthRequest waits on, and fails the case where the wait ended once it took the datagram
func (h *repeatSite) send(raw []byte, place int) {
	conn := h.conns[place]
	to := &net.UDPAddr{IP: conn.LocalAddr().(*net.UDPAddr).IP, Port: h.hubPort}
	if _, err := conn.WriteToUDP(withNonESPMarker(raw), to); err != nil {
		h.ht.Fatal(err)
	}
	synctest.Wait()
	select {
	case <-h.waited:
		h.ht.Fatalf("the half-open wait ended on %d octets from place %d: %v", len(raw), place, h.waitErr)
	default:
	}
}

// intermediate sends the IKE_INTERMEDIATE request at Message ID 1 from places[place] to the half-open wait, and fails the case unless its answer goes to that place alone
// the wait then forgets the IKE_SA_INIT answer
func (h *repeatSite) intermediate(place int) {
	ctx := h.s.current
	_, key := modelKEM(h.ht, ML_KEM_768)
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
	raw, err := EncryptMessage(modelSuite, ctx.skei, header, nil, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}})
	if err != nil {
		h.ht.Fatal(err)
	}
	h.send(raw, place)
	for at, got := range h.took(place, 1) {
		if (at == place) != (len(got) > 0) {
			h.ht.Fatalf("the IKE_INTERMEDIATE request from place %d drew %d datagrams at place %d, want its answer there alone", place, len(got), at)
		}
	}
	h.forgotten = true
}

// model takes d, octets of IKE message from places[place] at the answered Message ID, into the model's state
// it reports whether d draws the answer, which the model then holds as it goes, or ends the SA
// a repeat from the origin draws it on its fragment 1 of a Total Fragments other than zero and at least the request's, or as the request whole as it came, at most maxRetransmitsWhileBusy times in the exchange
// one from another place draws it once all of the request came from there, in the fragments of one cut or whole as it came, where that place's credit covers the answer's octets on the wire, and spends nothing of the origin's count
// the credit is the octets on the wire of that place's repeats in the exchange, kept for at most movedCredits places, and the place the IKE_SA_INIT answer went to never needs one
// none draws it once the half-open wait answered the IKE_INTERMEDIATE request
// RFC 7383 section 2.6: "check that the Fragment Number and the Total Fragments fields contain non-zero values"
func (h *repeatSite) model(octets, place int, d repeatDatagram) (draws, ends bool) {
	if h.forgotten || place == 0 && h.answers >= maxRetransmitsWhileBusy {
		return false, false
	}
	var from *creditModel
	fit := 0
	switch {
	case d.whole:
		if !d.exact {
			return false, false
		}
		if place > 0 {
			from = h.account(place, octets+h.around)
		}
	case place == 0:
		if !h.negotiated || d.number != 1 || d.total == 0 || d.total < h.form.total || !d.authentic {
			return false, false
		}
		fit = octets
	default:
		if !h.negotiated || d.total < h.form.total || !d.authentic {
			return false, false
		}
		from = h.account(place, octets+h.around)
		outcome, full := from.queue.take(modelFragment{messageID: h.r.mid, number: d.number, total: d.total, octets: octets, authentic: true, negotiated: true, foreign: d.foreign}, h.now)
		switch {
		case outcome == refused:
			return false, true
		case outcome != delivered || full.foreign:
			return false, false
		}
		fit = full.largest
	}
	next := h.answer.again(h.negotiated, h.room, fit)
	if from == nil {
		h.answers++
	} else {
		if next.wire(h.around) > from.octets {
			return false, false
		}
		from.octets -= next.wire(h.around)
	}
	h.answer = next
	return true, false
}

// account takes octets from places[place] into that place's credit, and returns the credit
// a place new to the exchange while movedCredits credits are kept takes the place of the one whose last datagram arrived least recently
func (h *repeatSite) account(place, octets int) *creditModel {
	h.arrivals, h.last = h.arrivals+1, place
	at := slices.IndexFunc(h.others, func(c creditModel) bool { return c.place == place })
	switch {
	case at >= 0:
	case len(h.others) < movedCredits:
		h.others, at = append(h.others, creditModel{place: place}), len(h.others)
	default:
		at = 0
		for i, c := range h.others {
			if c.last < h.others[at].last {
				at = i
			}
		}
		h.others[at] = creditModel{place: place}
	}
	c := &h.others[at]
	c.octets, c.last = c.octets+octets, h.arrivals
	return c
}

// arrive hands raw, a datagram of the next request, to the queue as every site does, and returns the request once all of it came
func (h *repeatSite) arrive(raw []byte, d repeatDatagram) *opened {
	m, err := DecodeMessage(raw)
	if err != nil {
		h.ht.Fatal(err)
	}
	q := &h.s.current.requestFragments
	got, err := h.s.open(h.s.current, q, raw, m)
	if err != nil {
		h.ht.Fatalf("%+v of the next request ended the SA with %v", d, err)
	}
	made := d.whole
	if !d.whole && h.negotiated {
		outcome, _ := h.queue.take(modelFragment{messageID: m.Header.MessageID, number: d.number, total: d.total, octets: len(raw), authentic: true, negotiated: true}, h.now)
		made = outcome == delivered
	}
	if (got != nil) != made || !queueHolds(q, &h.queue) {
		h.ht.Fatalf("%+v of the next request made it %v, want %v, and the queue holds Message ID %d, %d of %d fragments in %d octets, want %+v", d, got != nil, made, q.messageID, len(q.chunks), q.total, q.held, h.queue)
	}
	return got
}

// requestWhole is the answered request whole under header, the octets it came in where it came whole and the draw takes them, or the request sealed again, and whether it is the request as it came
func (h *repeatSite) requestWhole(header Header) ([]byte, bool) {
	if h.came != nil && hegel.Draw(h.ht, hegel.Booleans()) {
		return h.came, true
	}
	sealed, err := EncryptMessage(modelSuite, h.r.key, header, nil, h.r.inner)
	if err != nil {
		h.ht.Fatal(err)
	}
	return sealed, false
}

// cover sends the answered request as it came, whole or in its cut, from places[place] as often as a credit that place starts needs to cover the answer as the repeat draws it, and reports whether the SA goes on
// a credit the place holds already draws the answer sooner, and a repeat of its own the place's queue gathers can keep the answer from it
func (h *repeatSite) cover(place int) bool {
	came, fit := [][]byte{h.came}, 0
	if h.came == nil {
		came, fit = h.r.cut, largest(h.r.cut)
	}
	each := octetsOf(came) + len(came)*h.around
	for range (h.answer.again(h.negotiated, h.room, fit).wire(h.around) + each - 1) / each {
		for at, raw := range came {
			d := repeatDatagram{whole: true, exact: true}
			if h.came == nil {
				d = repeatDatagram{number: uint16(at + 1), total: uint16(len(came)), authentic: true}
			}
			if !h.repeat(raw, place, d) {
				return false
			}
		}
	}
	return true
}

// carried is the plaintext the message in datagrams carries under key, whole or in IKE Fragment messages in Fragment Number order, and nil where they carry none so
func carried(key []byte, datagrams [][]byte) []byte {
	var content []byte
	for i, raw := range datagrams {
		m, err := DecodeMessage(raw)
		if err != nil {
			return nil
		}
		if !fragment(m) {
			if len(datagrams) != 1 {
				return nil
			}
		} else if number, total := fragmentNumbers(m); int(number) != i+1 || int(total) != len(datagrams) {
			return nil
		}
		_, plain, err := decryptMessagePlaintext(modelSuite, key, raw, m)
		if err != nil {
			return nil
		}
		chunk, err := unpadded(plain)
		if err != nil {
			return nil
		}
		content = append(content, chunk...)
	}
	return content
}

// repeatKinds are the datagrams the repeat property draws, each drawn outright, the last two only while the next request has not come
var repeatKinds = []string{
	"a fragment of a cut", "a cut in any order", "a cut just under the answer's datagrams", "the request whole", "a fragment that does not authenticate",
	"a fragment of other content", "a fragment to the limit", "a fragment of the next request", "the next request whole",
}

// over two IKE_INTERMEDIATE exchanges of a half-open SA, with fragmentation negotiated or not, a path of the IPv4 floor, 1280, 1500 or the host's, and each request whole or cut into up to six fragments, repeats of each request draw the answer as the model draws it
// the repeats come from the origin, the address and port the IKE SA was set up from, or five others, as fragments of any cut in any order, the cut just under the answer's datagrams, whole, forged, of other content or to the limit, among datagrams of the next request
// a cut or the request whole goes up to four times over from one place, as a moved initiator retransmits it, and in some cases the repeats come from the others alone, which leaves the credits alone to bound them, and in some of those the second exchange's from the place a repeat of the first last came from
// the model answers a repeat from the origin on its fragment 1 of a Total Fragments at least the request's, or the request whole as it came, at most maxRetransmitsWhileBusy times in each exchange
// it answers one from another place once all of the request came from there, in the fragments of one cut or whole as it came, and only where that place's repeats in the exchange cover the answer's octets with those of every answer drawn there, each datagram counted on the wire, and that answer spends nothing of the origin's count
// it keeps that credit, and the repeat in fragments it gathers, for at most movedCredits places, a newcomer past them taking the place of the one whose last datagram arrived least recently, and the session keeps the credits the model keeps after each datagram
// it cuts the answer again within the largest datagram of the repeat that draws it and never under the floor's, and ends the SA where a repeat's fragments pass reassemblyLimit
// a repeat never touches the queue the next request is gathered in, which holds what the model holds after each datagram
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
// RFC 7383 section 5: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
func TestHalfOpenRepeatsDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testHalfOpenRepeatsDrawTheAnswerAsTheModelDoes)(t)
}

func testHalfOpenRepeatsDrawTheAnswerAsTheModelDoes(t *testing.T) {
	repeatsAsTheModelDraws(t, []string{halfOpenSite}, []bool{false}, false)
}

// the repeat property over an initiator that moved: its repeats come from the places other than the origin alone, none to the limit, with fragmentation negotiated, a path wider than the IPv4 floor and requests of 900 octets or more
// and every repeat of the second exchange comes from the place a repeat of the first last came from, so the credit's bounds, its start over at the next exchange and the answer's recut come up in most cases
func TestHalfOpenRepeatsOfAMovedInitiatorDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testHalfOpenRepeatsOfAMovedInitiatorDrawTheAnswerAsTheModelDoes)(t)
}

func testHalfOpenRepeatsOfAMovedInitiatorDrawTheAnswerAsTheModelDoes(t *testing.T) {
	repeatsAsTheModelDraws(t, []string{halfOpenSite}, []bool{true}, false)
}

// the repeat property past IKE_AUTH: each case runs at one of the sites of takers, Run's dispatch or the dial's wait after IKE_AUTH, over the inputs of either property above
// the session's endpoint is the origin, keepAnswer keeps each answer and moves the peer's window past it, and the rule and its model are the half-open wait's
// RFC 7296 section 2.1: "The responder MUST never retransmit a response unless it receives a retransmission of the request."
// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
func TestRepeatsPastIKEAuthDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testRepeatsPastIKEAuthDrawTheAnswerAsTheModelDoes)(t)
}

func testRepeatsPastIKEAuthDrawTheAnswerAsTheModelDoes(t *testing.T) {
	repeatsAsTheModelDraws(t, slices.Sorted(maps.Keys(takers)), []bool{false, true}, false)
}

// the repeat property at the bounds its rule branches on, at the half-open wait, Run's dispatch and the wait after IKE_AUTH, with fragmentation negotiated and the origin among the places of every kind
// among the other kinds an exchange draws runs of one repeat from the origin, the request whole as it came or fragment 1 of a cut of at least its Total Fragments, sent as often as the model's count needs to reach maxRetransmitsWhileBusy less one, maxRetransmitsWhileBusy, or one past it, which the cap leaves unanswered
// after each run the request comes from another place as it came, as often as that place's credit needs to cover the answer
// so the count meets its cap in an exchange, starts over at the next one and holds no other place
// of the other kinds, "a fragment of a cut", "a fragment that does not authenticate", "a fragment of other content" and "a fragment to the limit" draw Total Fragments from 0 and Fragment Number from 0 to Total Fragments, or 1 where Total Fragments is 0, so each zero comes alone, and the model answers neither zero at the origin
// RFC 7383 section 2.6: "check that the Fragment Number and the Total Fragments fields contain non-zero values"
// RFC 7383 section 2.6: "If any of these tests fail, the message MUST be silently discarded."
func TestRepeatsAtTheBoundsOfTheRuleDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testRepeatsAtTheBoundsOfTheRuleDrawTheAnswerAsTheModelDoes)(t)
}

func testRepeatsAtTheBoundsOfTheRuleDrawTheAnswerAsTheModelDoes(t *testing.T) {
	repeatsAsTheModelDraws(t, slices.Sorted(maps.Keys(repeatSites())), []bool{false}, true)
}

// repeatsAsTheModelDraws checks the repeat property, each case at one of sites and over the inputs of an initiator that moved or not as one of moves says
// atBounds adds the draws of the property at the bounds, and a case without it draws none of them
func repeatsAsTheModelDraws(t *testing.T, sites []string, moves []bool, atBounds bool) {
	hub := listenHub(t)
	places, conns := repeatPlaces(t, hub, net.IPv4(127, 0, 0, 1), 0x71)
	mux, err := hub.NewMuxTo(places[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	hostRoom := floorRoom
	if mtu, err := mux.PathMTU(); err == nil {
		hostRoom = max(floorRoom, mtu-576+floorRoom)
	}
	// paths are the IPv4 floor, path MTUs of 1280 and 1500 and the host's, each with the octets of IKE message its datagram carries
	paths := []struct {
		mtu  func() (int, error)
		room int
	}{{noPathMTU, floorRoom}, {pathMTUOf(1280), 1280 - 576 + floorRoom}, {pathMTUOf(1500), 1500 - 576 + floorRoom}, {nil, hostRoom}}
	pbt.Check(t, func(ht *hegel.T) {
		site, moved := hegel.Draw(ht, hegel.SampledFrom(sites)), hegel.Draw(ht, hegel.SampledFrom(moves))
		// a case of its own mux, since Run closes the mux of an IKE SA that a repeat's fragments end
		mux, err := hub.NewMuxTo(places[0])
		if err != nil {
			ht.Fatal(err)
		}
		defer mux.Close()
		negotiated, lowest, smallest := true, 1, 900
		switch {
		case atBounds:
			// a zero Fragment Number or Total Fragments is read only where the ends negotiated fragments
			lowest, smallest = 0, 1
		case !moved:
			negotiated, lowest, smallest = hegel.Draw(ht, hegel.Booleans()), 0, 1
		}
		path := paths[hegel.Draw(ht, pbt.Spanning(lowest, len(paths)-1))]
		// the sites past IKE_AUTH expect the first exchange's Message ID next
		ctx := &ikeContext{suite: modelSuite, responder: true, spiI: 0x0102030405060708, spiR: 0x1112131415161718, sker: bytes.Repeat([]byte{9}, modelKeyLen), nextPeerMID: 1}
		h := &repeatSite{ht: ht, site: site, s: &Session{mux: mux, current: ctx, fragments: negotiated, pathMTU: path.mtu}, places: places, conns: conns, around: v4Around, negotiated: negotiated, room: path.room, now: time.Now()}
		header := func(mid uint32) Header {
			return Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: mid}
		}
		// each request comes under a key of its own, the second the one the first exchange makes
		// the first comes whole in half the cases, so a repeat whole as it came meets the next request in fragments
		// an answer is within 400 octets of its request in half the cases, where the credit and the recut meet their bounds
		var requests [2]repeatRequest
		for i := range requests {
			r := &requests[i]
			r.mid, r.key = uint32(i+1), bytes.Repeat([]byte{byte(i + 1)}, modelKeyLen)
			size := hegel.Draw(ht, pbt.Spanning(smallest, 2000))
			r.inner = []RawPayload{{Type: PayloadKE, Body: make([]byte, size)}}
			r.content = encodePayloadChain(r.inner)
			whole, err := EncryptMessage(modelSuite, r.key, header(r.mid), nil, r.inner)
			if err != nil {
				ht.Fatal(err)
			}
			r.whole = whole
			total := 0
			switch {
			case i > 0:
				total = hegel.Draw(ht, pbt.Spanning(0, 6))
			case hegel.Draw(ht, hegel.Booleans()):
				total = hegel.Draw(ht, pbt.Spanning(1, 6))
			}
			if negotiated && total > 0 {
				for number := range total {
					raw, _ := piece(ht, r, header(r.mid), uint16(number+1), uint16(total), false)
					r.cut = append(r.cut, raw)
				}
			}
			r.answer = hegel.Draw(ht, pbt.Spanning(1, 4000))
			if hegel.Draw(ht, hegel.Booleans()) {
				r.answer = max(1, size+hegel.Draw(ht, pbt.Spanning(-400, 400)))
			}
		}
		ctx.skei = requests[0].key
		came := requests[0].cut
		if came == nil {
			came = [][]byte{requests[0].whole}
		}
		var request *opened
		for _, raw := range came {
			m, err := DecodeMessage(raw)
			if err != nil {
				ht.Fatal(err)
			}
			got, err := h.s.open(ctx, &ctx.requestFragments, raw, m)
			if err != nil {
				ht.Fatal(err)
			}
			request = got
		}
		if request == nil {
			ht.Fatalf("the request in %d datagrams did not come", len(came))
		}
		h.begin(request, &requests[0], requests[0].cut == nil)
		ctx.skei = requests[1].key
		next := &requests[1]
		// in some cases the repeats come from the places other than the origin alone, and in some of those every repeat of the second exchange from the place a repeat of the first last came from, as a moved initiator stays where it moved
		first, stay := 1, true
		if !moved {
			first, stay = 0, false
			if !atBounds && hegel.Draw(ht, hegel.Booleans()) {
				first, stay = 1, hegel.Draw(ht, hegel.Booleans())
			}
		}
		kept := 0
		for exchange := range requests {
			r := &requests[exchange]
			kinds := repeatKinds
			if exchange > 0 {
				kinds = repeatKinds[:len(repeatKinds)-2]
			}
			if moved {
				kinds = slices.DeleteFunc(slices.Clone(kinds), func(kind string) bool { return kind == "a fragment to the limit" })
			}
			if atBounds {
				kinds = append(slices.Clip(kinds), "the origin's repeats to its cap")
			}
			var arrived *opened
			whole := false
		events:
			for range hegel.Draw(ht, pbt.Spanning(1, 24)) {
				kind := hegel.Draw(ht, hegel.SampledFrom(kinds))
				place := kept
				if place == 0 {
					place = hegel.Draw(ht, pbt.Spanning(first, len(places)-1))
				}
				switch kind {
				case "a cut in any order":
					total := hegel.Draw(ht, pbt.Spanning(1, 8))
					for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
						for _, at := range drawOrder(ht, total) {
							raw, _ := piece(ht, r, header(r.mid), uint16(at+1), uint16(total), false)
							if !h.repeat(raw, place, repeatDatagram{number: uint16(at + 1), total: uint16(total), authentic: true}) {
								return
							}
						}
					}
				case "a cut just under the answer's datagrams":
					// the coarsest cut of at least the request's Total Fragments whose datagrams are smaller than the answer's, the largest repeat that cuts the answer again
					total := max(1, int(h.form.total))
					for total < 8 && fragmentAround+(len(r.content)+total-1)/total >= h.answer.largest() {
						total++
					}
					for number := range total {
						raw, _ := piece(ht, r, header(r.mid), uint16(number+1), uint16(total), false)
						if !h.repeat(raw, place, repeatDatagram{number: uint16(number + 1), total: uint16(total), authentic: true}) {
							return
						}
					}
				case "the request whole":
					raw, exact := h.requestWhole(header(r.mid))
					for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
						if !h.repeat(raw, place, repeatDatagram{whole: true, exact: exact}) {
							return
						}
					}
				case "the origin's repeats to its cap":
					raw, d := h.came, repeatDatagram{whole: true, exact: true}
					if h.came == nil || hegel.Draw(ht, hegel.Booleans()) {
						total := uint16(hegel.Draw(ht, pbt.Spanning(max(1, int(h.form.total)), 8)))
						raw, _ = piece(ht, r, header(r.mid), 1, total, false)
						d = repeatDatagram{number: 1, total: total, authentic: true}
					}
					for range maxRetransmitsWhileBusy + hegel.Draw(ht, pbt.Spanning(-1, 1)) - h.answers {
						if !h.repeat(raw, 0, d) {
							return
						}
					}
					if place == 0 {
						place = hegel.Draw(ht, pbt.Spanning(1, len(places)-1))
					}
					if !h.cover(place) {
						return
					}
				case "a fragment of the next request", "the next request whole":
					raw, d := next.whole, repeatDatagram{whole: true, exact: true}
					if kind == "a fragment of the next request" && next.cut != nil {
						at := hegel.Draw(ht, pbt.Spanning(0, len(next.cut)-1))
						raw, d = next.cut[at], repeatDatagram{number: uint16(at + 1), total: uint16(len(next.cut)), authentic: true}
					}
					if arrived, whole = h.arrive(raw, d), d.whole; arrived != nil {
						break events
					}
				default:
					least := 1
					if atBounds {
						least = 0
					}
					total := uint16(hegel.Draw(ht, pbt.Spanning(least, 8)))
					number := uint16(1)
					if total > 0 {
						number = uint16(hegel.Draw(ht, pbt.Spanning(least, int(total))))
					}
					raw, foreign := piece(ht, r, header(r.mid), number, total, kind == "a fragment of other content")
					d := repeatDatagram{number: number, total: total, authentic: true, foreign: foreign}
					switch kind {
					case "a fragment that does not authenticate":
						raw[len(raw)-1] ^= 1
						d.authentic = false
					case "a fragment to the limit":
						// a datagram one octet short of the limit or at it, which an empty queue keeps or refuses
						named := PayloadNone
						if number == 1 {
							named = PayloadKE
						}
						sealed, err := sealedFragment(modelSuite, r.key, header(r.mid), nil, named, 0, number, total, make([]byte, reassemblyLimit+hegel.Draw(ht, pbt.Spanning(-1, 0))-fragmentAround))
						if err != nil {
							ht.Fatal(err)
						}
						raw, d.foreign = sealed, true
					}
					if !h.repeat(raw, place, d) {
						return
					}
				}
			}
			if exchange == len(requests)-1 {
				return
			}
			// the rest of the next request comes, its fragments the queue does not hold or the request whole
			// where the answered request came whole, it comes again as it came after each of those fragments but the last, from a place other than the origin and the one a repeat last came from
			// so a repeat that makes a credit of its own meets the next request in the queue
			if arrived == nil && next.cut == nil {
				arrived, whole = h.arrive(next.whole, repeatDatagram{whole: true, exact: true}), true
			}
			late := 1
			if h.last == 1 {
				late = 2
			}
			for at, raw := range next.cut {
				if arrived != nil {
					break
				}
				if h.queue.held && h.queue.messageID == next.mid && h.queue.stored[uint16(at+1)] {
					continue
				}
				if arrived = h.arrive(raw, repeatDatagram{number: uint16(at + 1), total: uint16(len(next.cut)), authentic: true}); arrived == nil && h.came != nil {
					if !h.repeat(h.came, late, repeatDatagram{whole: true, exact: true}) {
						return
					}
				}
			}
			if arrived == nil {
				ht.Fatalf("the next request did not come in all of its %d fragments", len(next.cut))
			}
			if stay {
				kept = h.last
			}
			h.begin(arrived, next, whole)
			ctx.skei = bytes.Repeat([]byte{byte(len(requests) + 1)}, modelKeyLen)
		}
	})
}

// repeatPlaces are the places at source the repeat property's repeats come from on hub, observed under the IKE SPIs from first on, and the sockets behind them
// the first place is the address and port the IKE_SA_INIT answer went to, which is the session's endpoint past IKE_AUTH
// the others outnumber movedCredits, so a newcomer takes the place of a credit
func repeatPlaces(t *testing.T, hub *transport.Hub, source net.IP, first uint64) ([]transport.Endpoint, []*transport.MemoryConn) {
	var places []transport.Endpoint
	var conns []*transport.MemoryConn
	for spi := first; spi < first+6; spi++ {
		place, conn := observedPeerFrom(t, hub, spi, source)
		places, conns = append(places, place), append(conns, conn)
	}
	return places, conns
}

// initSite is the half-open wait's IKE_SA_INIT exchange, whose answer goes in the clear and whole
// the property hands answerInitRepeat the count and credits of ctx.lastPeer, which the other sites spend through answerRepeat and wantCredits reads at every site
const initSite = "IKE_SA_INIT exchange"

// waitSite is the same exchange as awaitAuthRequest runs it, each datagram sent to the hub it waits on
const waitSite = "half-open wait's IKE_SA_INIT exchange"

// initKinds are the runs of datagrams the IKE_SA_INIT repeat property draws, each drawn outright
var initKinds = []string{"the request", "another request", "the origin's repeats to its cap"}

// in the half-open wait, with IKE fragmentation negotiated on a path of the IPv4 floor, repeats of the IKE_SA_INIT request draw its answer as the repeat property's model draws a repeat whole, the answer whole in one datagram, which the model holds as an answer whole of the answer's octets
// the request and the answer are of 100 to 1500 octets, the answer within 400 octets of the request in half the cases, and the repeats come from the origin or five other places of one family, IPv4 or IPv6, in half the cases the runs of the first two kinds from the others alone
// a run is the request octet for octet up to four times over from one place, the request with one octet turned, which draws nothing, or the origin's repeats to its count's cap less one, at it or one past it, after which the request comes from another place as often as that place's credit needs to cover the answer
// so no place other than the origin draws more octets on the wire, each datagram counted with its family's IP header, than it sent, the origin draws at most maxRetransmitsWhileBusy answers, and the session keeps the credits the model keeps, at most movedCredits
// RFC 7383 section 2.2: "This implies that messages of the IKE_SA_INIT exchange cannot be fragmented."
func TestIKESAInitRepeatsDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testIKESAInitRepeatsDrawTheAnswerAsTheModelDoes)(t)
}

func testIKESAInitRepeatsDrawTheAnswerAsTheModelDoes(t *testing.T) {
	initRepeatsAsTheModelDraws(t, initSite)
}

// the IKE_SA_INIT repeat property over awaitAuthRequest itself, its repeats sent to the hub the wait takes them from, among them the IKE_INTERMEDIATE request from any place, which draws the wait's answer there alone
// once that request is answered no repeat of the IKE_SA_INIT request draws the answer from anywhere, and until then the repeats draw it as the model does
// the wait keeps the exchange's credits to itself, so the property checks the datagrams each place takes and not the credits
// RFC 7296 section 2.1: "The responder MUST remember each response until it receives a request whose sequence number is larger than or equal to the sequence number in the response plus its window size"
func TestIKESAInitRepeatsInTheHalfOpenWaitDrawTheAnswerAsTheModelDoes(t *testing.T) {
	bubble.Run(testIKESAInitRepeatsInTheHalfOpenWaitDrawTheAnswerAsTheModelDoes)(t)
}

func testIKESAInitRepeatsInTheHalfOpenWaitDrawTheAnswerAsTheModelDoes(t *testing.T) {
	initRepeatsAsTheModelDraws(t, waitSite)
}

// waitSuite is the suite of the half-open SA the property's wait runs, one IKE_INTERMEDIATE exchange for ML-KEM-768
var waitSuite = SASuite{EncrID: modelSuite.EncrID, EncrKeyBits: modelSuite.EncrKeyBits, PRFID: modelSuite.PRFID, DHGroup: modelSuite.DHGroup, Addition: ML_KEM_768}

// initRepeatsAsTheModelDraws checks the IKE_SA_INIT repeat property at site, initSite or waitSite, each case from the places of one family
func initRepeatsAsTheModelDraws(t *testing.T, site string) {
	hub := listenHub(t)
	type family struct {
		places []transport.Endpoint
		conns  []*transport.MemoryConn
		around int
	}
	v4, v4Conns := repeatPlaces(t, hub, net.IPv4(127, 0, 0, 1), 0x71)
	v6, v6Conns := repeatPlaces(t, hub, net.IPv6loopback, 0x81)
	families := []family{{v4, v4Conns, v4Around}, {v6, v6Conns, v6Around}}
	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	message := func(flags uint8, octets int) []byte {
		header := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: flags}
		return (&Message{Header: header, Payloads: []RawPayload{{Type: PayloadNonce, Body: make([]byte, octets-HeaderLen-genericPayloadHeaderLen)}}}).Encode()
	}
	pbt.Check(t, func(ht *hegel.T) {
		at := families[hegel.Draw(ht, pbt.Spanning(0, 1))]
		places := at.places
		mux, err := hub.NewMuxTo(places[0])
		if err != nil {
			ht.Fatal(err)
		}
		defer mux.Close()
		size, answer := hegel.Draw(ht, pbt.Spanning(100, 1500)), hegel.Draw(ht, pbt.Spanning(100, 1500))
		if hegel.Draw(ht, hegel.Booleans()) {
			answer = max(100, size+hegel.Draw(ht, pbt.Spanning(-400, 400)))
		}
		request, response := message(FlagInitiator, size), message(FlagResponse, answer)
		h := &repeatSite{ht: ht, site: site, s: &Session{mux: mux, current: &ikeContext{}, fragments: true, pathMTU: noPathMTU}, places: places, conns: at.conns, around: at.around, room: floorRoom, now: time.Now(),
			r: &repeatRequest{whole: request}, came: request, inner: response, answer: answerModel{inner: len(response) - wholeAround}, went: [][]byte{response},
			sent: make([]int, len(places)), drawn: make([]int, len(places))}
		if site == waitSite {
			h.s.current = &ikeContext{suite: waitSuite, responder: true, spiI: spiI, spiR: spiR, skD: bytes.Repeat([]byte{3}, 48), skei: bytes.Repeat([]byte{1}, modelKeyLen), sker: bytes.Repeat([]byte{2}, modelKeyLen),
				skpi: bytes.Repeat([]byte{4}, 48), skpr: bytes.Repeat([]byte{5}, 48)}
			if err := mux.RegisterIKE(spiI); err != nil {
				ht.Fatal(err)
			}
			h.waited, h.hubPort = make(chan struct{}), hub.LocalAddr().(*net.UDPAddr).Port
			nonce := bytes.Repeat([]byte{6}, nonceLen)
			go func() {
				defer close(h.waited)
				_, _, h.waitErr = h.s.awaitAuthRequest(request, response, nonce, nonce, time.Now().Add(time.Hour))
			}()
			defer func() {
				mux.Close()
				<-h.waited
			}()
		}
		first := hegel.Draw(ht, pbt.Spanning(0, 1))
		for range hegel.Draw(ht, pbt.Spanning(1, 24)) {
			place := hegel.Draw(ht, pbt.Spanning(first, len(places)-1))
			kinds := initKinds
			if site == waitSite && !h.forgotten {
				kinds = append(slices.Clip(initKinds), "the IKE_INTERMEDIATE request")
			}
			switch hegel.Draw(ht, hegel.SampledFrom(kinds)) {
			case "the IKE_INTERMEDIATE request":
				h.intermediate(place)
			case "the request":
				for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
					h.repeat(request, place, repeatDatagram{whole: true, exact: true})
				}
			case "another request":
				other := slices.Clone(request)
				other[hegel.Draw(ht, pbt.Spanning(0, len(other)-1))] ^= 1
				h.repeat(other, place, repeatDatagram{whole: true})
			case "the origin's repeats to its cap":
				for range maxRetransmitsWhileBusy + hegel.Draw(ht, pbt.Spanning(-1, 1)) - h.answers {
					h.repeat(request, 0, repeatDatagram{whole: true, exact: true})
				}
				h.cover(max(place, 1))
			}
		}
	})
}

// piece is fragment number of total of r's content under header, every octet of its chunk turned where foreign holds, and whether its content is then other than r's
// a zero Fragment Number or Total Fragments cuts no chunk, so that fragment carries nothing
func piece(ht *hegel.T, r *repeatRequest, header Header, number, total uint16, foreign bool) ([]byte, bool) {
	var chunk []byte
	if number > 0 && total > 0 {
		size := (len(r.content) + int(total) - 1) / int(total)
		chunk = slices.Clone(r.content[min(int(number-1)*size, len(r.content)):min(int(number)*size, len(r.content))])
	}
	if foreign {
		for i := range chunk {
			chunk[i] ^= 0xff
		}
	}
	next := PayloadNone
	if number == 1 {
		next = PayloadKE
	}
	raw, err := sealedFragment(modelSuite, r.key, header, nil, next, 0, number, total, chunk)
	if err != nil {
		ht.Fatal(err)
	}
	return raw, foreign && len(chunk) > 0
}
