// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// outbound is a message this end built under an IKE SA, sealed whole, with its inner payloads in plaintext kept for a send that cuts it into fragments
// key is the encryption key of the generation it was built under
type outbound struct {
	whole  []byte
	ctx    *ikeContext
	key    []byte
	header Header
	first  PayloadType
	inner  []byte
}

func (c *ikeContext) seal(key []byte, header Header, inner []RawPayload) (*outbound, error) {
	o := &outbound{ctx: c, key: key, header: header, inner: encodePayloadChain(inner)}
	if len(inner) > 0 {
		o.first = inner[0].Type
	}
	iv, err := c.nextIV()
	if err != nil {
		return nil, err
	}
	// this end pads with nothing, so the plaintext ends in a Pad Length of zero
	if o.whole, err = encryptMessagePlaintextIV(c.suite, key, header, nil, o.first, append(slices.Clip(o.inner), 0), iv); err != nil {
		return nil, err
	}
	return o, nil
}

// capacity is the most plaintext octets of the message an IKE Fragment message carries within room octets
// a fragment adds Fragment Number and Total Fragments to what the whole message adds around its plaintext
func (o *outbound) capacity(room int) int {
	return room - (len(o.whole) - len(o.inner)) - 4
}

func (o *outbound) total(size int) int { return max(1, (len(o.inner)+size-1)/size) }

func (o *outbound) octets(size int) int {
	return o.total(size)*(len(o.whole)-len(o.inner)+4) + len(o.inner)
}

// fragments seals the message as IKE Fragment messages of at most size plaintext octets each
// RFC 7383 section 2.5: "The content is treated as a binary blob and is split regardless of the boundaries of inner payloads."
// RFC 7383 section 2.5: "When prepending the IKE header to the IKE Fragment messages, it MUST be taken intact from the original message, except for the Length and Next Payload fields."
func (o *outbound) fragments(size int) ([][]byte, error) {
	total := o.total(size)
	if total > math.MaxUint16 {
		return nil, fmt.Errorf("ike: a message of %d octets in fragments of %d would take %d of them", len(o.inner), size, total)
	}
	datagrams := make([][]byte, 0, total)
	for number := 1; number <= total; number++ {
		// RFC 7383 section 2.5: "in the very first fragment (with Fragment Number equal to 1), this field MUST be set to the payload type of the first inner payload (the same as for the Encrypted payload)."
		// and: "In the rest of the Fragment messages (with Fragment Number greater than 1), this field MUST be set to zero."
		next := PayloadNone
		if number == 1 {
			next = o.first
		}
		iv, err := o.ctx.nextIV()
		if err != nil {
			return nil, err
		}
		chunk := o.inner[(number-1)*size : min(number*size, len(o.inner))]
		raw, err := encryptFragmentIV(o.ctx.suite, o.key, o.header, nil, next, uint16(number), uint16(total), append(slices.Clip(chunk), 0), iv)
		if err != nil {
			return nil, err
		}
		datagrams = append(datagrams, raw)
	}
	return datagrams, nil
}

// path is the threshold of a send to the peer now, the largest IP datagram it goes in, and the octets of IKE message one datagram carries within it
// RFC 7383 section 2.5.1: "If the sender has information about the PMTU size, it SHOULD use it."
func (s *Session) path() (threshold, room int) {
	threshold, room = s.floor()
	read := s.pathMTU
	if read == nil {
		read = s.mux.PathMTU
	}
	if mtu, err := read(); err == nil && mtu > threshold {
		room += mtu - threshold
		threshold = mtu
	}
	return threshold, room
}

// floor is the smallest threshold of a send to the peer, and the octets of IKE message one datagram carries within it
// RFC 7383 section 2.5.1: "Otherwise, for messages to be sent over IPv6, it is RECOMMENDED that a value of 1280 bytes as a maximum IP datagram size be used ([RFC2460]). For messages to be sent over IPv4, it is RECOMMENDED that a value of 576 bytes as a maximum IP datagram size be used."
// the two are the floor, since IPv6 carries 1280 on every link and RFC 7383 section 2.5.1 says of 576 that "the value is large enough for the presented solution and small enough to avoid IP fragmentation in most situations"
func (s *Session) floor() (threshold, room int) {
	endpoint := s.mux.Endpoint()
	threshold = 1280
	if endpoint.AddrPort().Addr().Is4() {
		threshold = 576
	}
	return threshold, threshold - around(endpoint)
}

// around is the octets an IP datagram to or from endpoint carries past its octets of IKE message: an IP header without options of endpoint's family, the UDP header and the non-ESP marker
func around(endpoint transport.Endpoint) int {
	if endpoint.AddrPort().Addr().Is4() {
		return 20 + 8 + NonESPMarkerLen
	}
	return 40 + 8 + NonESPMarkerLen
}

// onWire is the octets of the IP datagrams to or from endpoint that carry octets of IKE message in datagrams of them, each counted as path counts one of this end's
func onWire(endpoint transport.Endpoint, datagrams, octets int) int {
	return octets + datagrams*around(endpoint)
}

// Fragments reports whether both ends said they support IKE fragmentation, and where they did the path's threshold now, the largest IP datagram this end cuts a new message to fit
// a request stepped down to its family's floor, and an answer cut within the datagrams of the request or repeat it answers, go below it
func (s *Session) Fragments() (bool, int) {
	if !s.fragments {
		return false, 0
	}
	threshold, _ := s.path()
	return true, threshold
}

// transmission is a message this end sends, as the datagrams that carry it now
// threshold is the one they were cut under, sends the sends of them a request's backoff scheduled, total their Total Fragments, zero for the message whole, and request the Total Fragments of the request the message answers, which a repeat of that request is read against
type transmission struct {
	message   *outbound
	datagrams [][]byte
	threshold int
	sends     int
	total     int
	request   uint16
}

// form is how a request came, the Total Fragments of its fragments and the octets of IKE message of the largest of their datagrams, both zero where it came whole
type form struct {
	total   uint16
	largest int
}

// transmit readies message for its first send, in fragments where both ends negotiated them and it does not fit the path or answers a request that came in fragments
// request is the form of the request message answers, zero where that came whole or message answers none, and an answer to a request in fragments is cut to fit the largest of their datagrams where the path is wider
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
// RFC 7383 section 2.4: "If either peer has information that a part of the transaction is likely to be fragmented at the IP layer, causing interference with the IKE exchange, that peer SHOULD use IKE fragmentation."
// RFC 7383 section 2.4: "IKE fragmentation SHOULD NOT be used in cases where IP-layer fragmentation of both the request and response messages is unlikely."
// RFC 7383 section 2.4: "If none of the above apply, the responder SHOULD respond in the same form (fragmented or not) as the request message to which it is responding."
func (s *Session) transmit(message *outbound, request form) (*transmission, error) {
	t := &transmission{message: message, datagrams: [][]byte{message.whole}, request: request.total}
	if !s.fragments {
		return t, nil
	}
	threshold, room := s.path()
	threshold, room = s.within(threshold, room, request.largest)
	t.threshold = threshold
	if len(message.whole) <= room && request.total == 0 {
		return t, nil
	}
	if err := s.cut(t, threshold, message.capacity(room)); err != nil {
		return nil, err
	}
	return t, nil
}

// within is threshold and its room lowered to a datagram of fit octets of IKE message from the peer, where that is smaller and fit is not zero, and never under the family's floor
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
// the peer's datagram is counted as the path counts one of this end's, with an IP header without options, the UDP header and the non-ESP marker around its IKE octets
func (s *Session) within(threshold, room, fit int) (int, int) {
	_, floorRoom := s.floor()
	if bound := max(fit, floorRoom); fit > 0 && bound < room {
		return threshold - room + bound, bound
	}
	return threshold, room
}

// sealRequest seals inner under ctx's key as the request header names, and readies it for its first send
// a request answers nothing, so its size alone says whether it goes in fragments
func (s *Session) sealRequest(ctx *ikeContext, header Header, inner []RawPayload) (*transmission, error) {
	message, err := ctx.seal(ctx.localEncryptionKey(), header, inner)
	if err != nil {
		return nil, err
	}
	return s.transmit(message, form{})
}

// resend sends t through send once more, cut again first where cutFor says, and reports whether it was cut again
// every send of a message goes through it unless it is a first send right after the cut, so no send carries a cut the path no longer takes
// fit is cutFor's
// RFC 7383 section 2.5.2: "it MUST start from larger values and refragment the original message"
func (s *Session) resend(t *transmission, fit int, send func([]byte) error) (bool, error) {
	threshold, size := s.cutFor(t, fit)
	return s.sendCut(t, threshold, size, send)
}

// retransmit is resend for a send of a request that its backoff schedules, the first send included, and only such a send counts toward stepDownSends
// so a probe, which a network change asks for at any time, steps a request down only once the backoff's own sends under its cut reached stepDownSends, and that cut starts the backoff over
func (s *Session) retransmit(t *transmission, send func([]byte) error) (bool, error) {
	again, err := s.resend(t, 0, send)
	t.sends++
	return again, err
}

// sendCut sends t through send once more under threshold, cut first into fragments of size plaintext octets where size is not zero, and reports whether it was cut again
func (s *Session) sendCut(t *transmission, threshold, size int, send func([]byte) error) (bool, error) {
	again := false
	if size > 0 {
		again = s.cut(t, threshold, size) == nil
	} else {
		t.threshold = threshold
	}
	return again, sendEach(send, t.datagrams)
}

// cutFor is the threshold t goes under at its next send, and the plaintext octets of each of its fragments where that send cuts it again, zero where it goes as it stands
// t is cut again where the path's threshold fell below the one t was cut under, under its family's floor where t is a request whose datagrams its backoff sent stepDownSends times under a threshold above it,
// and within fit where t is an answer and fit is the octets of IKE message of the largest datagram of the repeat that draws it again, zero for a repeat whole, and a datagram of t is larger
// RFC 7383 section 2.5.2: "It is the initiator of the exchange who performs PMTU discovery."
// RFC 7383 section 2.5.2: "While doing probes, it MUST start from larger values and refragment the original message, using the next smaller value of the threshold if it did not receive a response in a reasonable time after several retransmissions."
// RFC 7383 section 2.5.2: "PMTU discovery in IKE is supposed to be coarse-grained, i.e., it is expected that a node will try only a few fragmentation thresholds in order to minimize delays caused by unsuccessful probes."
// so the values are the path's and then the floor, and a message whose fragments cannot shrink again is at the smallest
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
// so an answer follows the initiator's probe down and probes nothing of its own, and one whose datagrams fit the repeat's stays as it is
// RFC 7383 section 2.5.2: "When selecting the next smaller value for the fragmentation threshold, the sender MUST ensure that the value in the Total Fragments field is really increased."
func (s *Session) cutFor(t *transmission, fit int) (threshold, size int) {
	if !s.fragments {
		return t.threshold, 0
	}
	threshold, room := s.path()
	if floor, floorRoom := s.floor(); !t.message.header.IsResponse() && t.sends >= stepDownSends && floor < min(threshold, t.threshold) {
		threshold, room = floor, floorRoom
	}
	switch lower, inside := s.within(threshold, room, fit); {
	case inside < room && largest(t.datagrams) > inside:
		threshold, room = lower, inside
	case threshold >= t.threshold:
		return t.threshold, 0
	}
	size = t.message.capacity(room)
	switch {
	case t.total == 0 && len(t.message.whole) <= room:
		return threshold, 0
	case t.total > 0:
		size = min(size, len(t.message.inner)/(t.total+1))
	}
	if size <= 0 {
		return t.threshold, 0
	}
	return threshold, size
}

// carried is the datagrams t goes in at a send that cuts it into fragments of size plaintext octets, or as it stands where size is zero, and the octets of IKE message they carry in all
func (t *transmission) carried(size int) (datagrams, octets int) {
	if size > 0 {
		return t.message.total(size), t.message.octets(size)
	}
	for _, datagram := range t.datagrams {
		octets += len(datagram)
	}
	return len(t.datagrams), octets
}

func largest(datagrams [][]byte) int {
	n := 0
	for _, datagram := range datagrams {
		n = max(n, len(datagram))
	}
	return n
}

// cut seals t's message in fragments of at most size plaintext octets for threshold
func (s *Session) cut(t *transmission, threshold, size int) error {
	datagrams, err := t.message.fragments(size)
	if err != nil {
		return err
	}
	t.datagrams, t.threshold, t.sends, t.total = datagrams, threshold, 0, len(datagrams)
	header := t.message.header
	slog.Debug("ike sending a message in fragments", "exchange", exchangeName(header.ExchangeType), "message_id", header.MessageID,
		"octets", len(t.message.whole), "fragments", t.total, "threshold", threshold)
	s.emit("ike.message.fragmented", slog.String("exchange", exchangeName(header.ExchangeType)), slog.Uint64("message_id", uint64(header.MessageID)),
		slog.Int("fragments", t.total), slog.Int("threshold", threshold))
	return nil
}

// exchangeName is the name RFC 7296, RFC 9242 and RFC 9370 give an exchange type this end runs, and its number for any other
func exchangeName(exchange ExchangeType) string {
	switch exchange {
	case IKE_SA_INIT:
		return "IKE_SA_INIT"
	case IKE_AUTH:
		return "IKE_AUTH"
	case CREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case INFORMATIONAL:
		return "INFORMATIONAL"
	case IKE_INTERMEDIATE:
		return "IKE_INTERMEDIATE"
	case IKE_FOLLOWUP_KE:
		return "IKE_FOLLOWUP_KE"
	}
	return strconv.Itoa(int(exchange))
}

// answer sends a response that is kept nowhere, since the exchange or the IKE SA ends with it
func (s *Session) answer(response *outbound, request form, endpoint transport.Endpoint) {
	if sent, err := s.transmit(response, request); err == nil {
		_ = s.sendTo(sent.datagrams, endpoint)
	}
}

// keepAnswer readies response to the peer's request at mid, which came as request, for its first send, keeps it as the answer to every repeat of that request, and moves the peer's window past mid
func (s *Session) keepAnswer(ctx *ikeContext, mid uint32, response *outbound, request *opened) (*transmission, error) {
	sent, err := s.transmit(response, request.form)
	if err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := ctx.keep(mid, request, sent); err != nil {
		return nil, err
	}
	ctx.nextPeerMID++
	return sent, nil
}

// keep holds sent, the answer to the peer's request at mid that came as request, for every repeat of that request, and stateMu guards it
func (c *ikeContext) keep(mid uint32, request *opened, sent *transmission) error {
	if err := c.lastPeer.answered(request, c.peerEncryptionKey(), sent); err != nil {
		return err
	}
	c.lastPeerResponseID = mid
	return nil
}

func (s *Session) send(datagrams [][]byte) error { return sendEach(s.mux.SendIKE, datagrams) }

func (s *Session) sendTo(datagrams [][]byte, endpoint transport.Endpoint) error {
	return sendEach(s.to(endpoint), datagrams)
}

func (s *Session) to(endpoint transport.Endpoint) func([]byte) error {
	return func(datagram []byte) error { return s.mux.SendIKETo(datagram, endpoint) }
}

// sendEach sends every datagram whatever fails, since each fragment the peer gets is one it keeps
func sendEach(send func([]byte) error, datagrams [][]byte) error {
	var first error
	for _, datagram := range datagrams {
		if err := send(datagram); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// opened is a message from the peer that authenticated under its IKE SA, whole or reassembled from its fragments
// raw is its octets through the Encrypted payload's generic header at least, as IntAuth reads them, plaintext its inner payloads with an Encrypted payload's padding, and form how it came
type opened struct {
	raw        []byte
	outer      *Message
	innerFirst PayloadType
	plaintext  []byte
	form
}

// fragment reports whether m is an IKE Fragment message
// RFC 7383 section 2.6: "The receiver identifies the IKE Fragment message by the presence of an Encrypted Fragment payload in it."
func fragment(m *Message) bool {
	return len(m.Payloads) > 0 && m.Payloads[len(m.Payloads)-1].Type == PayloadSKF
}

// fragmentNumbers is the Fragment Number and Total Fragments of an IKE Fragment message, zero where its payload is too short to hold them
func fragmentNumbers(m *Message) (number, total uint16) {
	body := m.Payloads[len(m.Payloads)-1].Body
	if len(body) < 4 {
		return 0, 0
	}
	return binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4])
}

var errFragmentLimit = errors.New("ike: the peer's fragments of one message passed the reassembly limit")

// reassembly gathers one message the peer sends in fragments
// only the goroutine receiving for the IKE SA touches it
type reassembly struct {
	messageID uint32
	total     uint16
	started   time.Time
	// held is the octets of the stored fragments' datagrams, which is more than their content holds, and largest those of the largest
	held    int
	largest int
	chunks  map[uint16][]byte
	// head is fragment 1's octets ahead of its Encrypted Fragment payload, namer the offset in it of the octet naming that payload, cleartext its unprotected payloads, and next and flags the payload's Next Payload and the octet of its C bit and RESERVED
	head        []byte
	namer       int
	cleartext   []RawPayload
	next, flags byte
}

// take files one IKE Fragment message from the peer, raw decoded as m, which arrived at now, and decrypts it under key
// it returns the message whose last fragment this is, and errFragmentLimit, after which q holds nothing, once storing it would pass reassemblyLimit
// a fragment that fails a test is discarded silently, and take returns neither
func (q *reassembly) take(suite SASuite, key, raw []byte, m *Message, now time.Time) (*opened, error) {
	number, total := fragmentNumbers(m)
	// RFC 7383 section 2.6: "If the receiver does not get all IKE fragments needed to reassemble the original message within a timeout interval, it MUST discard all IKE Fragment messages received so far for the exchange."
	// the receive path hands over fragments of the one message it waits for, so another Message ID ends the message held
	if q.chunks != nil && (!now.Before(q.started.Add(reassemblyTimeout)) || m.Header.MessageID != q.messageID) {
		*q = reassembly{}
	}
	// RFC 7383 section 2.6: "check that the Fragment Number and the Total Fragments fields contain non-zero values", "check that the value in the Fragment Number field is less than or equal to the value in the Total Fragments field" and "if reassembling has already started, check that the value in the Total Fragments field is equal to or greater than the Total Fragments field in the fragments that have already been stored in the reassembling queue"
	// and: "If any of these tests fail, the message MUST be silently discarded."
	// a Fragment Number from 1 to Total Fragments leaves Total Fragments non-zero
	if number == 0 || number > total || q.chunks != nil && total < q.total {
		return nil, nil
	}
	// RFC 7383 section 2.6: "If an IKE Fragment message with the same Message ID, Fragment Number, and Total Fragments fields is already present in the reassembling queue, this message is considered a replay and MUST be silently discarded."
	if _, stored := q.chunks[number]; stored && total == q.total {
		return nil, nil
	}
	// RFC 7383 section 2.6: "If the ICV check fails, the message MUST be silently discarded."
	// a fragment whose padding does not hold carries no content to merge, and goes the same way
	_, plain, err := decryptMessagePlaintext(suite, key, raw, m)
	if err != nil {
		return nil, nil
	}
	content, err := unpadded(plain)
	if err != nil {
		return nil, nil
	}
	// RFC 7383 section 2.6: "If reassembling is not finished yet and the Total Fragments field in the received fragment is greater than the Total Fragments field in those fragments that are in the reassembling queue, the receiver MUST discard all received fragments and start the reassembly process over with just the received IKE Fragment message."
	if q.chunks != nil && total > q.total {
		*q = reassembly{}
	}
	// RFC 7383 section 5: "it is RECOMMENDED that the receiver limit the number of fragments it stores in the reassembling queue so that the sum of the sizes of Encrypted Fragment payload contents (after decryption) for fragments that are already placed into the reassembling queue is less than some value that is reasonable for the implementation."
	// and: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
	if q.held+len(raw) >= reassemblyLimit {
		*q = reassembly{}
		return nil, errFragmentLimit
	}
	if q.chunks == nil {
		*q = reassembly{messageID: m.Header.MessageID, total: total, started: now, chunks: make(map[uint16][]byte)}
	}
	q.chunks[number] = slices.Clone(content)
	q.held, q.largest = q.held+len(raw), max(q.largest, len(raw))
	if number == 1 {
		// RFC 7383 section 2.5.3: "all unprotected payloads MUST be placed in the first fragment (with the Fragment Number field equal to 1), along with the Encrypted Fragment payload, which MUST be present in every IKE Fragment message and be the last payload in it."
		q.head, q.next, q.flags = slices.Clone(raw[:m.skHeaderOffset]), raw[m.skHeaderOffset], raw[m.skHeaderOffset+1]
		// the IKE header's octet 16 names the first payload, and each payload's first octet the one after it
		q.namer, q.cleartext = 16, nil
		offset := HeaderLen
		for _, payload := range m.Payloads[:len(m.Payloads)-1] {
			q.namer, offset = offset, offset+genericPayloadHeaderLen+len(payload.Body)
			q.cleartext = append(q.cleartext, RawPayload{Type: payload.Type, Critical: payload.Critical, Body: slices.Clone(payload.Body)})
		}
	}
	if len(q.chunks) < int(q.total) {
		return nil, nil
	}
	message := q.merge()
	*q = reassembly{}
	return message, nil
}

// merge is the message the stored fragments make, fragment 1's header and unprotected payloads ahead of an Encrypted payload whose header takes fragment 1's Next Payload, C bit and RESERVED, and the content in fragment order
// its header's Length counts the octets it holds, with no IV, padding or ICV, and the Encrypted payload's Payload Length stays zero, since only IntAuth reads it and IntAuth sets it
// RFC 7383 section 2.6: "When all IKE Fragment messages (as indicated in the Total Fragments field) are received, the decrypted content of all Encrypted Fragment payloads is merged together to form the content of the original Encrypted payload and, therefore, along with the IKE header and unprotected payloads (if any), the original message."
// RFC 9242 section 3.3.2: "While reconstructing, the RESERVED field in the reconstructed Encrypted payload header MUST be set to the value of the RESERVED field in the Encrypted Fragment payload header from the first fragment (with the Fragment Number field set to 1)."
func (q *reassembly) merge() *opened {
	var content []byte
	for number := uint16(1); number <= q.total; number++ {
		content = append(content, q.chunks[number]...)
	}
	raw := append(slices.Clone(q.head), q.next, q.flags, 0, 0)
	raw[q.namer] = byte(PayloadSK)
	binary.BigEndian.PutUint32(raw[24:28], uint32(len(raw)+len(content)))
	header, _ := decodeHeader(raw)
	payloads := append(q.cleartext, RawPayload{Type: PayloadSK, Critical: q.flags&0x80 != 0})
	return &opened{
		raw:        raw,
		outer:      &Message{Header: *header, Payloads: payloads, skHeaderOffset: len(q.head)},
		innerFirst: PayloadType(q.next),
		plaintext:  append(content, 0),
		form:       form{total: q.total, largest: q.largest},
	}
}

// open authenticates raw, decoded as m, from ctx's peer, a whole message at once or a fragment q gathers until the last of its message arrives
// it returns errFragmentLimit once q's fragments pass reassemblyLimit, and nothing for a datagram that does not authenticate or leaves its message incomplete
func (s *Session) open(ctx *ikeContext, q *reassembly, raw []byte, m *Message) (*opened, error) {
	if !fragment(m) {
		first, plain, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, m)
		if err != nil {
			return nil, nil
		}
		return &opened{raw: raw, outer: m, innerFirst: first, plaintext: plain}, nil
	}
	// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
	// so the fragments of a peer that did not say it supports them are discarded before anything of them is held
	if !s.fragments {
		return nil, nil
	}
	message, err := q.take(ctx.suite, ctx.peerEncryptionKey(), raw, m, time.Now())
	if message != nil {
		_, total := fragmentNumbers(m)
		slog.Debug("ike reassembled a message from fragments", "exchange", exchangeName(m.Header.ExchangeType), "message_id", m.Header.MessageID, "fragments", total)
	}
	return message, err
}

// asksAgain reports whether raw, decoded as m, an IKE Fragment message from the origin, draws the response to the request this end answered last, which came in request fragments, again
// RFC 7383 section 2.6.1: "If the responder receives a retransmitted fragment of a request when it has already processed that request and has sent back a response, that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
// and: "otherwise, it MUST be ignored."
func (s *Session) asksAgain(suite SASuite, key, raw []byte, m *Message, request uint16) bool {
	number, total := fragmentNumbers(m)
	return number == 1 && total > 0 && s.repeats(suite, key, raw, m, request)
}

// repeats reports whether raw, decoded as m, an IKE Fragment message, is one of a repeat of the request this end answered last, which came in request fragments, under key
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
// RFC 7383 section 2.6.1: "If an incoming message contains an Encrypted Fragment payload, the values of the Fragment Number and Total Fragments fields MUST be used along with the Message ID to detect retransmissions and replays."
// RFC 7383 section 2.5.2: "Since the sender starts from larger fragments and then makes them smaller, the value in the Total Fragments field increases with each new probe."
// so a repeat in fewer fragments than the request came in is of a cut the peer left before the answered one, and draws nothing
func (s *Session) repeats(suite SASuite, key, raw []byte, m *Message, request uint16) bool {
	if _, total := fragmentNumbers(m); !s.fragments || total < request {
		return false
	}
	_, _, err := decryptMessagePlaintext(suite, key, raw, m)
	return err == nil
}

// expireFragments discards each message the peer left incomplete for reassemblyTimeout, a repeat a credit gathers among them, and returns when the next one it holds expires
func (s *Session) expireFragments(now time.Time) (time.Time, bool) {
	s.stateMu.RLock()
	contexts := []*ikeContext{s.current, s.old, s.collision}
	s.stateMu.RUnlock()
	var next time.Time
	held := false
	for _, ctx := range contexts {
		if ctx == nil {
			continue
		}
		queues := []*reassembly{&ctx.requestFragments, &ctx.responseFragments}
		for _, c := range ctx.lastPeer.others {
			queues = append(queues, &c.repeat)
		}
		for _, q := range queues {
			if q.chunks == nil {
				continue
			}
			ends := q.started.Add(reassemblyTimeout)
			if !now.Before(ends) {
				slog.Info("ike dropped the fragments of a message the peer left incomplete", "message_id", q.messageID, "held", len(q.chunks), "total", q.total)
				*q = reassembly{}
				continue
			}
			if !held || ends.Before(next) {
				next, held = ends, true
			}
		}
	}
	return next, held
}
