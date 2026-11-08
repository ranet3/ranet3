// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// The reasons an ICMP message is dropped or an echo mapping refused
const (
	reasonICMPChecksum = "icmp checksum"
	reasonNotEcho      = "icmp not echo"
	reasonEchoSocket   = "echo socket"
	reasonEchoTooLarge = "echo too large"
)

// errEchoTooLarge is a reply longer than the buffer it is read into, which is
// dropped whole rather than carried cut
var errEchoTooLarge = errors.New("userspace: echo reply too large for its buffer")

// echoRelay carries the leaves' echo requests outside gVisor, as RFC 5508 has
// a NAT carry them: one mapping per leaf address and identifier (REQ-1), each
// with one ICMP datagram socket that sends to every destination and holds the
// leaf's identifier where no other mapping holds it, so every server reads
// one identifier (REQ-1a), and that is the mapping's reverse key. A mapping
// ends echoIdle after its last request out or reply in (REQ-2). Every socket
// passes the platform's Prepare.
type echoRelay struct {
	x   *Exit
	now func() time.Time

	mu       sync.Mutex
	mappings map[echoKey]*echoMapping
	// held is each identifier a mapping's socket holds, by family. The relay
	// keeps it, since Linux binds a second socket of the process to an
	// identifier one holds, which would split the replies between the two.
	held map[echoOutside]bool
	// withdrawn refuses every request from a withdrawal until resume
	withdrawn bool

	// readers counts the goroutines reading the mappings' sockets, and out the
	// pooled buffers they hold
	readers sync.WaitGroup
	out     atomic.Int64
}

// echoKey is a mapping's leaf address and identifier, the address naming the
// family
type echoKey struct {
	leaf netip.Addr
	id   uint16
}

// echoOutside is an identifier a mapping's socket holds, in one family
type echoOutside struct {
	ipv6 bool
	id   uint16
}

// echoMapping is one leaf address and identifier's socket, and the
// identifier it holds
type echoMapping struct {
	key     echoKey
	socket  *echoSocket
	outside echoOutside
	// last is the mapping's last request out or reply in, in unix nanoseconds
	last atomic.Int64
}

func newEchoRelay(x *Exit) *echoRelay {
	return &echoRelay{x: x, now: time.Now, mappings: map[echoKey]*echoMapping{}, held: map[echoOutside]bool{}}
}

// echoQuery is an echo request as take reads it from its packet: the leaf's
// address, the destination's, the identifier and the ICMP message whole
type echoQuery struct {
	from, to netip.Addr
	id       uint16
	message  []byte
}

// readEcho reads raw, one IPv4 or IPv6 packet holding an ICMP or ICMPv6
// message right after its header, and reports false where that is no echo
// request of code 0, the one request an ICMP datagram socket sends
func readEcho(raw []byte) (echoQuery, bool) {
	raw, version := packet.Payload(raw)
	var e echoQuery
	var request byte
	switch version {
	case 4:
		if raw[9] != 1 {
			return e, false
		}
		e.from, e.to = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
		e.message, request = raw[int(raw[0]&0x0f)*4:], 8
	case 6:
		if raw[6] != 58 {
			return e, false
		}
		e.from, e.to = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
		e.message, request = raw[40:], 128
	default:
		return e, false
	}
	if len(e.message) < 8 || e.message[0] != request || e.message[1] != 0 {
		return e, false
	}
	e.id = binary.BigEndian.Uint16(e.message[4:6])
	return e, true
}

// checksumValid is whether the request's checksum holds, over the message in
// IPv4 (RFC 792) and with RFC 4443 section 2.3's pseudo header in IPv6
func (e echoQuery) checksumValid() bool {
	if e.from.Is4() {
		return packet.Sum(0, e.message) == 0xffff
	}
	return transportSum(e.from, e.to, 58, e.message) == 0xffff
}

// fastQuery is whether raw, a packet the lane's judgment delivers, is an
// unfragmented ICMP or ICMPv6 message other than an error, with no IPv6
// extension header, which the relay takes without the stack: it relays an
// echo request and drops and counts any other, an extended echo request of
// RFC 8335 among them, which the stack would drop uncounted
func fastQuery(raw []byte) bool {
	switch raw[0] >> 4 {
	case 4:
		header := int(raw[0]&0x0f) * 4
		return raw[9] == 1 && binary.BigEndian.Uint16(raw[6:8])&0x3fff == 0 && len(raw) > header && !icmp4Error(raw[header])
	case 6:
		return raw[6] == 58 && len(raw) > 40 && raw[40] >= 128
	}
	return false
}

// icmp4Error is whether an ICMPv4 message of type kind is an error: a
// destination unreachable, source quench, redirect, time exceeded or
// parameter problem (RFC 792)
func icmp4Error(kind byte) bool {
	return kind == 3 || kind == 4 || kind == 5 || kind == 11 || kind == 12
}

// take relays raw, one echo request a leaf sent, whole in one packet with no
// fragment or extension header, which the lane's fast path and the stack's
// ICMP default handler both hand here. The checksum is checked first on both
// paths, since the socket computes a new one: a damaged request is dropped
// and counted and touches no mapping. Any other ICMP message is dropped and
// counted.
func (e *echoRelay) take(raw []byte) {
	request, ok := readEcho(raw)
	switch {
	case !ok:
		e.x.counts.dropUntracked(len(raw) > 0 && raw[0]>>4 == 6, reasonNotEcho)
		return
	case !request.checksumValid():
		e.x.counts.drop(reasonICMPChecksum)
		return
	}
	m, reason := e.mapping(request)
	if m == nil {
		e.refuse(raw, reason)
		return
	}
	m.last.Store(e.now().UnixNano())
	_ = m.socket.send(request.message, request.to)
}

// mapping is the mapping of the request's leaf address and identifier, opened
// where it has none, and why it refused
func (e *echoRelay) mapping(request echoQuery) (*echoMapping, string) {
	key := echoKey{request.from, request.id}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch m := e.mappings[key]; {
	case e.withdrawn:
		return nil, reasonWithdrawn
	case m != nil:
		return m, ""
	}
	if reason, ok := e.x.flows.admit(key.leaf); !ok {
		return nil, reason
	}
	want := key.id
	if e.held[echoOutside{key.leaf.Is6(), want}] {
		want = 0
	}
	socket, err := e.x.icmp.openEcho(key.leaf.Is6(), e.x.sourceFor(key.leaf), want, request.to)
	var id uint16
	if err == nil {
		if id, err = socket.identifier(); err != nil {
			_ = socket.close()
		}
	}
	if err != nil {
		e.x.flows.release(key.leaf)
		return nil, echoReason(err)
	}
	m := &echoMapping{key: key, socket: socket, outside: echoOutside{key.leaf.Is6(), id}}
	m.last.Store(e.now().UnixNano())
	e.mappings[key] = m
	e.held[m.outside] = true
	e.readers.Add(1)
	go e.read(m)
	return m, ""
}

// echoReason is why a socket's failure refused an echo mapping: the platform
// refusing the socket, as Android refuses an app outside ping_group_range,
// the descriptors, or the socket otherwise
func echoReason(err error) string {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, errors.ErrUnsupported) {
		return reasonEchoSocket
	}
	return socketReason(err)
}

// refuse counts a request refused for reason, and answers it past the limit
// where a limit refused it, and administratively prohibited where the
// platform refused the socket (RFC 5508 REQ-8's code 13)
func (e *echoRelay) refuse(raw []byte, reason string) {
	e.x.refused(raw, reason)
	switch reason {
	case reasonShare, reasonTotal, reasonDescriptors:
		e.x.answers.Answer(raw, netstack.ExitPastLimit, 0)
	case reasonEchoSocket:
		e.x.answers.Answer(raw, netstack.ExitProhibited, 0)
	}
}

// read hands m's leaf each echo reply m's socket receives, with the leaf's
// identifier written back and the checksum computed again, its sequence
// number and data untouched, until the socket closes. A pooled buffer is held
// only while a reply moves.
func (e *echoRelay) read(m *echoMapping) {
	defer e.readers.Done()
	headroom, reply := 20, byte(0)
	if m.key.leaf.Is6() {
		headroom, reply = 40, 129
	}
	b := replyBuffer{headroom: headroom, out: &e.out}
	for {
		n, from, err := m.socket.receive(&b)
		switch {
		case errors.Is(err, errEchoTooLarge):
			e.x.counts.drop(reasonEchoTooLarge)
		case err != nil:
			b.give()
			if errors.Is(err, errEchoClosed) || !icmpErrno(err) && !errors.Is(err, syscall.EINTR) {
				return
			}
			continue
		case n < 8 || (*b.buf)[:headroom+n][headroom] != reply:
			e.x.counts.drop(reasonNotEcho)
		default:
			m.last.Store(e.now().UnixNano())
			ident := e.x.ident.Add(1)
			e.x.toLeaf(echoPacket((*b.buf)[:headroom+n], from, m.key, uint16(ident), e.x.hops(m.key.leaf.Is6())), ident)
		}
		b.give()
	}
}

// replyBuffer is the pooled buffer an echo reply is read into, taken once a
// reply is there to read and given back once it has moved, so a mapping
// waiting for one holds none. out counts the buffers held.
type replyBuffer struct {
	headroom int
	buf      *[]byte
	out      *atomic.Int64
}

// take is the room past the headroom of the buffer b holds, taken from the
// pool where it holds none
func (b *replyBuffer) take() []byte {
	if b.buf == nil {
		b.buf = buffers[1].Get().(*[]byte)
		b.out.Add(1)
	}
	return (*b.buf)[b.headroom:cap(*b.buf)]
}

// give puts the buffer b holds back in the pool
func (b *replyBuffer) give() {
	if b.buf != nil {
		buffers[1].Put(b.buf)
		b.buf = nil
		b.out.Add(-1)
	}
}

// echoPacket writes the IP header of a reply from from to key's leaf, hops
// its TTL or hop limit, in the headroom of buf, whose ICMP message follows
// it, writes the leaf's identifier and the checksum into the message, and
// returns the packet
func echoPacket(buf []byte, from netip.Addr, key echoKey, ident uint16, hops uint8) []byte {
	if key.leaf.Is4() {
		message := buf[20:]
		binary.BigEndian.PutUint16(message[4:6], key.id)
		binary.BigEndian.PutUint16(message[2:4], 0)
		binary.BigEndian.PutUint16(message[2:4], ^uint16(packet.Sum(0, message)))
		leafHeader(buf, from, key.leaf, 1, 0, hops, ident)
		return buf
	}
	message := buf[40:]
	binary.BigEndian.PutUint16(message[4:6], key.id)
	binary.BigEndian.PutUint16(message[2:4], 0)
	binary.BigEndian.PutUint16(message[2:4], ^uint16(transportSum(from, key.leaf, 58, message)))
	leafHeader(buf, from, key.leaf, 58, 0, hops, ident)
	return buf
}

// expire ends each mapping with no request or reply for echoIdle at now
func (e *echoRelay) expire(now time.Time) {
	idle := now.Add(-echoIdle).UnixNano()
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, m := range e.mappings {
		if m.last.Load() <= idle {
			delete(e.mappings, key)
			e.close(m)
		}
	}
}

// close ends m: its socket closed, its identifier and its flow given back
func (e *echoRelay) close(m *echoMapping) {
	_ = m.socket.close()
	delete(e.held, m.outside)
	e.x.flows.release(m.key.leaf)
}

func (e *echoRelay) withdraw() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.withdrawn = true
	for key, m := range e.mappings {
		delete(e.mappings, key)
		e.close(m)
	}
}

func (e *echoRelay) resume() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.withdrawn = false
}
