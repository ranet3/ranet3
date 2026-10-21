// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

// Package nftables speaks nf_tables over NETLINK_NETFILTER directly, the way
// internal/kernel speaks rtnetlink: no `nft` to shell out to, no library to
// add, and the same request and reply discipline on one socket used by one
// goroutine.
//
// Two things about nf_tables differ from rtnetlink. Every integer in an NFTA_
// attribute is big endian, header fields included, while the netlink header
// itself stays native. And every write is a transaction: a batch between
// NFNL_MSG_BATCH_BEGIN and NFNL_MSG_BATCH_END commits whole or not at all,
// which is how a chain is replaced with no window in which a packet meets
// half of it.
package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Tables is the flags of each table named name, keyed by its nf_tables
// family
func Tables(conn *Conn, name string) (map[uint8]uint32, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETTABLE), PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump tables: %w", err)
	}
	held := make(map[uint8]uint32)
	for _, reply := range replies {
		if len(reply.Data) < SizeofNfgenmsg {
			continue
		}
		var table string
		var flags uint32
		for kind, value := range reply.Attributes() {
			switch {
			case kind == unix.NFTA_TABLE_NAME:
				table = unix.ByteSliceToString(value)
			case kind == unix.NFTA_TABLE_FLAGS && len(value) == 4:
				flags = binary.BigEndian.Uint32(value)
			}
		}
		if table == name {
			held[reply.Data[0]] = flags
		}
	}
	return held, nil
}

// NewTable creates the table name in the nf_tables family proto if it is
// absent and adopts it if it is there, which is how a table a previous
// instance left behind is taken over. It writes the flags as none over
// whatever another writer set, so a dormant table is woken.
func NewTable(proto uint8, name string) Request {
	table := tableRequest(unix.NFT_MSG_NEWTABLE, unix.NLM_F_CREATE, proto, name)
	table.Body = PutAttrBE32(table.Body, unix.NFTA_TABLE_FLAGS, 0)
	return table
}

// DeleteTable's request takes every chain in the table with it
func DeleteTable(proto uint8, name string) Request {
	return tableRequest(unix.NFT_MSG_DELTABLE, 0, proto, name)
}

func tableRequest(command int, flags uint16, proto uint8, name string) Request {
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_TABLE_NAME, name)
	return Request{Kind: Command(command), Flags: flags, Body: body}
}

// Chain is a base chain one owner writes in its table, which accepts what no
// rule decides
type Chain struct {
	Table    string
	Name     string
	Type     string
	Hook     uint32
	Priority int32
}

// Create writes c's policy over whatever another writer set
func (c Chain) Create(proto uint8) Request {
	hooked := PutAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, c.Hook)
	hooked = PutAttrBE32(hooked, unix.NFTA_HOOK_PRIORITY, uint32(c.Priority))
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_CHAIN_TABLE, c.Table)
	body = PutAttrString(body, unix.NFTA_CHAIN_NAME, c.Name)
	body = PutAttr(body, unix.NFTA_CHAIN_HOOK|unix.NLA_F_NESTED, hooked)
	body = PutAttrBE32(body, unix.NFTA_CHAIN_POLICY, Accept)
	body = PutAttrString(body, unix.NFTA_CHAIN_TYPE, c.Type)
	return Request{Kind: Command(unix.NFT_MSG_NEWCHAIN), Flags: unix.NLM_F_CREATE, Body: body}
}

// Flush names no handle, which nf_tables reads as every rule in the chain
func (c Chain) Flush(proto uint8) Request {
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_RULE_TABLE, c.Table)
	body = PutAttrString(body, unix.NFTA_RULE_CHAIN, c.Name)
	return Request{Kind: Command(unix.NFT_MSG_DELRULE), Body: body}
}

// Rule carries spec as the rule's comment and identity, so a rule reads in
// `nft list ruleset` exactly as its owner's diff spells it
func (c Chain) Rule(proto uint8, spec string, expressions [][]byte) (Request, error) {
	// a longer comment still lists in `nft list ruleset`, but nft -f will not load that listing back
	if len(spec) > udataCommentMax {
		return Request{}, fmt.Errorf("nftables: rule %s does not fit in a %d byte comment, which is its identity on the host", spec, udataCommentMax)
	}
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_RULE_TABLE, c.Table)
	body = PutAttrString(body, unix.NFTA_RULE_CHAIN, c.Name)
	body = PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, slices.Concat(expressions...))
	body = PutAttr(body, unix.NFTA_RULE_USERDATA, userdata(spec))
	return Request{Kind: Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND, Body: body}, nil
}

// Fault names how the chain a dump holds differs from c as Create writes it,
// empty for that chain as written and for any other. remake holds where it
// differs in what nf_tables will not change in place: its type, hook or
// priority, or a hook at all, since a regular chain cannot become a base
// chain.
func (c Chain) Fault(message Message) (fault string, remake bool) {
	table, chain, kind, hook, priority := DecodeChain(message)
	if table != c.Table || chain != c.Name {
		return "", false
	}
	policy := ^uint32(0)
	for attribute, value := range message.Attributes() {
		if attribute == unix.NFTA_CHAIN_POLICY && len(value) == 4 {
			policy = binary.BigEndian.Uint32(value)
		}
	}
	remake = kind != c.Type || hook != c.Hook || priority != c.Priority
	if !remake && policy == Accept {
		return "", false
	}
	return fmt.Sprintf("its chain reads back as type %q at hook %d, priority %d, policy %d, where a %s chain at hook %d, priority %d, policy accept was written",
		kind, int32(hook), priority, int32(policy), c.Type, c.Hook, c.Priority), remake
}

// Installed is one rule as a dump read it back: the comment it was written
// under, empty for a rule with none, and its counter
type Installed struct {
	Spec    string
	Packets uint64
	Bytes   uint64
}

// Readback is a chain and the table holding it in one nf_tables family, as a
// dump finds them
type Readback struct {
	// Rules is every rule of the chain in order
	Rules []Installed
	// Fault names how the table or the chain differs from what NewTable and
	// Create write, empty where neither does
	Fault string
	// Remake holds where the table or the chain differs in what nf_tables
	// will not change in place, a table flag other than dormant, or the
	// chain's type, hook or priority or a hook at all, so its owner deletes
	// the table and makes it again in one transaction
	Remake bool
}

// Read takes tables as Tables read them
func (c Chain) Read(conn *Conn, tables map[uint8]uint32, proto uint8) (Readback, error) {
	flags, held := tables[proto]
	if !held {
		return Readback{}, nil
	}
	var read Readback
	if flags != 0 {
		read.Fault = fmt.Sprintf("its table carries flags %#x, where none are written and 0x1 is dormant", flags)
	}
	// nf_tables clears no flag of a table in place but dormant
	read.Remake = flags&^unix.NFT_TABLE_F_DORMANT != 0
	chains, err := conn.Dump(Command(unix.NFT_MSG_GETCHAIN), PutNfgenmsg(nil, proto))
	if err != nil {
		return Readback{}, fmt.Errorf("dump chains: %w", err)
	}
	for _, reply := range chains {
		fault, remake := c.Fault(reply)
		if read.Fault == "" {
			read.Fault = fault
		}
		read.Remake = read.Remake || remake
	}
	if read.Rules, err = c.rules(conn, proto); err != nil {
		return Readback{}, fmt.Errorf("dump rules: %w", err)
	}
	return read, nil
}

func (c Chain) rules(conn *Conn, proto uint8) ([]Installed, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETRULE), PutNfgenmsg(nil, proto))
	if err != nil {
		return nil, err
	}
	var out []Installed
	for _, reply := range replies {
		if table, name, spec, packets, bytes := DecodeRule(reply); table == c.Table && name == c.Name {
			out = append(out, Installed{Spec: spec, Packets: packets, Bytes: bytes})
		}
	}
	return out, nil
}

// DecodeChain reads where a chain lives and how it is hooked. A chain with no
// hook is a regular chain, reached by a jump rather than by the packet path,
// so the absent hook reads as one no packet enters at.
func DecodeChain(message Message) (table, chain, kind string, hook uint32, priority int32) {
	hook = ^uint32(0)
	for attribute, value := range message.Attributes() {
		switch attribute {
		case unix.NFTA_CHAIN_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_NAME:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_TYPE:
			kind = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_HOOK:
			for _, field := range Nested(value) {
				if len(field.Value) != 4 {
					continue
				}
				switch field.Kind {
				case unix.NFTA_HOOK_HOOKNUM:
					hook = binary.BigEndian.Uint32(field.Value)
				case unix.NFTA_HOOK_PRIORITY:
					priority = int32(binary.BigEndian.Uint32(field.Value))
				}
			}
		}
	}
	return table, chain, kind, hook, priority
}

// DecodeRule reads the fields a diff and a report need: where the rule lives,
// the comment its owner wrote as its identity, and the counter. The
// expressions are walked only far enough to find that counter, because the
// comment already says what the rule does and re-deriving it from the
// expressions would be a second encoder to keep in step with the first.
func DecodeRule(message Message) (table, chain, spec string, packets, bytes uint64) {
	for kind, value := range message.Attributes() {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_USERDATA:
			spec = comment(value)
		case unix.NFTA_RULE_EXPRESSIONS:
			packets, bytes = counters(value)
		}
	}
	return table, chain, spec, packets, bytes
}

// comment is the rule's identity out of the libnftnl userdata format: a
// sequence of type, length and value triples, of which Rule writes exactly
// one
func comment(userdata []byte) string {
	for len(userdata) >= 2 {
		kind, length := userdata[0], int(userdata[1])
		if len(userdata) < 2+length {
			return ""
		}
		if kind == udataComment {
			return strings.TrimRight(string(userdata[2:2+length]), "\x00")
		}
		userdata = userdata[2+length:]
	}
	return ""
}

// counters walks the expression list for a counter. In a nat chain the count
// is of flows rather than of packets: such a chain is evaluated once per
// connection, when conntrack first sees it.
func counters(expressions []byte) (packets, bytes uint64) {
	for _, element := range Nested(expressions) {
		if element.Kind != unix.NFTA_LIST_ELEM {
			continue
		}
		var name string
		var data []byte
		for _, field := range Nested(element.Value) {
			switch field.Kind {
			case unix.NFTA_EXPR_NAME:
				name = unix.ByteSliceToString(field.Value)
			case unix.NFTA_EXPR_DATA:
				data = field.Value
			}
		}
		if name != "counter" {
			continue
		}
		for _, field := range Nested(data) {
			if len(field.Value) != 8 {
				continue
			}
			switch field.Kind {
			case unix.NFTA_COUNTER_BYTES:
				bytes = binary.BigEndian.Uint64(field.Value)
			case unix.NFTA_COUNTER_PACKETS:
				packets = binary.BigEndian.Uint64(field.Value)
			}
		}
	}
	return packets, bytes
}

// userdata is the comment in the format libnftnl reads, so `nft list ruleset`
// prints it beside the rule
func userdata(spec string) []byte {
	value := append([]byte(spec), 0)
	return append([]byte{udataComment, byte(len(value))}, value...)
}

// DeviceName refuses a name too long to be a device's. The kernel caps one at
// IFNAMSIZ-1, and a comparison of 16 bytes with no terminator equals no
// interface register: the rule would install and then match nothing, or
// through a "not" everything.
func DeviceName(name string) error {
	if len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("nftables: interface %q is %d bytes, and a device name is at most %d", name, len(name), unix.IFNAMSIZ-1)
	}
	return nil
}

// MetaCompare loads one interface name and compares it, over the full
// IFNAMSIZ the kernel pads it to. A shorter comparison would match every
// device whose name starts the same way.
func MetaCompare(key uint32, op int, name string) [][]byte {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return MetaCompareValue(key, op, padded)
}

func MetaCompareValue(key uint32, op int, value []byte) [][]byte {
	meta := PutAttrBE32(nil, unix.NFTA_META_KEY, key)
	meta = PutAttrBE32(meta, unix.NFTA_META_DREG, unix.NFT_REG_1)
	return [][]byte{Expression("meta", meta), Expression("cmp", Compare(op, value))}
}

func SourcePrefix(prefix netip.Prefix) [][]byte {
	offset, length := uint32(ipv6SourceOffset), uint32(net.IPv6len)
	if prefix.Addr().Is4() {
		offset, length = ipv4SourceOffset, net.IPv4len
	}
	out := [][]byte{NetworkLoad(offset, length)}
	if int(prefix.Bits()) < int(length)*8 {
		mask := prefixMask(prefix)
		bitwise := PutAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
		bitwise = PutAttrBE32(bitwise, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
		bitwise = PutAttrBE32(bitwise, unix.NFTA_BITWISE_LEN, length)
		bitwise = PutAttr(bitwise, unix.NFTA_BITWISE_MASK|unix.NLA_F_NESTED, PutAttr(nil, unix.NFTA_DATA_VALUE, mask))
		bitwise = PutAttr(bitwise, unix.NFTA_BITWISE_XOR|unix.NLA_F_NESTED,
			PutAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, length)))
		out = append(out, Expression("bitwise", bitwise))
	}
	return append(out, Expression("cmp", Compare(unix.NFT_CMP_EQ, AddressBytes(prefix.Masked().Addr()))))
}

func NetworkLoad(offset, length uint32) []byte {
	load := PutAttrBE32(nil, unix.NFTA_PAYLOAD_DREG, unix.NFT_REG_1)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_BASE, unix.NFT_PAYLOAD_NETWORK_HEADER)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_OFFSET, offset)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_LEN, length)
	return Expression("payload", load)
}

func prefixMask(prefix netip.Prefix) []byte {
	length := net.IPv6len
	if prefix.Addr().Is4() {
		length = net.IPv4len
	}
	mask := make([]byte, length)
	bits := prefix.Bits()
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return mask
}

func Compare(op int, value []byte) []byte {
	body := PutAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1)
	body = PutAttrBE32(body, unix.NFTA_CMP_OP, uint32(op))
	return PutAttr(body, unix.NFTA_CMP_DATA|unix.NLA_F_NESTED, PutAttr(nil, unix.NFTA_DATA_VALUE, value))
}

// Expression emits the data attribute even when empty, as libnftnl does, so
// an expression carrying no parameters still reads as one
func Expression(name string, data []byte) []byte {
	body := PutAttrString(nil, unix.NFTA_EXPR_NAME, name)
	body = PutAttr(body, unix.NFTA_EXPR_DATA|unix.NLA_F_NESTED, data)
	return PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, body)
}

// AddressBytes is the wire form of an address, four bytes or sixteen, never
// the 4-in-6 form: a table or a test is of one family by the time an address
// is encoded.
func AddressBytes(address netip.Addr) []byte {
	if address.Is4() {
		raw := address.As4()
		return raw[:]
	}
	raw := address.As16()
	return raw[:]
}

// Conn is one NETLINK_NETFILTER socket used for synchronous request and reply.
// Its owner's one goroutine is its only caller, so it needs no locking, and
// nothing subscribes to a notification group, so an unsolicited message can
// never arrive on it.
type Conn struct {
	fd  int
	pid uint32
	seq uint32
	buf []byte
}

func Dial() (*Conn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nftables: open netfilter netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nftables: bind netfilter netlink socket: %w", err)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nftables: read netfilter netlink socket name: %w", err)
	}
	local, ok := name.(*unix.SockaddrNetlink)
	if !ok {
		_ = unix.Close(fd)
		return nil, errors.New("nftables: netfilter socket is not a netlink socket")
	}
	timeout := unix.Timeval{Sec: replyTimeout}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nftables: set netfilter netlink receive timeout: %w", err)
	}
	// Every message in a transaction is acknowledged, and the kernel queues
	// all of those acks while this process is still inside its one send, with
	// nothing draining them. The default receive buffer holds a few hundred,
	// which a few hundred rules would exceed, and the overflow arrives as an
	// ENOBUFS that explains nothing.
	growReceiveBuffer(fd)
	return &Conn{fd: fd, pid: local.Pid, buf: make([]byte, replyReadSize)}, nil
}

func (c *Conn) Close() error { return unix.Close(c.fd) }

// Request is one message inside a transaction
type Request struct {
	Kind  uint16
	Flags uint16
	Body  []byte
}

func Command(command int) uint16 {
	return uint16(unix.NFNL_SUBSYS_NFTABLES)<<8 | uint16(command)
}

// Message is one parsed reply: the header fields read here plus the body,
// which holds a struct nfgenmsg and the attributes after it
type Message struct {
	Kind uint16
	Seq  uint32
	Pid  uint32
	Data []byte
}

// Batch sends one transaction and waits for the kernel to acknowledge every
// message in it. Everything between the batch markers commits together or not
// at all, so a failure leaves the host holding exactly what it held before.
//
// A failure inside the batch is reported against the message that caused it,
// and a failure of the commit itself against the batch marker, so any nonzero
// error in the range this call owns ends it. Acknowledgments left in the
// socket by an earlier call carry earlier sequence numbers and are ignored
// rather than mistaken for this call's.
func (c *Conn) Batch(requests []Request) error {
	if len(requests) == 0 {
		return nil
	}
	marker := putNfgenmsgSubsys(nil, unix.NFPROTO_UNSPEC)
	begin := c.next()
	var buf []byte
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_BEGIN, 0, begin, marker)
	expected := make(map[uint32]bool, len(requests))
	first, last := begin, begin
	for _, request := range requests {
		seq := c.next()
		expected[seq] = true
		last = seq
		buf = c.appendMessage(buf, request.Kind, request.Flags|unix.NLM_F_ACK, seq, request.Body)
	}
	end := c.next()
	last = end
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_END, 0, end, marker)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	for len(expected) > 0 {
		messages, err := c.receive()
		if err != nil {
			return err
		}
		for _, message := range messages {
			// subtracted rather than compared, so a sequence number that wraps
			// inside one transaction narrows the window rather than inverting it
			if message.Pid != c.pid || message.Seq-first > last-first {
				continue
			}
			if message.Kind != unix.NLMSG_ERROR {
				continue
			}
			if len(message.Data) < 4 {
				return errors.New("nftables: truncated netlink error")
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return unix.Errno(-code)
			}
			delete(expected, message.Seq)
		}
	}
	return nil
}

func (c *Conn) Dump(kind uint16, body []byte) ([]Message, error) {
	seq := c.next()
	buf := c.appendMessage(nil, kind, unix.NLM_F_DUMP, seq, body)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies []Message
	for {
		messages, err := c.receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Seq != seq || message.Pid != c.pid {
				continue
			}
			switch message.Kind {
			case unix.NLMSG_NOOP:
			case unix.NLMSG_DONE:
				return replies, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return nil, errors.New("nftables: truncated netlink error")
				}
				if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
					return nil, unix.Errno(-code)
				}
				return replies, nil
			default:
				replies = append(replies, message)
			}
		}
	}
}

func (c *Conn) next() uint32 {
	c.seq++
	return c.seq
}

// appendMessage writes one netlink message, header and body, padded as the
// kernel expects. The header fields are native endian, but everything inside an
// NFTA attribute is not.
func (c *Conn) appendMessage(buf []byte, kind, flags uint16, seq uint32, body []byte) []byte {
	length := unix.SizeofNlMsghdr + len(body)
	start := len(buf)
	buf = append(buf, make([]byte, nlmsgAlign(length))...)
	binary.NativeEndian.PutUint32(buf[start:], uint32(length))
	binary.NativeEndian.PutUint16(buf[start+4:], kind)
	binary.NativeEndian.PutUint16(buf[start+6:], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(buf[start+8:], seq)
	binary.NativeEndian.PutUint32(buf[start+12:], c.pid)
	copy(buf[start+unix.SizeofNlMsghdr:], body)
	return buf
}

// receive reads one datagram whole, growing the buffer when the kernel has
// more to say than it currently holds, exactly as internal/kernel does
func (c *Conn) receive() ([]Message, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_PEEK|unix.MSG_TRUNC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("nftables: the kernel did not answer a netfilter netlink request")
		}
		if err != nil {
			return nil, err
		}
		if n <= len(c.buf) {
			break
		}
		c.buf = make([]byte, n)
	}
	for {
		n, from, err := unix.Recvfrom(c.fd, c.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			return nil, errors.New("nftables: netfilter reply did not come from the kernel")
		}
		return parseMessages(slices.Clone(c.buf[:n]))
	}
}

// parseMessages splits one datagram into messages. A length running past the
// buffer is an error rather than a short read, so a truncated dump can never
// look like a complete one.
func parseMessages(buf []byte) ([]Message, error) {
	var out []Message
	for len(buf) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(buf[0:]))
		if length < unix.SizeofNlMsghdr || length > len(buf) {
			return nil, errors.New("nftables: malformed netlink message length")
		}
		out = append(out, Message{
			Kind: binary.NativeEndian.Uint16(buf[4:]),
			Seq:  binary.NativeEndian.Uint32(buf[8:]),
			Pid:  binary.NativeEndian.Uint32(buf[12:]),
			Data: buf[unix.SizeofNlMsghdr:length],
		})
		next := nlmsgAlign(length)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return out, nil
}

// Attributes iterates the attributes that follow the message's struct
// nfgenmsg. A malformed attribute ends the iteration: the kernel emits none,
// and a half-decoded message fails the name checks that follow rather than
// being acted on.
func (m Message) Attributes() iter.Seq2[uint16, []byte] {
	return func(yield func(uint16, []byte) bool) {
		if len(m.Data) < SizeofNfgenmsg {
			return
		}
		for _, field := range Nested(m.Data[SizeofNfgenmsg:]) {
			if !yield(field.Kind, field.Value) {
				return
			}
		}
	}
}

// Attribute's Kind has NLA_F_NESTED masked off
type Attribute struct {
	Kind  uint16
	Value []byte
}

func Nested(buf []byte) []Attribute {
	var out []Attribute
	for len(buf) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(buf[0:]))
		kind := binary.NativeEndian.Uint16(buf[2:]) & nlaTypeMask
		if length < unix.SizeofRtAttr || length > len(buf) {
			return out
		}
		out = append(out, Attribute{Kind: kind, Value: buf[unix.SizeofRtAttr:length]})
		next := rtaAlign(length)
		if next >= len(buf) {
			return out
		}
		buf = buf[next:]
	}
	return out
}

func PutNfgenmsg(buf []byte, family uint8) []byte {
	return append(buf, family, nfnetlinkV0, 0, 0)
}

// putNfgenmsgSubsys writes struct nfgenmsg for a batch marker, whose res_id
// names the subsystem the transaction belongs to. It is big endian, unlike the
// netlink header around it.
func putNfgenmsgSubsys(buf []byte, family uint8) []byte {
	buf = append(buf, family, nfnetlinkV0, 0, 0)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(unix.NFNL_SUBSYS_NFTABLES))
	return buf
}

func PutAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, rtaAlign(length))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

// PutAttrBE32 writes a 32-bit attribute in network byte order, which is how
// nf_tables carries every number in an NFTA attribute
func PutAttrBE32(buf []byte, kind uint16, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return PutAttr(buf, kind, raw[:])
}

func PutAttrString(buf []byte, kind uint16, value string) []byte {
	return PutAttr(buf, kind, append([]byte(value), 0))
}

func nlmsgAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

func rtaAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1) }
