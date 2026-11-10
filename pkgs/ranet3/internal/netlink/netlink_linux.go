// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

// Package netlink is the netlink request and reply socket, the codec of its
// messages and attributes, and the socket notifications are read from.
package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// Conn is one netlink socket used for synchronous request and reply. One
// goroutine at a time uses each, so it needs no locking. Notifications arrive
// on a separate socket, so an unsolicited message can never be mistaken for a
// reply.
type Conn struct {
	fd  int
	pid uint32
	seq uint32
	buf []byte
}

// Options set a socket up beyond its protocol
type Options struct {
	// Strict has the kernel check each request whole and honor the filters a dump carries
	Strict bool
	// Timeout bounds each wait for a datagram, and zero waits for good
	Timeout time.Duration
	// ReceiveBuffer is the receive buffer asked for, past rmem_max where the process may, and zero keeps the kernel's
	ReceiveBuffer int
}

func Dial(protocol int, options Options) (*Conn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, fmt.Errorf("netlink: open a socket of protocol %d: %w", protocol, err)
	}
	c, err := bind(fd, options)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink: %w, on a socket of protocol %d", err, protocol)
	}
	return c, nil
}

func bind(fd int, options Options) (*Conn, error) {
	// binding with no port lets the kernel pick one, so several sockets in
	// this process and several processes on the box can coexist
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	if options.Strict {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1); err != nil {
			return nil, fmt.Errorf("ask for strict checking, which needs linux 4.20 or later: %w", err)
		}
	}
	if options.Timeout > 0 {
		timeout := unix.NsecToTimeval(options.Timeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return nil, fmt.Errorf("set the receive timeout: %w", err)
		}
	}
	if options.ReceiveBuffer > 0 {
		growReceiveBuffer(fd, options.ReceiveBuffer)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("read the socket's name: %w", err)
	}
	local, ok := name.(*unix.SockaddrNetlink)
	if !ok {
		return nil, errors.New("the socket is not a netlink socket")
	}
	return &Conn{fd: fd, pid: local.Pid, buf: make([]byte, readSize)}, nil
}

func (c *Conn) Close() error { return unix.Close(c.fd) }

// Fd is the socket's descriptor, for an option of its owner's
func (c *Conn) Fd() int { return c.fd }

// Pid is the port the kernel gave the socket, which it stamps on every reply
// and on every notification of a change made through it
func (c *Conn) Pid() uint32 { return c.pid }

// Next is the sequence number of the socket's next request
func (c *Conn) Next() uint32 {
	c.seq++
	return c.seq
}

// Send sends one datagram of requests, each framed by AppendMessage
func (c *Conn) Send(datagram []byte) error {
	return unix.Sendto(c.fd, datagram, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// Execute sends a request and collects every reply the kernel sends for it.
// A dump ends at NLMSG_DONE and a modify request at its NLMSG_ERROR ack, so
// every modify request must carry NLM_F_ACK, or this waits until the socket's
// Options.Timeout, and for good on a socket without one. A dump the kernel
// flags as interrupted is asked again, dumpAttempts asks in all.
func (c *Conn) Execute(kind, flags uint16, body []byte) ([]Message, error) {
	return execute(c, kind, flags, body)
}

// socket holds the methods of a Conn that execute calls
type socket interface {
	Next() uint32
	Pid() uint32
	Send([]byte) error
	Receive() ([]Message, error)
}

// execute sends the request under a sequence number of its own and collects its replies, and asks a dump the kernel flags
// interrupted again under the next, dumpAttempts asks in all
// it asks again only after collect has read the interrupted dump to its end, so the next ask meets no dump still running on the
// socket
// it takes the socket's parts rather than a Conn so any sequence of datagrams can answer the asks without a socket
func execute(s socket, kind, flags uint16, body []byte) ([]Message, error) {
	attempts := 1
	if flags&unix.NLM_F_DUMP == unix.NLM_F_DUMP {
		attempts = dumpAttempts
	}
	for attempt := 1; ; attempt++ {
		seq := s.Next()
		if err := s.Send(AppendMessage(nil, kind, flags|unix.NLM_F_REQUEST, seq, s.Pid(), body)); err != nil {
			return nil, err
		}
		replies, err := collect(seq, s.Pid(), s.Receive)
		if !errors.Is(err, ErrDumpInterrupted) || attempt == attempts {
			return replies, err
		}
	}
}

// ErrDumpInterrupted is a dump a change interrupted, whose replies may miss or repeat an entry
var ErrDumpInterrupted = errors.New("netlink: dump interrupted by a change")

// errNotFromKernel is a datagram another socket sent
var errNotFromKernel = errors.New("netlink: a reply did not come from the kernel")

// errNoAnswer is a wait for a datagram that outlasted the socket's timeout
var errNoAnswer = errors.New("netlink: the kernel did not answer in time")

// collect reads datagrams until the message ending request seq of port pid, and returns the replies before it
// NLMSG_DONE carries an errno as an ack does, and a dump the kernel cut short still ends at DONE
// so a nonzero errno comes back as the error with none of the replies, never as a table that looks complete
// nor does a dump whose reply or end carries NLM_F_DUMP_INTR, which comes back as ErrDumpInterrupted
// it takes the socket's read as a function so any sequence of messages can be decoded without a socket
func collect(seq, pid uint32, receive func() ([]Message, error)) ([]Message, error) {
	var replies []Message
	interrupted := func(message Message) bool { return message.Flags&unix.NLM_F_DUMP_INTR != 0 }
	finish := func(end Message) ([]Message, error) {
		if interrupted(end) || slices.ContainsFunc(replies, interrupted) {
			return nil, ErrDumpInterrupted
		}
		return replies, nil
	}
	for {
		messages, err := receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Seq != seq || message.Pid != pid {
				continue // a late reply to an abandoned request
			}
			switch message.Kind {
			case unix.NLMSG_NOOP:
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return nil, errors.New("netlink: truncated errno")
				}
				if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
					return nil, unix.Errno(-code)
				}
				return finish(message)
			default:
				replies = append(replies, message)
				if message.Flags&unix.NLM_F_MULTI == 0 {
					return finish(message)
				}
			}
		}
	}
}

// Receive reads one datagram whole and returns its messages. MSG_PEEK with
// MSG_TRUNC reports the real length first, so a dump larger than the current
// buffer grows it instead of silently losing the tail.
func (c *Conn) Receive() ([]Message, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_PEEK|unix.MSG_TRUNC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		// a read returns EAGAIN on this blocking socket only where its timeout ran out
		if errors.Is(err, unix.EAGAIN) {
			return nil, errNoAnswer
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
			return nil, errNotFromKernel
		}
		// parsed messages point into the buffer they came from, and a
		// multipart dump arrives as several datagrams, so each one gets its
		// own copy rather than being overwritten by the next.
		return ParseMessages(slices.Clone(c.buf[:n]))
	}
}

// Message is one parsed netlink message: its header fields, and its body with
// a fixed struct and the attributes after it
type Message struct {
	Kind  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
	Data  []byte
}

// ParseMessages splits one datagram into messages. A length running past the
// buffer is an error rather than a short read, so a truncated dump can never
// look like a complete one.
func ParseMessages(buf []byte) ([]Message, error) {
	var out []Message
	for len(buf) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(buf[0:]))
		if length < unix.SizeofNlMsghdr || length > len(buf) {
			return nil, errors.New("netlink: malformed message length")
		}
		out = append(out, Message{
			Kind:  binary.NativeEndian.Uint16(buf[4:]),
			Flags: binary.NativeEndian.Uint16(buf[6:]),
			Seq:   binary.NativeEndian.Uint32(buf[8:]),
			Pid:   binary.NativeEndian.Uint32(buf[12:]),
			Data:  buf[unix.SizeofNlMsghdr:length],
		})
		next := nlmsgAlign(length)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return out, nil
}

// Attributes iterates the attributes that follow a fixed header of offset bytes
func (m Message) Attributes(offset int) iter.Seq2[uint16, []byte] {
	if len(m.Data) < offset {
		return func(func(uint16, []byte) bool) {}
	}
	return Attributes(m.Data[offset:])
}

// Attributes iterates the attributes in buf, each type with NLA_F_NESTED and
// NLA_F_NET_BYTEORDER masked off as the kernel's nla_type reads it. A
// malformed attribute ends the iteration: the kernel never emits one, and a
// half-decoded message fails the checks that follow rather than being acted
// on.
func Attributes(buf []byte) iter.Seq2[uint16, []byte] {
	return func(yield func(uint16, []byte) bool) {
		for len(buf) >= unix.SizeofRtAttr {
			length := int(binary.NativeEndian.Uint16(buf[0:]))
			kind := binary.NativeEndian.Uint16(buf[2:]) & nlaTypeMask
			if length < unix.SizeofRtAttr || length > len(buf) {
				return
			}
			if !yield(kind, buf[unix.SizeofRtAttr:length]) {
				return
			}
			next := AttrAlign(length)
			if next >= len(buf) {
				return
			}
			buf = buf[next:]
		}
	}
}

// AppendMessage appends one message, its header and body, padded to the
// netlink alignment. The header is native endian, whatever its body holds.
func AppendMessage(buf []byte, kind, flags uint16, seq, pid uint32, body []byte) []byte {
	length := unix.SizeofNlMsghdr + len(body)
	start := len(buf)
	buf = append(buf, make([]byte, nlmsgAlign(length))...)
	binary.NativeEndian.PutUint32(buf[start:], uint32(length))
	binary.NativeEndian.PutUint16(buf[start+4:], kind)
	binary.NativeEndian.PutUint16(buf[start+6:], flags)
	binary.NativeEndian.PutUint32(buf[start+8:], seq)
	binary.NativeEndian.PutUint32(buf[start+12:], pid)
	copy(buf[start+unix.SizeofNlMsghdr:], body)
	return buf
}

// PutAttr appends one attribute, padded the way the kernel's own NLA_ALIGN
// pads it. The length field stays unpadded, as the kernel expects.
func PutAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, AttrAlign(length))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

func PutAttrU32(buf []byte, kind uint16, value uint32) []byte {
	return PutAttr(buf, kind, binary.NativeEndian.AppendUint32(nil, value))
}

func PutAttrString(buf []byte, kind uint16, value string) []byte {
	return PutAttr(buf, kind, append([]byte(value), 0))
}

func nlmsgAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

func AttrAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1) }

// AddressBytes is the wire form of an address: four bytes for IPv4 and sixteen
// otherwise. A 4-in-6 address stays sixteen bytes, because sadr keeps such a
// prefix in its IPv6 table and the kernel would too.
func AddressBytes(address netip.Addr) []byte {
	if address.Is4() {
		raw := address.As4()
		return raw[:]
	}
	raw := address.As16()
	return raw[:]
}
