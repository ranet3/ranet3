// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// answeredSeq and answeredPid are the request the drawn messages answer and the port that sent it
const answeredSeq, answeredPid = 41, 7001

// maxErrno is the largest errno an end message carries, the kernel's MAX_ERRNO
const maxErrno = 4095

// answers draws a reply to the request
// most are one part of a multipart dump
// one without NLM_F_MULTI is the whole answer to a keyed request
// a few carry NLM_F_DUMP_INTR, which the kernel sets on a part of a dump a change interrupted
func answers() hegel.Generator[Message] {
	return hegel.Composite(func(tc hegel.TestCase) Message {
		flags := unix.NLM_F_MULTI | hegel.Draw(tc, hegel.Integers[uint16](0, math.MaxUint16))&^unix.NLM_F_DUMP_INTR
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			flags &^= unix.NLM_F_MULTI
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			flags |= unix.NLM_F_DUMP_INTR
		}
		return Message{
			Kind:  hegel.Draw(tc, pbt.Spanning[uint16](unix.NLMSG_MIN_TYPE, math.MaxUint16)),
			Flags: flags,
			Seq:   answeredSeq,
			Pid:   answeredPid,
			Data:  hegel.Draw(tc, hegel.Binary(0, 64)),
		}
	})
}

// strays draws a message the request's replies have to pass over
// a NOOP of the request, or a message of another request or another port of any kind, an end with an errno among them
func strays() hegel.Generator[Message] {
	return hegel.Composite(func(tc hegel.TestCase) Message {
		message := Message{
			Kind:  hegel.Draw(tc, hegel.OneOf(hegel.Just[uint16](unix.NLMSG_DONE), hegel.Just[uint16](unix.NLMSG_ERROR), hegel.Integers[uint16](0, math.MaxUint16))),
			Flags: hegel.Draw(tc, hegel.Integers[uint16](0, math.MaxUint16)),
			Seq:   answeredSeq,
			Pid:   answeredPid,
			Data:  hegel.Draw(tc, hegel.Binary(0, 64)),
		}
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 0:
			message.Kind = unix.NLMSG_NOOP
		case 1:
			message.Seq = hegel.Draw(tc, hegel.Filter(hegel.Integers[uint32](0, math.MaxUint32), func(seq uint32) bool { return seq != answeredSeq }))
		default:
			message.Pid = hegel.Draw(tc, hegel.Filter(hegel.Integers[uint32](0, math.MaxUint32), func(pid uint32) bool { return pid != answeredPid }))
		}
		return message
	})
}

// messages appended into one datagram parse back whole and in order, and the attributes put into each body iterate back in order
// with each value as put and each type as nla_type reads it, NLA_F_NESTED and NLA_F_NET_BYTEORDER masked off
func TestMessagesAndAttributesReadBackAsPut(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		type attribute struct {
			kind  uint16
			value []byte
		}
		var datagram []byte
		var sent []Message
		var put [][]attribute
		var offsets []int
		for range hegel.Draw(ht, hegel.Integers(1, 6)) {
			// a fixed header of a whole number of aligned words, as every netlink family's is, and attributes after it, or a raw
			// body of any length, which the length field carries unpadded
			offset := hegel.Draw(ht, hegel.SampledFrom([]int{0, 4, unix.SizeofRtMsg, unix.SizeofIfInfomsg}))
			body := hegel.Draw(ht, hegel.Binary(offset, offset))
			count := hegel.Draw(ht, hegel.Integers(0, 6))
			if hegel.Draw(ht, hegel.Booleans()) {
				body = hegel.Draw(ht, hegel.Binary(0, 40))
				offset, count = len(body), 0
			}
			var attributes []attribute
			for range count {
				// the type is drawn from the 14 bits below the two flags, and the flags outright, from their four combinations
				flags := hegel.Draw(ht, hegel.SampledFrom([]uint16{0, unix.NLA_F_NESTED, unix.NLA_F_NET_BYTEORDER, unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER}))
				a := attribute{
					kind:  hegel.Draw(ht, pbt.Spanning[uint16](0, 1<<14-1)) | flags,
					value: hegel.Draw(ht, hegel.Binary(0, 40)),
				}
				body = PutAttr(body, a.kind, a.value)
				attributes = append(attributes, a)
			}
			message := Message{
				Kind:  hegel.Draw(ht, hegel.Integers[uint16](0, math.MaxUint16)),
				Flags: hegel.Draw(ht, hegel.Integers[uint16](0, math.MaxUint16)),
				Seq:   hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32)),
				Pid:   hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32)),
				Data:  body,
			}
			datagram = AppendMessage(datagram, message.Kind, message.Flags, message.Seq, message.Pid, message.Data)
			sent, put, offsets = append(sent, message), append(put, attributes), append(offsets, offset)
		}
		got, err := ParseMessages(datagram)
		if err != nil || !slices.EqualFunc(got, sent, sameMessage) {
			ht.Fatalf("%d messages read back as %v and %v", len(sent), got, err)
		}
		for i, message := range got {
			var read []attribute
			for kind, value := range message.Attributes(offsets[i]) {
				read = append(read, attribute{kind, value})
			}
			if len(read) != len(put[i]) {
				ht.Fatalf("message %d put %d attributes and read back %d", i, len(put[i]), len(read))
			}
			for j, a := range put[i] {
				if read[j].kind != a.kind&^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER) || !bytes.Equal(read[j].value, a.value) {
					ht.Fatalf("attribute %d of message %d put as type %#x %x reads back as type %#x %x", j, i, a.kind, a.value, read[j].kind, read[j].value)
				}
			}
		}
	})
}

func sameMessage(a, b Message) bool {
	return a.Kind == b.Kind && a.Flags == b.Flags && a.Seq == b.Seq && a.Pid == b.Pid && bytes.Equal(a.Data, b.Data)
}

// appendMessage frames message as linux/netlink.h lays one out, written apart from AppendMessage so a property over the decoder
// does not draw its input through the encoder it shares a layout with
func appendMessage(datagram []byte, message Message) []byte {
	length := unix.SizeofNlMsghdr + len(message.Data)
	start := len(datagram)
	datagram = append(datagram, make([]byte, (length+unix.NLMSG_ALIGNTO-1)&^(unix.NLMSG_ALIGNTO-1))...)
	binary.NativeEndian.PutUint32(datagram[start:], uint32(length))
	binary.NativeEndian.PutUint16(datagram[start+4:], message.Kind)
	binary.NativeEndian.PutUint16(datagram[start+6:], message.Flags)
	binary.NativeEndian.PutUint32(datagram[start+8:], message.Seq)
	binary.NativeEndian.PutUint32(datagram[start+12:], message.Pid)
	copy(datagram[start+unix.SizeofNlMsghdr:], message.Data)
	return datagram
}

// putAttr frames one attribute as linux/netlink.h lays one out, apart from PutAttr for the same reason
func putAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

// a datagram one of whose messages has a length below the header, past the datagram's end, or whose datagram ends inside it, is
// refused whole
// a message length that runs short or long cannot be told from the bytes around it, so no message of the datagram is trusted
func TestMalformedMessageLengthsAreRefused(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var datagram []byte
		var starts, lengths []int
		for range hegel.Draw(ht, hegel.Integers(1, 6)) {
			message := Message{
				Kind:  hegel.Draw(ht, hegel.Integers[uint16](0, math.MaxUint16)),
				Flags: hegel.Draw(ht, hegel.Integers[uint16](0, math.MaxUint16)),
				Seq:   hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32)),
				Pid:   hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32)),
				Data:  hegel.Draw(ht, hegel.Binary(0, 40)),
			}
			starts, lengths = append(starts, len(datagram)), append(lengths, unix.SizeofNlMsghdr+len(message.Data))
			datagram = appendMessage(datagram, message)
		}
		bad := hegel.Draw(ht, hegel.Integers(0, len(starts)-1))
		start, length := starts[bad], lengths[bad]
		how := hegel.Draw(ht, hegel.SampledFrom([]string{"below the header", "past the end", "cut short"}))
		if how == "cut short" && length == unix.SizeofNlMsghdr {
			how = "past the end"
		}
		switch how {
		case "below the header":
			binary.NativeEndian.PutUint32(datagram[start:], uint32(hegel.Draw(ht, hegel.Integers(0, unix.SizeofNlMsghdr-1))))
		case "past the end":
			binary.NativeEndian.PutUint32(datagram[start:], uint32(len(datagram)-start+hegel.Draw(ht, hegel.Integers(1, 64))))
		default:
			// the header stays whole, so the length it carries runs past the cut
			datagram = datagram[:start+hegel.Draw(ht, hegel.Integers(unix.SizeofNlMsghdr, length-1))]
		}
		if got, err := ParseMessages(datagram); err == nil || got != nil {
			ht.Fatalf("a datagram whose message %d has a length %s read as %d messages and %v", bad, how, len(got), err)
		}
	})
}

// the attributes of a body one of whose attributes has a length below its header, past the body's end, or whose body ends inside
// it, iterate as the ones before that attribute and no other
func TestMalformedAttributeEndsTheAttributes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		type attribute struct {
			kind  uint16
			value []byte
		}
		var body []byte
		var put []attribute
		var starts []int
		for range hegel.Draw(ht, hegel.Integers(1, 6)) {
			a := attribute{hegel.Draw(ht, hegel.Integers[uint16](0, 1<<14-1)), hegel.Draw(ht, hegel.Binary(0, 40))}
			starts, put = append(starts, len(body)), append(put, a)
			body = putAttr(body, a.kind, a.value)
		}
		// the body sits inside a larger buffer, as one message's attributes sit inside a datagram, so a value read past the body's
		// end reads the bytes after it rather than failing
		body = append(body, hegel.Draw(ht, hegel.Binary(64, 64))...)[:len(body)]
		bad := hegel.Draw(ht, hegel.Integers(0, len(starts)-1))
		start, length := starts[bad], unix.SizeofRtAttr+len(put[bad].value)
		how := hegel.Draw(ht, hegel.SampledFrom([]string{"below the header", "past the end", "cut short"}))
		switch how {
		case "below the header":
			binary.NativeEndian.PutUint16(body[start:], uint16(hegel.Draw(ht, hegel.Integers(0, unix.SizeofRtAttr-1))))
		case "past the end":
			binary.NativeEndian.PutUint16(body[start:], uint16(len(body)-start+hegel.Draw(ht, hegel.Integers(1, 64))))
		default:
			body = body[:start+hegel.Draw(ht, hegel.Integers(1, length-1))]
		}
		var read []attribute
		for kind, value := range Attributes(body) {
			read = append(read, attribute{kind, value})
		}
		if !slices.EqualFunc(read, put[:bad], func(a, b attribute) bool { return a.kind == b.kind && bytes.Equal(a.value, b.value) }) {
			ht.Fatalf("attribute %d of %d with a length %s iterated as %d attributes, want the %d before it", bad, len(put), how, len(read), bad)
		}
	})
}

// an end carrying an errno ends the request with that errno and none of the replies
// a dump the kernel cut short ends that way
// its replies are a table missing what the kernel did not send
// an end carrying zero ends the request with every reply in the order sent
// a reply without NLM_F_MULTI ends it the same way, as the one answer to a keyed request
// a reply or an end of the request carrying NLM_F_DUMP_INTR turns either into ErrDumpInterrupted and none of the replies,
// where the end's errno is zero
// everything else is passed over
// the end is NLMSG_DONE or the ack, which carry the errno in the same place
// what follows the errno is the request's header in an ack and the attributes of an extended one
// an end too short to carry an errno is a failure of its own
// a read that fails before the end is the request's failure, with none of the replies read before it
// the messages are cut into datagrams anywhere
func TestEndCarryingAnErrnoYieldsItAndNoReplies(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var sent, want []Message
		keyed := false
		for range hegel.Draw(ht, hegel.Integers(0, 12)) {
			if !hegel.Draw(ht, hegel.Booleans()) {
				sent = append(sent, hegel.Draw(ht, strays()))
				continue
			}
			answer := hegel.Draw(ht, answers())
			want, sent = append(want, answer), append(sent, answer)
			if keyed = answer.Flags&unix.NLM_F_MULTI == 0; keyed {
				break
			}
		}
		interrupted := slices.ContainsFunc(want, func(answer Message) bool { return answer.Flags&unix.NLM_F_DUMP_INTR != 0 })
		code, truncated := int32(0), false
		if !keyed {
			end := Message{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Seq: answeredSeq, Pid: answeredPid}
			if hegel.Draw(ht, hegel.Booleans()) {
				end.Kind, end.Flags = unix.NLMSG_ERROR, 0
			}
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
				end.Flags |= unix.NLM_F_DUMP_INTR
				interrupted = true
			}
			if truncated = hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)); truncated {
				end.Data = hegel.Draw(ht, hegel.Binary(0, 3))
			} else {
				// ENOENT is drawn by name
				// only the routing table's own dump reads it as an empty table, above this decoder
				code = hegel.Draw(ht, hegel.OneOf(pbt.Spanning[int32](-maxErrno, -1), hegel.Just(-int32(unix.ENOENT)), hegel.Just(int32(0))))
				end.Data = append(binary.NativeEndian.AppendUint32(nil, uint32(code)), hegel.Draw(ht, hegel.Binary(0, 64))...)
			}
			sent = append(sent, end)
		}

		var datagrams [][]byte
		var datagram []byte
		for i, message := range sent {
			if i > 0 && hegel.Draw(ht, hegel.Booleans()) {
				datagrams, datagram = append(datagrams, datagram), nil
			}
			datagram = appendMessage(datagram, message)
		}
		datagrams = append(datagrams, datagram)
		// a read may fail at any datagram up to the one that ends the request, which is the last, as a socket whose queue
		// overflowed or that another socket wrote to fails
		failing, failAt, failure := hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)), -1, error(nil)
		if failing {
			failAt = hegel.Draw(ht, hegel.Integers(0, len(datagrams)-1))
			failure = hegel.Draw(ht, hegel.SampledFrom([]error{unix.ENOBUFS, errNotFromKernel}))
		}
		read := 0
		receive := func() ([]Message, error) {
			if read == len(datagrams) {
				return nil, errors.New("read past the message that ended the request")
			}
			read++
			if read-1 == failAt {
				return nil, failure
			}
			return ParseMessages(datagrams[read-1])
		}

		got, err := collect(answeredSeq, answeredPid, receive)
		if failing {
			if !errors.Is(err, failure) || got != nil {
				ht.Fatalf("a read failing with %v at datagram %d of %d read as %d replies and %v", failure, failAt, len(datagrams), len(got), err)
			}
			return
		}
		switch {
		case keyed:
		case truncated:
			if err == nil || err.Error() != "netlink: truncated errno" || got != nil {
				ht.Fatalf("an end too short for an errno after %d replies read as %d replies and %v", len(want), len(got), err)
			}
			return
		case code != 0:
			if err != unix.Errno(-code) || got != nil {
				ht.Fatalf("an end carrying %d after %d replies read as %d replies and %v", code, len(want), len(got), err)
			}
			return
		}
		if interrupted {
			if err != ErrDumpInterrupted || got != nil {
				ht.Fatalf("a request interrupted after %d replies read as %d replies and %v", len(want), len(got), err)
			}
			return
		}
		if err != nil {
			ht.Fatalf("an end carrying zero or a single reply after %d replies read as %v", len(want), err)
		}
		if !slices.EqualFunc(got, want, sameMessage) {
			ht.Fatalf("the replies read as %v, want %v", got, want)
		}
	})
}
