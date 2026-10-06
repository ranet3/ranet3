// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

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
func answers() hegel.Generator[nlMessage] {
	return hegel.Composite(func(tc hegel.TestCase) nlMessage {
		flags := unix.NLM_F_MULTI | hegel.Draw(tc, hegel.Integers[uint16](0, math.MaxUint16))
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			flags &^= unix.NLM_F_MULTI
		}
		return nlMessage{
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
func strays() hegel.Generator[nlMessage] {
	return hegel.Composite(func(tc hegel.TestCase) nlMessage {
		message := nlMessage{
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

// appendMessage lays one message into a datagram the way the kernel does, padded to the netlink alignment
func appendMessage(datagram []byte, message nlMessage) []byte {
	length := unix.SizeofNlMsghdr + len(message.Data)
	start := len(datagram)
	datagram = append(datagram, make([]byte, nlmsgAlign(length))...)
	binary.NativeEndian.PutUint32(datagram[start:], uint32(length))
	binary.NativeEndian.PutUint16(datagram[start+4:], message.Kind)
	binary.NativeEndian.PutUint16(datagram[start+6:], message.Flags)
	binary.NativeEndian.PutUint32(datagram[start+8:], message.Seq)
	binary.NativeEndian.PutUint32(datagram[start+12:], message.Pid)
	copy(datagram[start+unix.SizeofNlMsghdr:], message.Data)
	return datagram
}

func sameMessage(a, b nlMessage) bool {
	return a.Kind == b.Kind && a.Flags == b.Flags && a.Seq == b.Seq && a.Pid == b.Pid && bytes.Equal(a.Data, b.Data)
}

// an end carrying an errno ends the request with that errno and none of the replies
// a dump the kernel cut short ends that way
// its replies are a table missing what the kernel did not send
// an end carrying zero ends the request with every reply in the order sent
// a reply without NLM_F_MULTI ends it the same way, as the one answer to a keyed request
// everything else is passed over
// the end is NLMSG_DONE or the ack, which carry the errno in the same place
// what follows the errno is the request's header in an ack and the attributes of an extended one
// an end too short to carry an errno is a failure of its own
// the messages are cut into datagrams anywhere
func TestEndCarryingAnErrnoYieldsItAndNoReplies(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var sent, want []nlMessage
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
		code, truncated := int32(0), false
		if !keyed {
			end := nlMessage{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Seq: answeredSeq, Pid: answeredPid}
			if hegel.Draw(ht, hegel.Booleans()) {
				end.Kind, end.Flags = unix.NLMSG_ERROR, 0
			}
			if truncated = hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)); truncated {
				end.Data = hegel.Draw(ht, hegel.Binary(0, 3))
			} else {
				// ENOENT is drawn by name
				// only the table's own dump reads it as an empty table, above this decoder
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
		read := 0
		receive := func() ([]nlMessage, error) {
			if read == len(datagrams) {
				return nil, errors.New("read past the message that ended the request")
			}
			read++
			return parseMessages(datagrams[read-1])
		}

		got, err := collect(answeredSeq, answeredPid, receive)
		switch {
		case keyed:
		case truncated:
			if err == nil || err.Error() != "kernel: truncated netlink errno" || got != nil {
				ht.Fatalf("an end too short for an errno after %d replies read as %d replies and %v", len(want), len(got), err)
			}
			return
		case code != 0:
			if err != unix.Errno(-code) || got != nil {
				ht.Fatalf("an end carrying %d after %d replies read as %d replies and %v", code, len(want), len(got), err)
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
