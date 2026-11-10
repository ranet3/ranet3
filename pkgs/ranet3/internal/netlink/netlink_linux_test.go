// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netlink

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// sizeofFibRuleHdr is struct fib_rule_hdr of linux/fib_rules.h, which x/sys does not carry
const sizeofFibRuleHdr = 12

// unansweredTimeout is the receive timeout of a socket nothing answers
const unansweredTimeout = 20 * time.Millisecond

// a dump whose reply or end carries NLM_F_DUMP_INTR comes back as ErrDumpInterrupted with none of its replies, and one that carries it
// nowhere comes back whole
func TestCollectRefusesAnInterruptedDump(t *testing.T) {
	reply := func(flags uint16) Message {
		return Message{Kind: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI | flags, Seq: 1, Pid: 1, Data: []byte{1, 2, 3, 4}}
	}
	done := func(flags uint16) Message {
		return Message{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI | flags, Seq: 1, Pid: 1, Data: make([]byte, 4)}
	}
	for name, arm := range map[string]struct {
		messages    []Message
		interrupted bool
	}{
		"the flag on a reply":       {[]Message{reply(0), reply(unix.NLM_F_DUMP_INTR), done(0)}, true},
		"the flag on the end alone": {[]Message{reply(0), reply(0), done(unix.NLM_F_DUMP_INTR)}, true},
		"the flag nowhere":          {[]Message{reply(0), reply(0), done(0)}, false},
	} {
		got, err := collect(1, 1, func() ([]Message, error) { return arm.messages, nil })
		switch {
		case arm.interrupted && (err != ErrDumpInterrupted || got != nil):
			t.Errorf("%s: the dump read as %d replies and %v, want none and %v", name, len(got), err, ErrDumpInterrupted)
		case !arm.interrupted && (err != nil || len(got) != 2):
			t.Errorf("%s: the dump read as %d replies and %v, want both", name, len(got), err)
		}
	}
}

// recording is a socket of port 1 whose sends are kept and each of whose asks answer gives one datagram, or a read's failure, from
// the ask's number, counted from 1, and every sequence number sent so far
type recording struct {
	next     uint32
	sent     []Message
	sendFail int
	answer   func(ask int, seqs []uint32) ([]Message, error)
	read     func() ([]Message, error)
}

func (r *recording) Next() uint32 { r.next++; return r.next }
func (r *recording) Pid() uint32  { return 1 }

func (r *recording) Send(datagram []byte) error {
	messages, err := ParseMessages(datagram)
	if err != nil {
		return err
	}
	r.sent = append(r.sent, messages...)
	if len(r.sent) == r.sendFail {
		return unix.ENOBUFS
	}
	var seqs []uint32
	for _, message := range r.sent {
		seqs = append(seqs, message.Seq)
	}
	messages, err = r.answer(len(r.sent), seqs)
	r.read = func() ([]Message, error) {
		r.read = nil
		return messages, err
	}
	return nil
}

func (r *recording) Receive() ([]Message, error) {
	if r.read == nil {
		return nil, errors.New("a read with no datagram left to answer it")
	}
	return r.read()
}

// a dump the kernel flags interrupted is asked again under a sequence number of its own, after the interrupted one was read to its
// end, and comes back as the whole ask's replies alone, a late message of the first ask among them passed over
// one flagged on every ask but the last comes back as the last ask's replies, and one flagged dumpAttempts times in a row is
// refused after that many asks
// a keyed request whose reply carries the flag, a send that fails and a read that fails end the request at once with that failure
func TestInterruptedDumpIsAskedAgain(t *testing.T) {
	reply := func(seq uint32, flags uint16, value byte) Message {
		return Message{Kind: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI | flags, Seq: seq, Pid: 1, Data: []byte{value, 0, 0, 0}}
	}
	done := func(seq uint32) Message {
		return Message{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Seq: seq, Pid: 1, Data: make([]byte, 4)}
	}
	interrupted := func(_ int, seqs []uint32) ([]Message, error) {
		seq := seqs[len(seqs)-1]
		return []Message{reply(seq, unix.NLM_F_DUMP_INTR, 1), done(seq)}, nil
	}
	for name, arm := range map[string]struct {
		flags    uint16
		sendFail int
		answer   func(ask int, seqs []uint32) ([]Message, error)
		asks     int
		values   []byte
		want     error
	}{
		"a dump flagged interrupted, then a whole one": {flags: unix.NLM_F_DUMP, asks: 2, values: []byte{2}, answer: func(ask int, seqs []uint32) ([]Message, error) {
			if ask == 1 {
				return interrupted(ask, seqs)
			}
			return []Message{reply(seqs[1], 0, 2), reply(seqs[0], 0, 9), done(seqs[1])}, nil
		}},
		"a dump flagged interrupted on every ask but the last": {flags: unix.NLM_F_DUMP, asks: dumpAttempts, values: []byte{2}, answer: func(ask int, seqs []uint32) ([]Message, error) {
			if ask < dumpAttempts {
				return interrupted(ask, seqs)
			}
			seq := seqs[len(seqs)-1]
			return []Message{reply(seq, 0, 2), done(seq)}, nil
		}},
		"dumpAttempts dumps flagged interrupted in a row": {flags: unix.NLM_F_DUMP, asks: dumpAttempts, answer: interrupted, want: ErrDumpInterrupted},
		"a keyed request whose reply carries the flag": {flags: unix.NLM_F_ACK, asks: 1, want: ErrDumpInterrupted, answer: func(_ int, seqs []uint32) ([]Message, error) {
			return []Message{{Kind: unix.RTM_NEWADDR, Flags: unix.NLM_F_DUMP_INTR, Seq: seqs[0], Pid: 1, Data: []byte{1, 0, 0, 0}}}, nil
		}},
		"a send that fails on the second ask": {flags: unix.NLM_F_DUMP, sendFail: 2, asks: 2, answer: interrupted, want: unix.ENOBUFS},
		"a read that fails on the first ask": {flags: unix.NLM_F_DUMP, asks: 1, want: unix.ENOBUFS, answer: func(int, []uint32) ([]Message, error) {
			return nil, unix.ENOBUFS
		}},
	} {
		s := &recording{sendFail: arm.sendFail, answer: arm.answer}
		got, err := execute(s, unix.RTM_GETADDR, arm.flags, []byte{unix.AF_INET, 0, 0, 0})
		if len(s.sent) != arm.asks {
			t.Errorf("%s: sent %d asks, want %d", name, len(s.sent), arm.asks)
		}
		for i, ask := range s.sent {
			if ask.Kind != unix.RTM_GETADDR || ask.Flags != arm.flags|unix.NLM_F_REQUEST || ask.Pid != 1 {
				t.Errorf("%s: ask %d went as %+v", name, i+1, ask)
			}
			for j, earlier := range s.sent[:i] {
				if ask.Seq == earlier.Seq {
					t.Errorf("%s: ask %d went under ask %d's sequence number %d", name, i+1, j+1, ask.Seq)
				}
			}
		}
		var values []byte
		for _, message := range got {
			values = append(values, message.Data[0])
		}
		switch {
		case arm.want != nil && (!errors.Is(err, arm.want) || got != nil):
			t.Errorf("%s: read as %d replies and %v, want none and %v", name, len(got), err, arm.want)
		case arm.want == nil && (err != nil || string(values) != string(arm.values)):
			t.Errorf("%s: read as the replies %v and %v, want %v", name, values, err, arm.values)
		}
	}
}

// a dump the kernel ends early still ends at NLMSG_DONE, with the errno it ended on as that message's payload
// a rule dump for a family with no rules engine ends that way on its first call, with no privileges and nothing written
func TestExecuteReportsTheErrnoADumpEndedOn(t *testing.T) {
	conn, err := Dial(unix.NETLINK_ROUTE, Options{Strict: true})
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rules := make([]byte, sizeofFibRuleHdr)
	rules[0] = unix.AF_BRIDGE
	if replies, err := conn.Execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, rules); !errors.Is(err, unix.EAFNOSUPPORT) || replies != nil {
		t.Errorf("a rule dump the kernel ended on EAFNOSUPPORT read as %d replies and %v", len(replies), err)
	}
	// the socket is still in step, so the next request is answered as its own
	routes := make([]byte, unix.SizeofRtMsg)
	routes[0] = unix.AF_INET
	if _, err := conn.Execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, routes); err != nil {
		t.Errorf("a dump after the one the kernel ended early failed: %v", err)
	}
}

// a datagram another socket sends to the port, though it answers the request in waiting with a message of its sequence, is refused
// as one the kernel did not send, never read as the reply
// any user may send to another socket of NETLINK_USERSOCK, so the test needs no privileges
func TestReceiveRefusesADatagramNotFromTheKernel(t *testing.T) {
	conn, err := Dial(unix.NETLINK_USERSOCK, Options{})
	if err != nil {
		t.Fatalf("dial a user netlink socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	forger, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_USERSOCK)
	if err != nil {
		t.Fatalf("open the forging socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(forger) })
	if err := unix.Bind(forger, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatalf("bind the forging socket: %v", err)
	}
	forged := AppendMessage(nil, unix.NLMSG_ERROR, 0, conn.seq+1, conn.Pid(), make([]byte, 4))
	if err := unix.Sendto(forger, forged, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: conn.Pid()}); err != nil {
		t.Fatalf("send the forged acknowledgment: %v", err)
	}
	if messages, err := conn.Receive(); !errors.Is(err, errNotFromKernel) || messages != nil {
		t.Errorf("a datagram from port %d read as %d messages and %v, want none and %v", conn.Pid(), len(messages), err, errNotFromKernel)
	}
}

// A datagram whose message claims to run past its end is an error rather than
// a short read, so a truncated dump can never look like a complete one and a
// diff built on it can never withdraw a rule that is still there.
func TestMalformedMessageLengthIsRefused(t *testing.T) {
	buf := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(buf, uint32(len(buf)+64))
	if _, err := ParseMessages(buf); err == nil {
		t.Fatal("a message running past its datagram was accepted")
	}
}

// a socket with a receive timeout that nothing answers ends its wait as a kernel that did not answer, not as the EAGAIN of a socket
// that never blocks
func TestReceiveEndsAnUnansweredWaitAtTheTimeout(t *testing.T) {
	conn, err := Dial(unix.NETLINK_USERSOCK, Options{Timeout: unansweredTimeout})
	if err != nil {
		t.Fatalf("dial a user netlink socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if messages, err := conn.Receive(); !errors.Is(err, errNoAnswer) || messages != nil {
		t.Errorf("a wait nothing answered read as %d messages and %v, want none and %v", len(messages), err, errNoAnswer)
	}
}
