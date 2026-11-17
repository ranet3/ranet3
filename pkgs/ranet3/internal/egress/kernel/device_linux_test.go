// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"io"
	"log/slog"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// The presence read judges each kind of answer as present gives, the answers
// its second guard alone takes marked so. A shutdown reading an answer the
// reader returns as unread, in the form the reader returns it, leaves the
// stopped rules and withdraws nothing.
func TestDevicePresenceCountsUnreadWhatDoesNotSingleOutTheDevice(t *testing.T) {
	const index = 7
	link := func(index uint32, flags uint16) netlink.Message {
		data := make([]byte, unix.SizeofIfInfomsg)
		binary.NativeEndian.PutUint32(data[4:], index)
		return netlink.Message{Kind: unix.RTM_NEWLINK, Flags: flags, Data: data}
	}
	for name, c := range map[string]struct {
		replies         []netlink.Message
		err             error
		present, unread bool
	}{
		"the device":                  {replies: []netlink.Message{link(index, 0)}, present: true},
		"no device of the index":      {err: unix.ENODEV},
		"a listing found interrupted": {err: netlink.ErrDumpInterrupted, unread: true},
		"another refusal":             {err: unix.EBUSY, unread: true},
		"a reply short of a device":   {replies: []netlink.Message{{Kind: unix.RTM_NEWLINK, Data: make([]byte, 8)}}, unread: true},
		// the second guard's
		"another device":                           {replies: []netlink.Message{link(9, 0)}, unread: true},
		"a listing holding the index":              {replies: []netlink.Message{link(3, unix.NLM_F_MULTI), link(index, unix.NLM_F_MULTI)}, unread: true},
		"a listing of the device alone":            {replies: []netlink.Message{link(index, unix.NLM_F_MULTI)}, unread: true},
		"the device in a reply marked interrupted": {replies: []netlink.Message{link(index, unix.NLM_F_DUMP_INTR)}, unread: true},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := present(index, c.replies, c.err); got != c.present || (err != nil) != c.unread {
				t.Errorf("the read of %+v (%v) answered %v, %v, want present %v and unread %v", c.replies, c.err, got, err, c.present, c.unread)
			}
		})
	}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, answer := range []error{netlink.ErrDumpInterrupted, unix.EBUSY} {
		be := &fakeBackend{}
		rt := Runtime{Present: func() (bool, error) { return present(index, nil, answer) }}
		tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, rt, be)
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
		if err := endedAtOnce(tr); err != nil || be.withdrawn != 0 || !slices.Equal(be.specs(), specsOf(tr.stopped())) {
			t.Errorf("the shutdown reading %v returned %v, withdrew %d times and left %q, want the stopped rules and no withdrawal", answer, err, be.withdrawn, be.specs())
		}
	}
}
