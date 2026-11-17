// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// DevicePresence reads device's index now and returns a reader of whether a
// device of the calling thread's network namespace holds that index, each
// read asking the kernel for that one device over netlink, as present judges
// its answer. The index stays with the device through a rename. Another
// device can take it once the device is gone, one made asking for it or one
// moved in from another namespace that held it (net/core/dev.c:10869-10873,
// :12772 at 940de590b), and reads as the device, which leaves the stopped
// rules. The reader fails where the index could not be read.
func DevicePresence(device string) func() (bool, error) {
	index, err := single(askLink(0, device))
	if err != nil {
		err = fmt.Errorf("read the index of %s: %w", device, err)
		return func() (bool, error) { return false, err }
	}
	return func() (bool, error) {
		replies, err := askLink(index, "")
		return present(index, replies, err)
	}
}

// present judges the kernel's answer to a request for the device of index.
// The kernel answers with that one device, read as there, or refuses the
// request: with ENODEV where no device of the namespace holds the index or the
// one that does is being unregistered (net/core/rtnetlink.c:4312, :4323, :4332
// at 940de590b), read as gone, and any other refusal is an error, which counts
// as unread. The rest of what present refuses as unread is a second guard over
// the layers below, never an answer the kernel gives such a request: a reply
// other than one whole RTM_NEWLINK of no listing, one marked interrupted,
// which netlink.Conn.Execute already answers with netlink.ErrDumpInterrupted
// and no reply, and a device of another index. The read decides a
// withdrawal, and the stopped rules stand in place of a withdrawal over a
// device still there, so what the layers below should never pass reads
// neither there nor gone.
func present(index uint32, replies []netlink.Message, err error) (bool, error) {
	if errors.Is(err, unix.ENODEV) {
		return false, nil
	}
	held, err := single(replies, err)
	switch {
	case err != nil:
		return false, err
	case held != index:
		return false, fmt.Errorf("the kernel answered for the device of index %d with that of index %d", index, held)
	}
	return true, nil
}

// single is the index of the one device replies answer with, and err or an
// error where they are not one whole RTM_NEWLINK of no listing
func single(replies []netlink.Message, err error) (uint32, error) {
	if err != nil {
		return 0, err
	}
	if len(replies) != 1 || replies[0].Kind != unix.RTM_NEWLINK || replies[0].Flags&(unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR) != 0 ||
		len(replies[0].Data) < unix.SizeofIfInfomsg {
		return 0, fmt.Errorf("the kernel answered with %d messages and no device alone", len(replies))
	}
	return binary.NativeEndian.Uint32(replies[0].Data[4:]), nil
}

// askLink asks the kernel of the calling thread's network namespace for the
// device of index, or of name where index is 0, with a keyed RTM_GETLINK
// rather than a listing, and answers its replies
func askLink(index uint32, name string) ([]netlink.Message, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, netlink.Options{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	if index == 0 {
		body = netlink.PutAttrString(body, unix.IFLA_IFNAME, name)
	}
	return conn.Execute(unix.RTM_GETLINK, 0, body)
}
