// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// A dump that fails with ENOMEM, as FetchRIB's does when the table grows past
// its sizing sysctl, or with ENOBUFS, as an interface list's does when it grows
// past the room its own sysctl sized, is fetched again up to dumpAttempts times
// in all, the two counted under that one bound, and any other failure ends it
// at once
func TestDumpFetchesAgainOnlyWhileTheTableOutgrowsItsBuffer(t *testing.T) {
	grown := os.NewSyscallError("sysctl", unix.ENOMEM)
	overrun := os.NewSyscallError("sysctl", unix.ENOBUFS)
	refused := os.NewSyscallError("sysctl", unix.EPERM)
	mixed := slices.Repeat([]error{grown, overrun}, dumpAttempts+1)
	// the last try's error is a value of its own, so a read that returns any earlier one fails the row
	mixed[dumpAttempts-1] = os.NewSyscallError("sysctl", unix.ENOBUFS)
	rib := []byte{1, 2, 3}
	for _, c := range []struct {
		what    string
		answers []error
		calls   int
		err     error
	}{
		{what: "a fetch that succeeds", answers: []error{nil}, calls: 1},
		{what: "a fetch that outgrows its buffer once", answers: []error{grown, nil}, calls: 2},
		{what: "a fetch that outgrows its buffer every time", answers: slices.Repeat([]error{grown}, dumpAttempts+1), calls: dumpAttempts, err: grown},
		{what: "a fetch that overruns the kernel's room once", answers: []error{overrun, nil}, calls: 2},
		{what: "a fetch that overruns the kernel's room every time", answers: slices.Repeat([]error{overrun}, dumpAttempts+1), calls: dumpAttempts, err: overrun},
		{what: "a fetch that outgrows and overruns by turns", answers: mixed, calls: dumpAttempts, err: mixed[dumpAttempts-1]},
		{what: "a fetch refused", answers: []error{refused, nil}, calls: 1, err: refused},
	} {
		calls := 0
		got, err := refetched(func() ([]byte, error) {
			answer := c.answers[calls]
			calls++
			if answer != nil {
				return nil, answer
			}
			return rib, nil
		})
		if calls != c.calls || !errors.Is(err, c.err) || c.err == nil && !slices.Equal(got, rib) {
			t.Errorf("%s: fetched %d times with %v and %v, want %d times with %v", c.what, calls, got, err, c.calls, c.err)
		}
	}
}

// Each read of the interface list fetches again where its first fetch overruns
// the kernel's room, and one that overruns on every fetch returns the errno
// wrapped as a single failed fetch would be
func TestInterfaceReadsFetchAgainWhileTheListOverrunsItsBuffer(t *testing.T) {
	lookupOverrun := &net.OpError{Op: "route", Net: "ip+net", Err: unix.ENOBUFS}
	dumpOverrun := os.NewSyscallError("sysctl", unix.ENOBUFS)
	loopback := net.Interface{Index: 1, Name: Loopback}
	listed := func() ([]net.Interface, error) { return []net.Interface{loopback}, nil }
	empty := func(int, route.RIBType, int) ([]byte, error) { return nil, nil }
	for _, c := range []struct {
		what    string
		err     error
		read    func(answer func() error) (string, error)
		want    string
		message string
	}{
		{
			what: "the addresses of one interface",
			err:  dumpOverrun,
			read: func(answer func() error) (string, error) {
				addresses, err := readAddresses(func(_ int, typ route.RIBType, index int) ([]byte, error) {
					if typ != route.RIBTypeInterface || index != 7 {
						return nil, fmt.Errorf("fetched %v of %d, want the interface list of 7", typ, index)
					}
					return nil, answer()
				}, 7)
				return fmt.Sprint(addresses), err
			},
			want:    "[]",
			message: "kernel: dump the addresses of interface 7: sysctl: no buffer space available",
		},
		{
			what: "the list of every interface",
			err:  lookupOverrun,
			read: func(answer func() error) (string, error) {
				links, err := readLinks(func() ([]net.Interface, error) {
					if err := answer(); err != nil {
						return nil, err
					}
					return listed()
				}, empty)
				return linkNames(links), err
			},
			want:    "[lo0]",
			message: "kernel: list the interfaces: route ip+net: no buffer space available",
		},
		{
			what: "the addresses of every interface",
			err:  dumpOverrun,
			read: func(answer func() error) (string, error) {
				links, err := readLinks(listed, func(_ int, typ route.RIBType, index int) ([]byte, error) {
					if typ != route.RIBTypeInterface || index != 0 {
						return nil, fmt.Errorf("fetched %v of %d, want the interface list of every interface", typ, index)
					}
					return nil, answer()
				})
				return linkNames(links), err
			},
			want:    "[lo0]",
			message: "kernel: dump the interfaces' addresses: sysctl: no buffer space available",
		},
		{
			what: "a lookup by name",
			err:  lookupOverrun,
			read: func(answer func() error) (string, error) {
				index, err := lookUpIndex(func(name string) (*net.Interface, error) {
					if name != Loopback {
						return nil, fmt.Errorf("looked up %s, want %s", name, Loopback)
					}
					if err := answer(); err != nil {
						return nil, err
					}
					return &loopback, nil
				}, Loopback)
				return fmt.Sprint(index), err
			},
			want:    "1",
			message: "kernel: look up interface lo0: route ip+net: no buffer space available",
		},
		{
			what: "a lookup by index",
			err:  lookupOverrun,
			read: func(answer func() error) (string, error) {
				return lookUpName(func(index int) (*net.Interface, error) {
					if index != loopback.Index {
						return nil, fmt.Errorf("looked up interface %d, want %d", index, loopback.Index)
					}
					if err := answer(); err != nil {
						return nil, err
					}
					return &loopback, nil
				}, loopback.Index)
			},
			want:    "lo0",
			message: "kernel: name interface 1: route ip+net: no buffer space available",
		},
	} {
		got, calls, err := readFailing(c.read, c.err, 1)
		if calls != 2 || err != nil || got != c.want {
			t.Errorf("%s overrun once: fetched %d times for %s and %v, want 2 times for %s", c.what, calls, got, err, c.want)
		}
		_, calls, err = readFailing(c.read, c.err, dumpAttempts+1)
		if calls != dumpAttempts || !errors.Is(err, unix.ENOBUFS) || err.Error() != c.message {
			t.Errorf("%s overrun every time: fetched %d times and %v, want %d times and %s", c.what, calls, err, dumpAttempts, c.message)
		}
	}
}

// readFailing runs read with an answer that fails with err its first failures
// times, and counts the answers read asked for
func readFailing(read func(answer func() error) (string, error), err error, failures int) (string, int, error) {
	calls := 0
	got, readErr := read(func() error {
		calls++
		if calls <= failures {
			return err
		}
		return nil
	})
	return got, calls, readErr
}

func linkNames(links []HostInterface) string {
	names := make([]string, 0, len(links))
	for _, link := range links {
		names = append(names, link.Name)
	}
	return fmt.Sprint(names)
}
