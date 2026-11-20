// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Done stays open while the monitor reads on past an overflow and closes once a
// read error stops it, as it does at Close
func TestMonitorDoneClosesOnceItStopsReading(t *testing.T) {
	f := feedMonitor(t)
	if _, missed := f.answer(t, monitorRead{err: unix.ENOBUFS}); !missed {
		t.Fatal("an overflow woke no loss")
	}
	select {
	case <-f.Done():
		t.Fatal("Done closed while the monitor reads on past an overflow")
	default:
	}
	f.answers <- monitorRead{err: unix.EIO}
	select {
	case <-f.Done():
	case <-time.After(monitorWait):
		t.Fatal("Done stayed open after a read error stopped the monitor")
	}
	if !woke(f.Missed()) {
		t.Error("the read error that stopped the monitor woke no loss")
	}
}
