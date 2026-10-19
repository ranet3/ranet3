// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// utunListenerSettle is how long a route listener would have to hear the link changes the kernel sends it
const utunListenerSettle = 500 * time.Millisecond

// nothing reads the utun's events, and a monitored utun hands a failure of its route socket to the reads
// so the mesh's utun runs no route listener and queues no link event
// the mesh's MTU moves more times than the event channel's 10 slots hold
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNRunsNoRouteListener(t *testing.T) {
	requireUTUN(t)
	const moves = 12
	m, err := NewNamed(DefaultMTU, "", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			m.Close()
		}
	})
	if got := utunRouteListeners(); got != 0 {
		t.Fatalf("%d route listener goroutines run for the mesh's utun", got)
	}
	for i := range moves {
		if err := m.SetMTU(DefaultMTU-1-i, nil); err != nil {
			t.Fatalf("set the mtu of %s to %d: %v", m.Name, DefaultMTU-1-i, err)
		}
	}
	time.Sleep(utunListenerSettle)
	events := m.dev.Events()
	if queued := len(events); queued != 0 {
		t.Errorf("the utun queued %d link events with nothing reading them", queued)
	}
	m.Close()
	closed = true
	select {
	case _, open := <-events:
		if open {
			t.Error("the utun sent an event after Close")
		}
	default:
		t.Error("Close left the utun's event channel open")
	}
}

// utunRouteListeners counts the goroutines running a utun's route listener
func utunRouteListeners() int {
	buf := make([]byte, 1<<22)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), ".routineRouteListener(")
}
