// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package bubble runs a test in a testing/synctest bubble with a bound in real
// time. Test files import it and nothing else does.
package bubble

import (
	"testing"
	"testing/synctest"
	"time"
)

// Run returns a test that runs body in a synctest bubble, and that fails by
// its name where the bubble still runs after realLimit of real time.
//
// A goroutine that never blocks holds the bubble's clock still, so without the
// bound such a test runs until go test's timeout, which ends the test binary
// with every test after it unreported. The bubble is left running once the
// test failed, and a body that fails its test after that panics the binary.
func Run(body func(*testing.T)) func(*testing.T) {
	return within(realLimit, body)
}

func within(limit time.Duration, body func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			synctest.Test(t, body)
		}()
		select {
		case <-done:
		case <-time.After(limit):
			t.Fatalf("%s still ran in its bubble after %v of real time", t.Name(), limit)
		}
	}
}
