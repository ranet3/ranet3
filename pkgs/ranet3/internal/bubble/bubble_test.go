// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package bubble

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// spinsEnv set tells the test binary run again that it runs the bubble that never blocks
const spinsEnv = "BUBBLE_SPINS"

// spinLimit bounds that bubble, and spinTimeout is the binary's -timeout, past which a bubble with no bound panics it
const (
	spinLimit   = time.Second
	spinTimeout = 30 * time.Second
)

// a body that never blocks fails its test by name once the bound passes, where with no bound the binary runs to its timeout
func TestBubbleThatNeverBlocksFailsItsTestAtTheBound(t *testing.T) {
	if os.Getenv(spinsEnv) != "" {
		within(spinLimit, func(*testing.T) {
			// the clock read against a bound without blocking, which the bubble's clock never reaches
			for start := time.Now(); time.Since(start) < time.Hour; {
			}
		})(t)
		return
	}
	run := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout="+spinTimeout.String())
	run.Env = append(os.Environ(), spinsEnv+"=1")
	out, err := run.CombinedOutput()
	want := fmt.Sprintf("%s still ran in its bubble after %v of real time", t.Name(), spinLimit)
	if err == nil || !strings.Contains(string(out), "--- FAIL: "+t.Name()+" ") || !strings.Contains(string(out), want) {
		t.Errorf("the binary whose bubble never blocks ended with %v and said\n%s\nwant its failure by name, %q", err, out, want)
	}
}
