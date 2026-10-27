// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package bubble

import "time"

// realLimit is far past the real time the slowest bubble of the module takes
// under -race on a loaded machine, and half of go test's default timeout, so
// the tests after a bubble that cannot end still run
// hegel shrinks a failing property for up to 300 s of real time, so a property
// that already fails and still shrinks at this bound fails its bubble after
// its test has ended and panics the binary
// the slowest shrink measured took 31 s
const realLimit = 5 * time.Minute
