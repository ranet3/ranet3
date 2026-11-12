// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package esp

// ProactiveRekeySequence is the sequence number from which a non-ESN SA asks to be replaced, 2^28 numbers before the last the space holds, which the scheduled rekey precedes unless a link reaches it inside one rekey interval, and the margin is a time budget rather than a packet count, two round trips that may wait behind an exchange already outstanding, sized for a rekey that failed and is retried
const ProactiveRekeySequence = uint64(0xffffffff - 1<<28)

// MaxReplayWindow is the widest anti-replay window built, since a window above half the sequence space overflows the 32-bit index arithmetic, and WithReplayWindow takes any uint32
const MaxReplayWindow uint32 = 1 << 20

// DefaultReplayWindow is wider than the 32-packet minimum, as RFC 4303 section 3.4.3 has a receiver in a high-speed environment widen it, since multicore IPsec senders reorder bursts by more than that before they reach userspace
const DefaultReplayWindow uint32 = 4096
