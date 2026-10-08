// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import "ranet3.com/pkgs/ranet3/srv6"

// defaultPacketSize is the most one babel packet carries when the runtime names no size, its four-byte header included
// with its IPv6 and UDP headers it makes an inner packet of the IPv6 minimum MTU
// every session carries a packet that large whatever its path
// no babel packet is then larger than the session it leaves through carries
const defaultPacketSize = srv6.MinimumIPv6MTU - ipv6HeaderLen - udpHeaderLen
