// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import "ranet3.com/pkgs/ranet3/internal/packet"

// ecnDSCP is the DSCP the ECN tests send under, whose bits a receiver that keeps the whole octet would read as part of the field
const ecnDSCP = 0xb8

// codepoints are the four values of the ECN field
var codepoints = []packet.ECN{packet.NotECT, packet.ECT1, packet.ECT0, packet.CE}
