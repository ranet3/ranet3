// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

// the values the darwin socket chooses, in a file of their own because no other platform reads them

// controlMessageSize is the bytes of control messages one received datagram carries
// a packet info message and the outer TOS or traffic class of the larger family fit
// darwin drops a message that finds the buffer full without setting MSG_CTRUNC, so the size holds both whole
const controlMessageSize = 48
