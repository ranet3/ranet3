// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package raw

// sources is how many addresses Sockets holds a socket bound to at once, the
// one past them closing another's, so addresses the host gives up do not
// keep sockets open
const sources = 16
