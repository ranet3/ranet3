// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"strings"
)

// EgressName is the egress device's name beside a mesh tun written as tun in
// link.tun: tun followed by egressSuffix, and linux's default for an empty tun
// on every platform, so a file loads the same on a host that only checks it.
// A name the kernel cannot carry and a template it numbers are refused, since
// the iif rule has to name the device before the daemon starts.
func EgressName(tun string) (string, error) {
	if tun == "" {
		tun = linuxTUNName
	}
	if strings.Contains(tun, "%") {
		return "", fmt.Errorf("link.tun %q is a template the kernel numbers, so the egress device's name is not known before the daemon starts: name the tun outright", tun)
	}
	name := tun + egressSuffix
	if len(name) >= ifNameSize {
		return "", fmt.Errorf("link.tun %q is %d bytes, and the egress device is named link.tun plus %s, which the kernel caps at %d bytes: name the tun in %d bytes or fewer",
			tun, len(tun), egressSuffix, ifNameSize-1, ifNameSize-1-len(egressSuffix))
	}
	return name, nil
}
