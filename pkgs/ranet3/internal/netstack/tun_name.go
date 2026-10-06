// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"math"
	"strconv"
	"strings"
)

// isUTUNName reports whether darwin's utun control creates name
// the control is sent the unit plus one in 32 bits, zero asking for the next free unit
func isUTUNName(name string) bool {
	unit, ok := strings.CutPrefix(name, utunName)
	if !ok {
		return false
	}
	if unit == "" {
		return true
	}
	n, err := strconv.ParseUint(unit, 10, 32)
	return err == nil && n < math.MaxUint32
}
