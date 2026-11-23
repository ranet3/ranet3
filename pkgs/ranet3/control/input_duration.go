// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"strings"
	"time"
)

// ParseInputDuration reads Go duration syntax with d for 24 elapsed hours in flags and queries.
func ParseInputDuration(text string) (time.Duration, error) {
	days := strings.Count(text, "d")
	if days == 0 {
		return time.ParseDuration(text)
	}
	// decimal multiplication adds at most two digits and leaves the range check to time.ParseDuration
	hours := make([]byte, len(text)+2*days)
	start := len(hours)
	for i := len(text); i > 0; {
		i--
		c := text[i]
		if c != 'd' {
			start--
			hours[start] = c
			continue
		}
		start--
		hours[start] = 'h'
		carry := 0
		for i > 0 {
			c := text[i-1]
			if c >= '0' && c <= '9' {
				carry += 24 * int(c-'0')
				c = '0' + byte(carry%10)
				carry /= 10
			} else if c != '.' {
				break
			}
			start--
			hours[start] = c
			i--
		}
		for carry > 0 {
			start--
			hours[start] = '0' + byte(carry%10)
			carry /= 10
		}
	}
	return time.ParseDuration(string(hours[start:]))
}
