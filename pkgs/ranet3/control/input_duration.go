// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"strings"
	"time"
)

// ParseInputDuration reads Go duration syntax with d for 24 elapsed hours in flags and queries.
func ParseInputDuration(text string) (time.Duration, error) {
	days := strings.Count(text, "d")
	if days == 0 {
		return parseInputDuration(text)
	}
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
	return parseInputDuration(string(hours[start:]))
}

func parseInputDuration(text string) (time.Duration, error) {
	// a term of 1<<63 ns needs at least seven whole digits even in hours
	const minBoundaryTermLen = len("1000000h")
	d, err := time.ParseDuration(text)
	if err != nil || len(text) < minBoundaryTermLen {
		return d, err
	}
	unsigned := text
	if unsigned[0] == '-' || unsigned[0] == '+' {
		unsigned = unsigned[1:]
	}
	end := 0
	for start := 0; start < len(unsigned); start = end {
		for end < len(unsigned) && durationNumberByte(unsigned[end]) {
			end++
		}
		for end < len(unsigned) && !durationNumberByte(unsigned[end]) {
			end++
		}
		if start == 0 || end-start < minBoundaryTermLen {
			continue
		}
		// Go reads each term to whole nanoseconds before adding, and their sum must fit int64
		if _, err := time.ParseDuration(unsigned[start:end]); err != nil {
			if _, err := time.ParseDuration(unsigned[:start]); err != nil {
				return 0, fmt.Errorf("time: invalid duration %q", text)
			}
		}
	}
	return d, nil
}

func durationNumberByte(c byte) bool {
	return c == '.' || c >= '0' && c <= '9'
}
