// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import "time"

// spacedLog counts what one log line stands for and says the line at most once per interval
type spacedLog struct {
	said  time.Time
	count int
}

// due counts one more at now and reports whether to say the line, with the count since the last line said
func (l *spacedLog) due(now time.Time, interval time.Duration) (int, bool) {
	l.count++
	if !l.said.IsZero() && now.Sub(l.said) < interval {
		return 0, false
	}
	count := l.count
	l.said, l.count = now, 0
	return count, true
}
