// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"fmt"
	"os"
	"syscall"
)

// journalStream reports whether value is f's device and inode in the form systemd.exec(5) gives JOURNAL_STREAM
func journalStream(value string, f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && value == fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino))
}
