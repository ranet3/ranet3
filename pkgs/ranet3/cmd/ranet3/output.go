// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import "io"

// outputWriter keeps the first write error and refuses each later write with it
type outputWriter struct {
	writer io.Writer
	err    error
}

func (w *outputWriter) Write(p []byte) (int, error) {
	var n int
	if w.err == nil {
		n, w.err = w.writer.Write(p)
	}
	return n, w.err
}
