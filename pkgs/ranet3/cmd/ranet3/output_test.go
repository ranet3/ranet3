// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"testing"
)

type outputWriteFunc func([]byte) (int, error)

func (f outputWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestOutputWriterKeepsFirstError(t *testing.T) {
	first, later := errors.New("first write failure"), errors.New("later write failure")
	calls := 0
	w := &outputWriter{writer: outputWriteFunc(func(p []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			return len(p), nil
		case 2:
			return 1, first
		default:
			return 0, later
		}
	})}
	p := []byte("ab")
	if n, err := w.Write(p); n != len(p) || err != nil || w.err != nil {
		t.Fatalf("successful write = %d, %v, stored %v", n, err, w.err)
	}
	if n, err := w.Write(p); n != 1 || err != first || w.err != first {
		t.Fatalf("partial write = %d, %v, stored %v", n, err, w.err)
	}
	for range 2 {
		if n, err := w.Write(p); n != 0 || err != first || w.err != first {
			t.Errorf("later write = %d, %v, stored %v", n, err, w.err)
		}
	}
	if calls != 2 {
		t.Errorf("underlying writer called %d times, want 2", calls)
	}
}
