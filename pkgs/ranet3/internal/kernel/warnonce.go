// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

// warnOnce is the keys seen in the last window and those seen in this one, so
// a key that stays costs one warning and the record holds no key gone for a
// whole window. A window ends only where its input was read whole, since a
// window that ends with nothing marked empties the record. Two marks of one key
// in one window both answer new.
//
// The zero value is an empty record. It belongs to one goroutine.
type warnOnce[K comparable] struct {
	last, seen map[K]bool
}

// mark records key as seen in this window and reports whether the last window
// did not see it
func (w *warnOnce[K]) mark(key K) bool {
	if w.seen == nil {
		w.seen = make(map[K]bool, len(w.last))
	}
	w.seen[key] = true
	return !w.last[key]
}

// end closes this window, whose keys become the last
func (w *warnOnce[K]) end() {
	w.last, w.seen = w.seen, nil
}
