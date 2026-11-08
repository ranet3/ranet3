// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

// Hold keeps the storage of delivered frames from being read into again until every holder has released it
// a goroutine that reads a frame after the call that handed it over returns retains the hold before the handoff and releases it after its last read
// a nil Hold is one on frames the collector owns, which nothing retains or releases
type Hold interface {
	Retain()
	Release()
}
