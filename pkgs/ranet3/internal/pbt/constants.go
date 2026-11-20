// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package pbt

const (
	// propertyCases is how many cases each property runs
	propertyCases = 200
	// boundaryChance is how often a generator draws a boundary outright, so
	// every run meets it rather than only a run whose sample lands there
	boundaryChance = 1.0 / 4
)
