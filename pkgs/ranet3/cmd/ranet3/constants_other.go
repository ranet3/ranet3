// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package main

// defaultStateDir is where the daemon keeps what outlives it when --state-dir names none, the conventional place on darwin and the BSDs for a service's state
const defaultStateDir = "/var/db/ranet3"
