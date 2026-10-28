// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

// mode lets the daemon's own user alone read and write a record, a lock and
// a state file, since a record names what this daemon holds in the kernel and
// the daemon alone takes a lock
const mode = 0o600

// tempSuffix names the file a write fills before it is renamed into place.
// One name per file, so a write after a crash overwrites what the crash left.
const tempSuffix = ".tmp"
