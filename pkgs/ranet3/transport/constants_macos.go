// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package transport

// link.underlay.bind decides how the reconciler on macOS installs an exit's default. Underlay.refuse reads this.
const takesBind = true
