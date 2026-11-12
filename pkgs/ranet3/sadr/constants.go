// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package sadr

// indexThreshold is the mean number of sources one length carries before a map per length beats the ordered scan, since a map probe costs about two Prefix.Contains and the edit path pays for the build
const indexThreshold = 4
