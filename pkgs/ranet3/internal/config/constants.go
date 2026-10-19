// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

// egressRulePriority is the priority a refusal suggests for the egress
// device's rule where the rules into the mesh table leave room for it: between
// the "to" rules at 100 and the "from" rules at 150 that networkd writes beside
// the mesh table on a server, which the file cannot see
const egressRulePriority = 120
