// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package client

// carriesEgress is whether this build carries other nodes' traffic out of the mesh through cap.egress, which it refuses: no build for Android, iOS or the BSDs carries an exit
const carriesEgress = false
