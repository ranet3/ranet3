// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package netstack

import "errors"

// tunMTUSettable is false, the device taking its MTU here only from wireguard-go when the mesh opens it
const tunMTUSettable = false

// setTUNMTU is never reached here, since CheckMTU refuses every change first
func setTUNMTU(string, int) error { return errors.ErrUnsupported }
