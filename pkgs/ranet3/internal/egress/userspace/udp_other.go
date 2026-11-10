// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package userspace

import (
	"errors"
	"net"
)

// setDontFragment refuses, since no build for this platform carries the exit
func setDontFragment(int, bool, bool) error { return errors.ErrUnsupported }

// socketPathMTU reads nothing, since no build for this platform carries the
// exit
func socketPathMTU(*net.UDPConn, bool) (int, error) { return 0, errors.ErrUnsupported }

// shareDialPort and shareMappingPort refuse, since no build for this platform
// carries the exit
func shareDialPort(int) error    { return errors.ErrUnsupported }
func shareMappingPort(int) error { return errors.ErrUnsupported }
