// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build !linux && !darwin

package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

func openPacketBind(uint16, underlay.Prepare, Selection, func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	return nil, nil, 0, fmt.Errorf("no underlay transport on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
