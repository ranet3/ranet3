// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

// ReadFallback has no table to read here, where fallback = "none" is refused at start
func ReadFallback() (FallbackDebug, error) { return FallbackDebug{}, ErrUnsupported }

// ResolvedLinkServers has no systemd-resolved to ask here
func ResolvedLinkServers() ([]LinkResolver, error) { return nil, nil }
