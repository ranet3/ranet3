// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package kernel

// ReadFallback has no switch to read here, where fallback = "none" is refused at start
func ReadFallback() (FallbackDebug, error) { return FallbackDebug{}, ErrUnsupported }

// DeleteFallback has no switch to delete here
func DeleteFallback() {}

// ResolvedLinkServers has no systemd-resolved to ask here
func ResolvedLinkServers() ([]LinkResolver, error) { return nil, nil }
