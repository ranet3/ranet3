// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

// RouteGetBatch has no batch to read here. It reads for the kernel exit alone,
// which this build does not carry, so no configuration reaches it
func RouteGetBatch(reads []RouteRead) ([]BatchAnswer, error) { return nil, ErrUnsupported }
