// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

// DumpRules has no policy rules to read here: darwin and the BSDs route by
// destination alone, and android keeps its rules from an application
func DumpRules() ([]DumpedRule, error) { return nil, ErrUnsupported }
