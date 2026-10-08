// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package kernel

// android is excluded with the linux backend and ios with the darwin one: the
// kernel under each is the supported one, but an application there has neither
// the privilege nor a routing table of its own, so the backend would only ever
// fail at runtime. On ios the tunnel's routes come from the network extension's
// settings rather than from PF_ROUTE at all. Each platform gets its own backend
// when it gets one; until then New reports it rather than starting a reconciler
// that installs nothing and reports no error.
func newPlatform(Table, Runtime) (platform, error) { return nil, ErrUnsupported }

func refuseMeaningless(Table, string) error { return ErrUnsupported }

// WatchNetwork has no routing table to read here, for the same reason
func WatchNetwork(Host, string) (*NetworkWatch, error) { return nil, ErrUnsupported }
