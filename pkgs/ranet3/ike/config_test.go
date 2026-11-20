// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"fmt"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/schema"
)

// A node that writes no cap.crypto runs these, and a fleet mid-migration has
// to agree with the strongSwan it is replacing about every one of them.
func TestCryptoDefaultsAreTheOnesDocumented(t *testing.T) {
	var absent Crypto
	for name, got := range map[string]struct{ have, want time.Duration }{
		"rekey child":       {absent.ChildInterval(), time.Hour},
		"rekey ike":         {absent.IKEInterval(), 3 * time.Hour},
		"rekey margin":      {absent.Margin(), 5 * time.Minute},
		"rekey jitter":      {absent.Jitter(), time.Minute},
		"rekey retry first": {absent.RetryFirst(), 5 * time.Second},
		"rekey retry max":   {absent.RetryMax(), 5 * time.Minute},
	} {
		if got.have != got.want {
			t.Errorf("default %s is %s, want %s", name, got.have, got.want)
		}
	}
	if absent.ReplayWindow() != 4096 {
		t.Errorf("default replay window is %d, want 4096", absent.ReplayWindow())
	}
	if err := absent.Validate(); err != nil {
		t.Errorf("the defaults do not validate: %v", err)
	}
	// An explicit zero is a window turned off rather than an absent field.
	for _, want := range []uint32{0, 64, 8192} {
		configured := want
		if got := (Crypto{Replay: &configured}).ReplayWindow(); got != want {
			t.Errorf("configured replay window = %d, want %d", got, want)
		}
	}
	atCap := esp.MaxReplayWindow
	if err := (Crypto{Replay: &atCap}).Validate(); err != nil {
		t.Errorf("a replay window at the cap was refused: %v", err)
	}
}

// Everything a session captures when it is created reaches it from here, so a
// value written in the file and dropped on the way through would leave a node
// running the default while its operator reads otherwise.
func TestConfiguredCryptoReachesEveryTimer(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	crypto := Crypto{Rekey: Rekey{
		Child:  interval(2 * time.Hour),
		IKE:    interval(8 * time.Hour),
		Margin: interval(10 * time.Minute),
		Jitter: interval(2 * time.Minute),
		Retry:  Retry{First: interval(3 * time.Second), Max: interval(30 * time.Second)},
	}}
	if err := crypto.Validate(); err != nil {
		t.Fatalf("a configuration a session could run was refused: %v", err)
	}
	for name, got := range map[string]struct{ have, want time.Duration }{
		"rekey child":       {crypto.ChildInterval(), 2 * time.Hour},
		"rekey ike":         {crypto.IKEInterval(), 8 * time.Hour},
		"rekey margin":      {crypto.Margin(), 10 * time.Minute},
		"rekey jitter":      {crypto.Jitter(), 2 * time.Minute},
		"rekey retry first": {crypto.RetryFirst(), 3 * time.Second},
		"rekey retry max":   {crypto.RetryMax(), 30 * time.Second},
	} {
		if got.have != got.want {
			t.Errorf("%s is %s, want %s", name, got.have, got.want)
		}
	}
	want := RekeyTiming{ChildRekeyInterval: 2 * time.Hour, IKERekeyInterval: 8 * time.Hour, RekeyMargin: 10 * time.Minute, RekeyJitter: 2 * time.Minute,
		RekeyRetryInitial: 3 * time.Second, RekeyRetryMax: 30 * time.Second}
	s := newSession(nil, nil, crypto.Timing(), nil, false, nil)
	if s.timing != want {
		t.Errorf("a session built with the configured timing runs %+v, want %+v", s.timing, want)
	}
	// A rekey runs interval minus margin minus jitter, so a disabled interval
	// has no schedule for either to fit inside and neither is contradictory.
	disabled := Crypto{Rekey: Rekey{
		Child:  interval(0),
		IKE:    interval(0),
		Margin: interval(time.Hour),
		Jitter: interval(time.Hour),
	}}
	if err := disabled.Validate(); err != nil {
		t.Errorf("a margin beside two disabled rekeys was refused: %v", err)
	}
}

// a rekey due at the end of its SA's lifetime can never replace the SA, which closes there, so a zero margin is refused beside either lifetime, by name, and taken beside none
func TestCryptoRefusesAZeroMarginBesideALifetime(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	for name, test := range map[string]struct {
		rekey Rekey
		// beside is the interval the refusal names, the child one where both are set
		beside string
	}{
		"a child lifetime":      {Rekey{Child: interval(time.Minute), IKE: interval(0), Margin: interval(0), Jitter: interval(0)}, "child"},
		"an ike lifetime":       {Rekey{Child: interval(0), IKE: interval(15 * time.Second), Margin: interval(0), Jitter: interval(0)}, "ike"},
		"the default lifetimes": {Rekey{Margin: interval(0)}, "child"},
	} {
		t.Run(name, func(t *testing.T) {
			want := fmt.Sprintf("ike: cap.crypto rekey margin must be positive beside rekey %s, since a rekey due at the end of the SA's lifetime can never replace it", test.beside)
			if err := (Crypto{Rekey: test.rekey}).Validate(); err == nil || err.Error() != want {
				t.Errorf("a zero margin beside %s was answered %v, want %q", name, err, want)
			}
		})
	}
	if err := (Crypto{Rekey: Rekey{Child: interval(0), IKE: interval(0), Margin: interval(0)}}).Validate(); err != nil {
		t.Errorf("a zero margin beside two disabled rekeys was refused: %v", err)
	}
}

// Each of these is a session that could not run the timers it was handed, and
// the refusal names the field as the operator wrote it.
func TestCryptoRefusesTimingsASessionCannotRun(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	oversized := esp.MaxReplayWindow + 1
	for name, test := range map[string]struct {
		crypto Crypto
		want   string
	}{
		"a replay window past the cap": {Crypto{Replay: &oversized}, fmt.Sprintf("ike: cap.crypto replay must not exceed %d", esp.MaxReplayWindow)},
		"a negative child rekey":       {Crypto{Rekey: Rekey{Child: interval(-time.Second)}}, "ike: cap.crypto rekey child must be nonnegative when set"},
		"a negative ike rekey":         {Crypto{Rekey: Rekey{IKE: interval(-time.Second)}}, "ike: cap.crypto rekey ike must be nonnegative when set"},
		"a negative margin":            {Crypto{Rekey: Rekey{Margin: interval(-time.Second)}}, "ike: cap.crypto rekey margin must be nonnegative when set"},
		"a negative jitter":            {Crypto{Rekey: Rekey{Jitter: interval(-time.Second)}}, "ike: cap.crypto rekey jitter must be nonnegative when set"},
		"a zero first retry":           {Crypto{Rekey: Rekey{Retry: Retry{First: interval(0)}}}, "ike: cap.crypto rekey retry first must be positive when set"},
		"a zero retry maximum":         {Crypto{Rekey: Rekey{Retry: Retry{Max: interval(0)}}}, "ike: cap.crypto rekey retry max must be positive when set"},
		"a negative first retry":       {Crypto{Rekey: Rekey{Retry: Retry{First: interval(-time.Second)}}}, "ike: cap.crypto rekey retry first must be positive when set"},
		"a first retry past the max": {Crypto{Rekey: Rekey{Retry: Retry{
			First: interval(time.Minute), Max: interval(5 * time.Second),
		}}}, "ike: cap.crypto rekey retry first must not exceed retry max"},
		"a child rekey shorter than its margin": {Crypto{Rekey: Rekey{Child: interval(5 * time.Minute)}}, "ike: cap.crypto rekey child 5m0s is shorter than rekey margin 5m0s plus jitter 1m0s plus 1s"},
		"an ike rekey shorter than its margin":  {Crypto{Rekey: Rekey{IKE: interval(6 * time.Minute)}}, "ike: cap.crypto rekey ike 6m0s is shorter than rekey margin 5m0s plus jitter 1m0s plus 1s"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := test.crypto.Validate(); err == nil || err.Error() != test.want {
				t.Errorf("a session that could not run these timers was answered %v, want %q", err, test.want)
			}
		})
	}
}

// the floors and messages are the configuration reference's, 10 seconds for a lifetime and the margin and 1 second for a retry delay, so a floor moved from either value fails here
func TestCryptoRefusesRekeyTimingsUnderTheirFloors(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	for name, test := range map[string]struct {
		rekey Rekey
		want  string
	}{
		"a child lifetime under the floor": {Rekey{Child: interval(10*time.Second - time.Nanosecond)}, "ike: cap.crypto rekey child 9.999999999s is shorter than 10s"},
		"an ike lifetime under the floor":  {Rekey{IKE: interval(10*time.Second - time.Nanosecond)}, "ike: cap.crypto rekey ike 9.999999999s is shorter than 10s"},
		"a margin under the floor":         {Rekey{Margin: interval(10*time.Second - time.Nanosecond)}, "ike: cap.crypto rekey margin 9.999999999s is shorter than 10s"},
		"a first retry under the floor":    {Rekey{Retry: Retry{First: interval(time.Second - time.Nanosecond)}}, "ike: cap.crypto rekey retry first 999.999999ms is shorter than 1s"},
		"a retry maximum under the floor":  {Rekey{Retry: Retry{Max: interval(time.Second - time.Nanosecond)}}, "ike: cap.crypto rekey retry max 999.999999ms is shorter than 1s"},
		"a child lifetime of 2ns":          {Rekey{Child: interval(2), Margin: interval(1), Jitter: interval(0)}, "ike: cap.crypto rekey child 2ns is shorter than 10s"},
		"an ike lifetime of 2ns":           {Rekey{Child: interval(0), IKE: interval(2), Margin: interval(1), Jitter: interval(0)}, "ike: cap.crypto rekey ike 2ns is shorter than 10s"},
		"a child lifetime of 1s":           {Rekey{Child: interval(time.Second), Margin: interval(500 * time.Millisecond), Jitter: interval(0)}, "ike: cap.crypto rekey child 1s is shorter than 10s"},
		"a first retry and maximum of 1ns": {Rekey{Retry: Retry{First: interval(1), Max: interval(1)}}, "ike: cap.crypto rekey retry first 1ns is shorter than 1s"},
		// a lifetime under its floor is answered by its own name ahead of the zero margin beside it
		"a child lifetime under the floor beside a zero margin": {Rekey{Child: interval(10*time.Second - time.Nanosecond), Margin: interval(0)}, "ike: cap.crypto rekey child 9.999999999s is shorter than 10s"},
		"an ike lifetime under the floor beside a zero margin":  {Rekey{Child: interval(0), IKE: interval(10*time.Second - time.Nanosecond), Margin: interval(0)}, "ike: cap.crypto rekey ike 9.999999999s is shorter than 10s"},
		// a margin that is on is at least its own floor, so a lifetime at its floor passes it and meets the relation to the margin instead
		"a child lifetime a nanosecond under 11s beside the least margin and no jitter": {Rekey{Child: interval(11*time.Second - time.Nanosecond), Margin: interval(10 * time.Second), Jitter: interval(0)}, "ike: cap.crypto rekey child 10.999999999s is shorter than rekey margin 10s plus jitter 0s plus 1s"},
		"a child lifetime at the floor": {Rekey{Child: interval(10 * time.Second), Margin: interval(10 * time.Second), Jitter: interval(0)}, "ike: cap.crypto rekey child 10s is shorter than rekey margin 10s plus jitter 0s plus 1s"},
		"an ike lifetime at the floor":  {Rekey{IKE: interval(10 * time.Second), Margin: interval(10 * time.Second), Jitter: interval(0)}, "ike: cap.crypto rekey ike 10s is shorter than rekey margin 10s plus jitter 0s plus 1s"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (Crypto{Rekey: test.rekey}).Validate(); err == nil || err.Error() != test.want {
				t.Errorf("%s was answered %v, want %q", name, err, test.want)
			}
		})
	}
	for name, rekey := range map[string]Rekey{
		"a margin at the floor": {Margin: interval(10 * time.Second)},
		"a child lifetime of 11s beside the least margin and no jitter": {Child: interval(11 * time.Second), Margin: interval(10 * time.Second), Jitter: interval(0)},
		"a first retry at the floor":                                    {Retry: Retry{First: interval(time.Second)}},
		"a retry maximum at the floor":                                  {Retry: Retry{First: interval(time.Second), Max: interval(time.Second)}},
		"a child lifetime of 0":                                         {Child: interval(0)},
		"an ike lifetime of 0":                                          {IKE: interval(0)},
	} {
		if err := (Crypto{Rekey: rekey}).Validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	if minRekeyMargin < requestTimeout+childRetireDelay {
		t.Errorf("a margin at the floor of %s does not hold a resend after %s and the drain of %s", minRekeyMargin, requestTimeout, childRetireDelay)
	}
	if minRekeyRetry < max(minPeerChildRekeyInterval, minPeerIKERekeyInterval) {
		t.Errorf("a retry at the floor of %s comes inside the %s or %s a ranet3 peer refuses a second rekey in", minRekeyRetry, minPeerChildRekeyInterval, minPeerIKERekeyInterval)
	}
}

// the relations among the rekey timings, with the defaults filled in
func TestCryptoHoldsRekeyTimingsToEachOther(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	for name, test := range map[string]struct {
		rekey Rekey
		want  string
	}{
		"a child lifetime a nanosecond short":                    {Rekey{Child: interval(16*time.Second - time.Nanosecond), Margin: interval(10 * time.Second), Jitter: interval(5 * time.Second)}, "ike: cap.crypto rekey child 15.999999999s is shorter than rekey margin 10s plus jitter 5s plus 1s"},
		"an ike lifetime a nanosecond short":                     {Rekey{IKE: interval(16*time.Second - time.Nanosecond), Margin: interval(10 * time.Second), Jitter: interval(5 * time.Second)}, "ike: cap.crypto rekey ike 15.999999999s is shorter than rekey margin 10s plus jitter 5s plus 1s"},
		"a child lifetime a nanosecond short of the defaults":    {Rekey{Child: interval(6*time.Minute + time.Second - time.Nanosecond)}, "ike: cap.crypto rekey child 6m0.999999999s is shorter than rekey margin 5m0s plus jitter 1m0s plus 1s"},
		"an ike lifetime a nanosecond short of the defaults":     {Rekey{IKE: interval(6*time.Minute + time.Second - time.Nanosecond)}, "ike: cap.crypto rekey ike 6m0.999999999s is shorter than rekey margin 5m0s plus jitter 1m0s plus 1s"},
		"a child lifetime of 6m0.5s beside the defaults":         {Rekey{Child: interval(6*time.Minute + 500*time.Millisecond)}, "ike: cap.crypto rekey child 6m0.5s is shorter than rekey margin 5m0s plus jitter 1m0s plus 1s"},
		"a first retry as long as the margin":                    {Rekey{Margin: interval(10 * time.Second), Retry: Retry{First: interval(10 * time.Second)}}, "ike: cap.crypto rekey retry first 10s must be shorter than rekey margin 10s while a lifetime is on"},
		"a first retry as long as the margin beside ike alone":   {Rekey{Child: interval(0), Margin: interval(10 * time.Second), Retry: Retry{First: interval(10 * time.Second)}}, "ike: cap.crypto rekey retry first 10s must be shorter than rekey margin 10s while a lifetime is on"},
		"a first retry as long as the margin beside child alone": {Rekey{IKE: interval(0), Margin: interval(10 * time.Second), Retry: Retry{First: interval(10 * time.Second)}}, "ike: cap.crypto rekey retry first 10s must be shorter than rekey margin 10s while a lifetime is on"},
		"a margin and jitter whose sum overflows":                {Rekey{Margin: interval(1500000 * time.Hour), Jitter: interval(1500000 * time.Hour)}, "ike: cap.crypto rekey child 1h0m0s is shorter than rekey margin 1500000h0m0s plus jitter 1500000h0m0s plus 1s"},
		"a first retry as long as the default margin":            {Rekey{Retry: Retry{First: interval(5 * time.Minute)}}, "ike: cap.crypto rekey retry first 5m0s must be shorter than rekey margin 5m0s while a lifetime is on"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (Crypto{Rekey: test.rekey}).Validate(); err == nil || err.Error() != test.want {
				t.Errorf("%s was answered %v, want %q", name, err, test.want)
			}
		})
	}
	for name, rekey := range map[string]Rekey{
		"a child lifetime of margin plus jitter plus a second": {Child: interval(16 * time.Second), Margin: interval(10 * time.Second), Jitter: interval(5 * time.Second)},
		"an ike lifetime of margin plus jitter plus a second":  {IKE: interval(16 * time.Second), Margin: interval(10 * time.Second), Jitter: interval(5 * time.Second)},
		"a child lifetime of the defaults plus a second":       {Child: interval(6*time.Minute + time.Second)},
		"an ike lifetime of the defaults plus a second":        {IKE: interval(6*time.Minute + time.Second)},
		"a first retry a nanosecond under the margin":          {Margin: interval(10 * time.Second), Retry: Retry{First: interval(10*time.Second - time.Nanosecond)}},
		"a first retry past the margin beside no lifetime":     {Child: interval(0), IKE: interval(0), Margin: interval(10 * time.Second), Retry: Retry{First: interval(20 * time.Second)}},
	} {
		if err := (Crypto{Rekey: rekey}).Validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}
