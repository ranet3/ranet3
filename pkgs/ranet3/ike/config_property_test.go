// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"fmt"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// at is a timing written in the file
func at(d time.Duration) *schema.Duration {
	timing := schema.Duration(d)
	return &timing
}

// drawRekey draws six timings that load, each from its accepted edges or its range, and then in most cases makes one move
// a move breaks one rule on purpose, or lands on the exemption of the second relation, so each rule decides a fair share of cases
// a case that broke a rule in every field would be answered by its first, masking the rest
func drawRekey(tc hegel.TestCase) Rekey {
	pick := func(chance float64) bool { return hegel.Draw(tc, hegel.WeightedBooleans(chance)) }
	within := func(edges []time.Duration, lo, hi time.Duration) time.Duration {
		if len(edges) > 0 && pick(0.6) {
			return hegel.Draw(tc, hegel.SampledFrom(edges))
		}
		return time.Duration(hegel.Draw(tc, hegel.Integers(int64(lo), int64(hi))))
	}
	var r Rekey
	childOff, ikeOff := pick(0.35), pick(0.35)
	on := !childOff || !ikeOff
	if !pick(0.15) {
		if !on && pick(0.3) {
			r.Margin = at(0)
		} else {
			r.Margin = at(within([]time.Duration{minRekeyMargin, minRekeyMargin + time.Nanosecond}, minRekeyMargin, 10*time.Minute))
		}
	}
	if !pick(0.15) {
		r.Jitter = at(within([]time.Duration{0, time.Nanosecond}, 0, 10*time.Minute))
	}
	margin, jitter := orDefault(r.Margin, DefaultRekeyMargin), orDefault(r.Jitter, DefaultRekeyJitter)
	least := func(spacing time.Duration) time.Duration { return margin + jitter + spacing }
	lifetime := func(off bool, spacing time.Duration) *schema.Duration {
		switch {
		case off:
			return at(0)
		case pick(0.15):
			return nil
		}
		return at(within([]time.Duration{least(spacing), least(spacing) + time.Nanosecond}, least(spacing), 2*time.Hour))
	}
	r.Child, r.IKE = lifetime(childOff, minPeerChildRekeyInterval), lifetime(ikeOff, minPeerIKERekeyInterval)
	if !pick(0.15) {
		r.Retry.Max = at(within([]time.Duration{minRekeyRetry, minRekeyRetry + time.Nanosecond}, minRekeyRetry, time.Hour))
	}
	last := orDefault(r.Retry.Max, DefaultRetryMax)
	candidates := []time.Duration{minRekeyRetry, minRekeyRetry + time.Nanosecond, last, margin, margin + time.Nanosecond}
	if on {
		last = min(last, margin-time.Nanosecond)
		candidates = append(candidates, last)
	}
	var edges []time.Duration
	for _, edge := range candidates {
		if edge >= minRekeyRetry && edge <= last {
			edges = append(edges, edge)
		}
	}
	if DefaultRetryFirst > last || !pick(0.15) {
		r.Retry.First = at(within(edges, minRekeyRetry, last))
	}
	if pick(0.85) {
		move(tc, &r)
	}
	return r
}

// move changes r so that it breaks the one rule a drawn move names, or so that it meets the exemption of the second relation
func move(tc hegel.TestCase, r *Rekey) {
	fields := []**schema.Duration{&r.Child, &r.IKE, &r.Margin, &r.Jitter, &r.Retry.First, &r.Retry.Max}
	floors := []time.Duration{minRekeyLifetime, minRekeyLifetime, minRekeyMargin, 0, minRekeyRetry, minRekeyRetry}
	margin := func() time.Duration { return orDefault(r.Margin, DefaultRekeyMargin) }
	jitter := func() time.Duration { return orDefault(r.Jitter, DefaultRekeyJitter) }
	// the second relation's moves need a margin that is on and a max that holds the first retry they write
	retryAt := func(first time.Duration) {
		if margin() == 0 {
			r.Margin = at(minRekeyMargin)
		}
		first += margin()
		if orDefault(r.Retry.Max, DefaultRetryMax) < first {
			r.Retry.Max = at(first)
		}
		r.Retry.First = at(first)
	}
	switch hegel.Draw(tc, hegel.Integers(0, 19)) {
	case 0: // a negative value in any field
		*fields[hegel.Draw(tc, hegel.Integers(0, 5))] = at(-time.Nanosecond)
	case 1: // a retry delay of zero
		*fields[hegel.Draw(tc, hegel.Integers(4, 5))] = at(0)
	case 2, 14, 15, 16, 17: // a nanosecond under a floor, drawn as often as the five fields that have one
		i := hegel.Draw(tc, hegel.SampledFrom([]int{0, 1, 2, 4, 5}))
		*fields[i] = at(floors[i] - time.Nanosecond)
	case 3: // a lifetime at its floor, which the first relation refuses beside a margin at least its own floor
		*fields[hegel.Draw(tc, hegel.Integers(0, 1))] = at(minRekeyLifetime)
	case 4: // a first retry a nanosecond past max
		r.Retry.First = at(orDefault(r.Retry.Max, DefaultRetryMax) + time.Nanosecond)
	case 5: // a zero margin beside a lifetime
		r.Margin = at(0)
		if orDefault(r.Child, DefaultChildRekey) == 0 && orDefault(r.IKE, DefaultIKERekey) == 0 {
			r.Child = nil
		}
	case 6: // a child lifetime a nanosecond short of the first relation
		r.Child = at(margin() + jitter() + minPeerChildRekeyInterval - time.Nanosecond)
	case 7: // an ike lifetime a nanosecond short of the first relation
		r.IKE = at(margin() + jitter() + minPeerIKERekeyInterval - time.Nanosecond)
	case 8, 9: // a first retry as long as the margin, or a nanosecond longer, beside the lifetimes as drawn or the defaults
		if orDefault(r.Child, DefaultChildRekey) == 0 && orDefault(r.IKE, DefaultIKERekey) == 0 {
			r.Child = nil
		}
		retryAt(time.Duration(hegel.Draw(tc, hegel.Integers(0, 1))))
	case 10: // the same beside child alone
		r.Child, r.IKE = nil, at(0)
		retryAt(0)
	case 11: // the same beside ike alone
		r.Child, r.IKE = at(0), nil
		retryAt(0)
	case 18, 19: // a lifetime anywhere above 0 and under its floor
		*fields[hegel.Draw(tc, hegel.Integers(0, 1))] = at(time.Duration(hegel.Draw(tc, hegel.Integers(int64(1), int64(minRekeyLifetime-time.Nanosecond)))))
	case 12, 13: // the exemption, a first retry at or past the margin beside two lifetimes that are off, which loads
		r.Child, r.IKE = at(0), at(0)
		retryAt(time.Duration(hegel.Draw(tc, hegel.Integers(0, 1))))
	}
}

// orDefault is a timing as a session runs it
func orDefault(written *schema.Duration, fallback time.Duration) time.Duration {
	if written == nil {
		return fallback
	}
	return written.Duration()
}

// referenceRefusal is the message the configuration reference's rules give for r, or the empty string where r loads
// every rule that r breaks is listed in the order Validate answers them, since the page states no order, and the first answers
func referenceRefusal(r Rekey) string {
	var broken []string
	for _, written := range []struct {
		name     string
		value    *schema.Duration
		floor    time.Duration
		positive bool
	}{
		{"rekey child", r.Child, minRekeyLifetime, false},
		{"rekey ike", r.IKE, minRekeyLifetime, false},
		{"rekey margin", r.Margin, minRekeyMargin, false},
		{"rekey jitter", r.Jitter, 0, false},
		{"rekey retry first", r.Retry.First, minRekeyRetry, true},
		{"rekey retry max", r.Retry.Max, minRekeyRetry, true},
	} {
		switch {
		case written.value == nil:
		case written.positive && *written.value <= 0:
			broken = append(broken, fmt.Sprintf("ike: cap.crypto %s must be positive when set", written.name))
		case *written.value < 0:
			broken = append(broken, fmt.Sprintf("ike: cap.crypto %s must be nonnegative when set", written.name))
		case *written.value != 0 && written.value.Duration() < written.floor:
			broken = append(broken, fmt.Sprintf("ike: cap.crypto %s %s is shorter than %s", written.name, written.value, written.floor))
		}
	}
	child, ike := orDefault(r.Child, DefaultChildRekey), orDefault(r.IKE, DefaultIKERekey)
	margin, jitter := orDefault(r.Margin, DefaultRekeyMargin), orDefault(r.Jitter, DefaultRekeyJitter)
	first, last := orDefault(r.Retry.First, DefaultRetryFirst), orDefault(r.Retry.Max, DefaultRetryMax)
	if first > last {
		broken = append(broken, "ike: cap.crypto rekey retry first must not exceed retry max")
	}
	for _, lifetime := range []struct {
		name        string
		on          time.Duration
		peerSpacing time.Duration
	}{{"child", child, minPeerChildRekeyInterval}, {"ike", ike, minPeerIKERekeyInterval}} {
		switch {
		case lifetime.on == 0:
		case margin == 0:
			broken = append(broken, fmt.Sprintf("ike: cap.crypto rekey margin must be positive beside rekey %s, since a rekey due at the end of the SA's lifetime can never replace it", lifetime.name))
		case lifetime.on < margin+jitter+lifetime.peerSpacing:
			broken = append(broken, fmt.Sprintf("ike: cap.crypto rekey %s %s is shorter than rekey margin %s plus jitter %s plus %s", lifetime.name, lifetime.on, margin, jitter, lifetime.peerSpacing))
		}
	}
	if (child != 0 || ike != 0) && first >= margin {
		broken = append(broken, fmt.Sprintf("ike: cap.crypto rekey retry first %s must be shorter than rekey margin %s while a lifetime is on", first, margin))
	}
	if len(broken) == 0 {
		return ""
	}
	return broken[0]
}

// Validate refuses the rekey timings the configuration reference refuses, with the message of the first rule broken, and takes every other
func TestCryptoRefusesRekeyTimingsAsTheReferenceStates(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		r := drawRekey(ht)
		want := referenceRefusal(r)
		err := (Crypto{Rekey: r}).Validate()
		switch {
		case want == "" && err != nil:
			ht.Fatalf("%+v was refused with %v, which the reference loads", r, err)
		case want != "" && (err == nil || err.Error() != want):
			ht.Fatalf("%+v was answered %v, want %q", r, err, want)
		}
	})
}
