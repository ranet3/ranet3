// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the Transform Type 4 IDs the properties draw a key exchange from, the classical groups and the two ML-KEM methods
var kexMethods = []uint16{DH_CURVE25519, DH_ECP_384, DH_ECP_256, ML_KEM_768, ML_KEM_1024}

// drawnEntries draws a kex list of distinct entries, each a group and up to three methods after it, none repeated within the entry
func drawnEntries(tc hegel.TestCase, classical bool) []kexEntry {
	var entries []kexEntry
	for range hegel.Draw(tc, pbt.Spanning(1, 4)) {
		entry := kexEntry{group: hegel.Draw(tc, hegel.SampledFrom(kexMethods[:3]))}
		if !classical {
			remaining := slices.Clone(kexMethods)
			for at := range hegel.Draw(tc, pbt.Spanning(0, 3)) {
				i := hegel.Draw(tc, hegel.Integers(0, len(remaining)-1))
				entry.additions[at] = remaining[i]
				remaining = slices.Delete(remaining, i, i+1)
			}
		}
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// drawnSubset draws a run of distinct transforms of every in the order drawn, of least to most of them
func drawnSubset(tc hegel.TestCase, every []Transform, least, most int) []Transform {
	remaining := slices.Clone(every)
	var out []Transform
	for range hegel.Draw(tc, pbt.Spanning(least, min(most, len(every)))) {
		i := hegel.Draw(tc, hegel.Integers(0, len(remaining)-1))
		out = append(out, remaining[i])
		remaining = slices.Delete(remaining, i, i+1)
	}
	return out
}

// drawnIKEProposal draws a peer's IKE SA proposal numbered number
// most of the time it aims at entries[aim], or at an entry it draws where aim is out of range
// a proposal aiming at an entry holds its group and its methods over ADDKE types in order, with gaps between them and NONE beside them at times
// beside that it holds ciphers, PRFs and groups in any order and number, more IDs in any ADDKE type with NONE and every method among them, and at times a type this end does not know
func drawnIKEProposal(tc hegel.TestCase, number uint8, entries []kexEntry, aim int) Proposal {
	var groups []Transform
	for _, method := range kexMethods[:3] {
		groups = append(groups, Transform{Type: TransDH, ID: method})
	}
	transforms := slices.Concat(
		drawnSubset(tc, listed(nil, cipherNames), 1, 3),
		drawnSubset(tc, listed(nil, prfNames), 1, 2),
		drawnSubset(tc, groups, 0, 3))
	var offered [addkeTypes][]uint16
	pool := append([]uint16{0}, kexMethods...)
	if hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
		if aim < 0 || aim >= len(entries) {
			aim = hegel.Draw(tc, hegel.Integers(0, len(entries)-1))
		}
		entry := entries[aim]
		// half the time the other types draw from NONE and the entry's own methods, which gives a method more than one type to sit in
		if hegel.Draw(tc, hegel.Booleans()) {
			pool = append([]uint16{0}, entry.added()...)
		}
		if !slices.Contains(transforms, Transform{Type: TransDH, ID: entry.group}) {
			transforms = append(transforms, Transform{Type: TransDH, ID: entry.group})
		}
		at := 0
		for _, method := range entry.added() {
			at += hegel.Draw(tc, pbt.Spanning(0, 1))
			if at >= addkeTypes {
				break
			}
			offered[at] = append(offered[at], method)
			if hegel.Draw(tc, hegel.Booleans()) {
				offered[at] = append(offered[at], 0)
			}
			at++
		}
	}
	for t := range offered {
		if hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
			continue
		}
		// mostly with NONE, since a type requiring a method rules out every entry that leaves the type unused
		if hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) && !slices.Contains(offered[t], 0) {
			offered[t] = append(offered[t], 0)
		}
		for range hegel.Draw(tc, pbt.Spanning(1, 3)) {
			if id := hegel.Draw(tc, hegel.SampledFrom(pool)); !slices.Contains(offered[t], id) {
				offered[t] = append(offered[t], id)
			}
		}
	}
	for t, ids := range offered {
		for _, id := range ids {
			transforms = append(transforms, Transform{Type: TransADDKE1 + TransformType(t), ID: id})
		}
	}
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
		transforms = append(transforms, Transform{Type: TransformType(15), ID: 1})
	}
	// a proposal's transforms reach the responder in the order the peer wrote them
	for i := len(transforms) - 1; i > 0; i-- {
		j := hegel.Draw(tc, hegel.Integers(0, i))
		transforms[i], transforms[j] = transforms[j], transforms[i]
	}
	return Proposal{Number: number, Protocol: ProtoIKE, Transforms: transforms}
}

// modelAdditions is every way to take one transform of each ADDKE type the proposal holds, in type order, whose methods other than NONE run as methods do
// earlier types carrying the methods come first
func modelAdditions(transforms []Transform, methods []uint16) [][]Transform {
	var types []TransformType
	for t := TransADDKE1; t <= TransADDKE7; t++ {
		if slices.ContainsFunc(transforms, func(transform Transform) bool { return transform.Type == t }) {
			types = append(types, t)
		}
	}
	ways := [][]Transform{nil}
	for _, t := range types {
		var next [][]Transform
		for _, way := range ways {
			for _, transform := range transforms {
				if transform.Type == t {
					next = append(next, append(slices.Clone(way), transform))
				}
			}
		}
		ways = next
	}
	var runs [][]Transform
	for _, way := range ways {
		var ran []uint16
		for _, transform := range way {
			if transform.ID != 0 {
				ran = append(ran, transform.ID)
			}
		}
		if slices.Equal(ran, methods) {
			runs = append(runs, way)
		}
	}
	// carriers is the ADDKE types a way runs a method in
	carriers := func(way []Transform) []TransformType {
		var types []TransformType
		for _, transform := range way {
			if transform.ID != 0 {
				types = append(types, transform.Type)
			}
		}
		return types
	}
	slices.SortStableFunc(runs, func(a, b []Transform) int { return slices.Compare(carriers(a), carriers(b)) })
	return runs
}

// modelChoice is the answer RFC 7296 and R304 give an offer, found pair by pair: each entry in this end's order, and for it each proposal in the offer's order
// a proposal counts while its types are known, ADDKE among them, and while the lists meet it in cipher and PRF
func modelChoice(proposals []Proposal, ciphers, prfs []Transform, entries []kexEntry, keGroup uint16) (Proposal, uint16, bool) {
	counts := func(proposal Proposal) bool {
		for _, transform := range proposal.Transforms {
			known := transform.Type == TransEncr || transform.Type == TransPRF || transform.Type == TransDH || additional(transform.Type)
			if !known {
				return false
			}
		}
		return slices.ContainsFunc(ciphers, func(t Transform) bool { return slices.Contains(proposal.Transforms, t) }) &&
			slices.ContainsFunc(prfs, func(t Transform) bool { return slices.Contains(proposal.Transforms, t) })
	}
	first := func(preferred, offered []Transform) Transform {
		for _, t := range preferred {
			if slices.Contains(offered, t) {
				return t
			}
		}
		return Transform{}
	}
	for _, entry := range entries {
		group := Transform{Type: TransDH, ID: entry.group}
		for _, proposal := range proposals {
			if !counts(proposal) || !slices.Contains(proposal.Transforms, group) {
				continue
			}
			ways := modelAdditions(proposal.Transforms, entry.added())
			if len(ways) == 0 {
				continue
			}
			if entry.group != keGroup {
				return Proposal{}, entry.group, false
			}
			answer := slices.Concat([]Transform{first(ciphers, proposal.Transforms), first(prfs, proposal.Transforms), group}, ways[0])
			return Proposal{Number: proposal.Number, Protocol: ProtoIKE, Transforms: answer}, 0, true
		}
	}
	return Proposal{}, 0, false
}

// a peer's IKE SA offer is answered in the proposal and the transforms a model enumerating every (entry, proposal) pair in R304's order finds
// so the answer holds one transform of each type the proposal holds, NONE for an ADDKE type the entry leaves unused, and no method twice
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
// RFC 9370 section 2.2.1: "However, for the ADDKE Transform Types, the responder's choice MUST NOT contain duplicated algorithms (those with an identical Transform ID and attributes), except for the Transform ID of NONE."
func TestIKEOfferIsAnsweredAsTheModelOfEveryEntryAndProposalPairChooses(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		entries := drawnEntries(ht, false)
		// half the time the lists hold every cipher and PRF, so the key exchanges alone decide between proposals
		ciphers, prfs := listed(nil, cipherNames), listed(nil, prfNames)
		if hegel.Draw(ht, hegel.Booleans()) {
			ciphers, prfs = drawnSubset(ht, ciphers, 1, 3), drawnSubset(ht, prfs, 1, 2)
		}
		// half the time the proposals aim at the entries in reverse, where the order of R304 and the order of the proposals part
		reversed := hegel.Draw(ht, hegel.Booleans())
		var proposals []Proposal
		for i := range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			aim := -1
			if reversed {
				aim = len(entries) - 1 - i
			}
			proposals = append(proposals, drawnIKEProposal(ht, uint8(i+1), entries, aim))
		}
		// mostly the group of an entry, so a choice is answered more often than asked again
		keGroup := hegel.Draw(ht, hegel.SampledFrom(kexMethods[:3]))
		if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
			keGroup = entries[hegel.Draw(ht, hegel.Integers(0, len(entries)-1))].group
		}
		chosen, retry, ok := chooseIKE(proposals, ciphers, prfs, entries, keGroup)
		want, wantRetry, wantOK := modelChoice(proposals, ciphers, prfs, entries, keGroup)
		if ok != wantOK || retry != wantRetry {
			ht.Fatalf("chose %v asking for group %d, the model %v asking for group %d", ok, retry, wantOK, wantRetry)
		}
		if !ok {
			return
		}
		answer := Proposal{Number: chosen.offered.Number, Protocol: ProtoIKE, Transforms: chosen.transforms}
		if !slices.EqualFunc(answer.Transforms, want.Transforms, func(a, b Transform) bool { return a == b }) || answer.Number != want.Number {
			ht.Fatalf("answered %+v, the model %+v", answer, want)
		}
		offered := proposals[slices.IndexFunc(proposals, func(p Proposal) bool { return p.Number == answer.Number })]
		var types []TransformType
		var methods []uint16
		for _, transform := range answer.Transforms {
			if slices.Contains(types, transform.Type) || !slices.Contains(offered.Transforms, transform) {
				ht.Fatalf("the answer %+v holds a type twice or a transform proposal %d did not offer", answer, answer.Number)
			}
			types = append(types, transform.Type)
			if additional(transform.Type) && transform.ID != 0 {
				if slices.Contains(methods, transform.ID) {
					ht.Fatalf("the answer %+v runs method %d twice", answer, transform.ID)
				}
				methods = append(methods, transform.ID)
			}
		}
		for _, transform := range offered.Transforms {
			if !slices.Contains(types, transform.Type) {
				ht.Fatalf("the answer %+v leaves out type %d of proposal %+v", answer, transform.Type, offered)
			}
		}
		suiteFromAnswer, err := suiteFromProposal(answer, proposals, true)
		if err != nil {
			ht.Fatalf("the answer %+v does not read back: %v", answer, err)
		}
		if suiteFromAnswer != chosen.suite {
			ht.Fatalf("the answer reads back as %+v, the responder holds %+v", suiteFromAnswer, chosen.suite)
		}
	})
}

// a split offer of classical entries is answered in the transforms one proposal holding every group would have drawn
// so an end offering an entry to a proposal changes no choice ranet3 made before RFC 9370's entries
func TestSplitClassicalOfferIsAnsweredAsOneProposalOfEveryGroup(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		initiator := Suites{
			ikeCipher: drawnSubset(ht, listed(nil, cipherNames), 0, 3),
			ikePRF:    drawnSubset(ht, listed(nil, prfNames), 0, 2),
			kex:       drawnEntries(ht, true),
		}
		responder := Suites{
			ikeCipher: drawnSubset(ht, listed(nil, cipherNames), 0, 3),
			ikePRF:    drawnSubset(ht, listed(nil, prfNames), 0, 2),
			kex:       drawnEntries(ht, true),
		}
		keGroup := hegel.Draw(ht, hegel.SampledFrom(kexMethods[:3]))
		split := initiator.ikeProposals(keGroup)
		combined := split[0]
		combined.Transforms = slices.Concat(initiator.ikeCiphers(), initiator.ikePRFs())
		for _, entry := range promoted(initiator.kexEntries(), kexEntry{group: keGroup}) {
			combined.Transforms = append(combined.Transforms, Transform{Type: TransDH, ID: entry.group})
		}
		got, gotRetry, gotOK := chooseIKE(split, responder.ikeCiphers(), responder.ikePRFs(), responder.kexEntries(), keGroup)
		want, wantRetry, wantOK := chooseIKE([]Proposal{combined}, responder.ikeCiphers(), responder.ikePRFs(), responder.kexEntries(), keGroup)
		if gotOK != wantOK || gotRetry != wantRetry || got.suite != want.suite {
			ht.Fatalf("the split offer %+v drew %+v (%v, group %d), one proposal of every group %+v (%v, group %d)",
				split, got.suite, gotOK, gotRetry, want.suite, wantOK, wantRetry)
		}
	})
}

// an IKE SA answer is taken only as the single choice of one proposal this end offered, by its number
// every mutation of such an answer is refused: another proposal's number, a transform left out or added, a type named twice, an unoffered ID or NONE, a method run twice, an ADDKE type where the exchange reads none
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
// RFC 9370 section 2.2.1: "If the responder's message contains one or more duplicated choices, the initiator should log the error and MUST treat the exchange as failed."
func TestIKEAnswerIsTakenOnlyAsTheSingleChoiceOfAnOfferedProposal(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		lists := Suites{kex: drawnEntries(ht, false)}
		offer := lists.ikeProposals(lists.kexEntries()[hegel.Draw(ht, hegel.Integers(0, len(lists.kexEntries())-1))].group)
		at := hegel.Draw(ht, hegel.Integers(0, len(offer)-1))
		proposal := offer[at]
		var answer []Transform
		for _, t := range []TransformType{TransEncr, TransPRF} {
			var of []Transform
			for _, transform := range proposal.Transforms {
				if transform.Type == t {
					of = append(of, transform)
				}
			}
			answer = append(answer, of[hegel.Draw(ht, hegel.Integers(0, len(of)-1))])
		}
		for _, transform := range proposal.Transforms {
			if transform.Type == TransDH || additional(transform.Type) {
				answer = append(answer, transform)
			}
		}
		valid := Proposal{Number: proposal.Number, Protocol: ProtoIKE, Transforms: answer}
		suite, err := suiteFromProposal(valid, offer, true)
		var entry kexEntry
		for _, e := range lists.kexEntries() {
			if slices.Equal(entryProposalKex(e), kexOf(proposal)) {
				entry = e
			}
		}
		if err != nil || suite.entry() != entry || suite.EncrID != answer[0].ID || suite.EncrKeyBits != answer[0].KeyLengthBits || suite.PRFID != answer[1].ID {
			ht.Fatalf("the single choice %+v of proposal %+v read as %+v, %v, want entry %+v", valid, proposal, suite, err, entry)
		}
		hasAddke := !entry.classical()
		if _, err := suiteFromProposal(valid, offer, false); (err == nil) == hasAddke {
			ht.Fatalf("the single choice %+v without ADDKE types read was taken %v, want %v", valid, err == nil, !hasAddke)
		}
		mutated := valid
		mutated.Transforms = slices.Clone(valid.Transforms)
		switch hegel.Draw(ht, pbt.Spanning(0, 6)) {
		case 0:
			if len(offer) == 1 {
				return
			}
			others := slices.DeleteFunc(slices.Clone(offer), func(p Proposal) bool { return p.Number == proposal.Number })
			mutated.Number = others[hegel.Draw(ht, hegel.Integers(0, len(others)-1))].Number
		case 1:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms = slices.Delete(mutated.Transforms, i, i+1)
		case 2:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms = slices.Insert(mutated.Transforms, i, mutated.Transforms[i])
		case 3:
			extra := hegel.Draw(ht, hegel.SampledFrom([]Transform{
				{Type: TransInteg, ID: INTEG_NONE}, {Type: TransESN, ID: ESN_NO}, {Type: TransformType(15), ID: 1},
				{Type: TransADDKE7, ID: 0}, {Type: TransADDKE7, ID: ML_KEM_768},
			}))
			mutated.Transforms = append(mutated.Transforms, extra)
		case 4:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms[i].ID = hegel.Draw(ht, hegel.SampledFrom([]uint16{0, 1, ENCR_AES_GCM_16 + 1, DH_ECP_256 - 1, ML_KEM_768 - 1}))
			if mutated.Transforms[i] == valid.Transforms[i] {
				return
			}
		case 5:
			if len(entry.added()) == 0 {
				return
			}
			// a second ADDKE type running a method the answer runs already
			mutated.Transforms = append(mutated.Transforms, Transform{Type: TransADDKE1 + TransformType(len(entry.added())), ID: entry.added()[0]})
		case 6:
			mutated.Protocol = ProtoESP
		}
		if got, err := suiteFromProposal(mutated, offer, true); err == nil {
			ht.Fatalf("the answer %+v to the offer %+v was taken as %+v", mutated, offer, got)
		}
	})
}

// entryProposalKex is the key exchange transforms a proposal offering entry holds
func entryProposalKex(entry kexEntry) []Transform {
	kex := []Transform{{Type: TransDH, ID: entry.group}}
	for at, method := range entry.added() {
		kex = append(kex, Transform{Type: TransADDKE1 + TransformType(at), ID: method})
	}
	return kex
}
