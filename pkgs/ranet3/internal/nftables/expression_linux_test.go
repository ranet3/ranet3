// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// A prefix's mask reads back with the boolean operation a dump writes for a
// bitwise expression written with none, as Linux does since it took
// NFTA_BITWISE_OP, and reads as written. A shift in its place does not.
func TestExpressionFaultReadsABitwiseBooleanOperationAsWritten(t *testing.T) {
	written := append(SourcePrefix(netip.MustParsePrefix("198.18.0.0/15")), CountedDrop()...)
	dumped := func(op uint32) []byte {
		var held []byte
		for _, expression := range written {
			name, data := expressionParts(Nested(expression)[0].Value)
			if name == "bitwise" {
				data = PutAttrBE32(data, bitwiseOp, op)
			}
			held = append(held, Expression(name, data)...)
		}
		return held
	}
	if fault := ExpressionFault(written, dumped(bitwiseBool)); fault != "" {
		t.Errorf("a mask dumped with its boolean operation reads %s", fault)
	}
	// NFT_BITWISE_LSHIFT
	if fault := ExpressionFault(written, dumped(1)); fault == "" {
		t.Error("a mask dumped as a shift reads as written")
	}
}

// A chain whose first line differs in what its Then reads and whose second
// differs in its expressions is named by its first line, and an error the
// first line's Then meets comes before the second line's fault, as a chain is
// read line by line
func TestChainFaultNamesTheFirstLineThatDiffers(t *testing.T) {
	first := append(SourcePrefix(netip.MustParsePrefix("192.0.2.0/24")), CountedDrop()...)
	second := append(SourcePrefix(netip.MustParsePrefix("198.51.100.0/24")), CountedDrop()...)
	other := append(SourcePrefix(netip.MustParsePrefix("203.0.113.0/24")), CountedDrop()...)
	held := []Installed{
		{Chain: "c", Spec: "first", Expressions: slices.Concat(first...)},
		{Chain: "c", Spec: "second", Expressions: slices.Concat(other...)},
	}
	for _, then := range []struct {
		fault string
		err   error
	}{
		{"the first line's set differs", nil},
		{"", errors.New("the first line's set cannot be read")},
	} {
		want := []Line{
			{Spec: "first", Expressions: first, Then: func(Installed) (string, error) { return then.fault, then.err }},
			{Spec: "second", Expressions: second},
		}
		fault, err := ChainFault("c", want, held)
		if fault != then.fault || err != then.err {
			t.Errorf("the chain reads %q, %v, want the first line's %q, %v", fault, err, then.fault, then.err)
		}
	}
}
