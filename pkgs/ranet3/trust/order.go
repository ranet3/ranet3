// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

// Row is the first holding condition of the local trust order.
type Row string

const (
	C1  Row = "C1"
	D1  Row = "D1"
	D2  Row = "D2"
	D3  Row = "D3"
	D4  Row = "D4"
	D5  Row = "D5"
	D6  Row = "D6"
	D7  Row = "D7"
	D8  Row = "D8"
	D9  Row = "D9"
	D11 Row = "D11"
	D12 Row = "D12"
	D13 Row = "D13"
	D14 Row = "D14"
	D15 Row = "D15"
	D16 Row = "D16"
	D19 Row = "D19"
	D20 Row = "D20"
	D21 Row = "D21"
	D22 Row = "D22"
	D23 Row = "D23"
	D24 Row = "D24"
)

// OrderInput contains only checks completed before step 10. A nil Offered
// means that the configured file did not verify under an eligible signer.
type OrderInput struct {
	Start, ConfigRefused, StoreUnreadable, CapRefused bool
	Overlap, ConfigChecksRefused                      bool
	Held, Offered                                     *Verified
	HeldSignerEligible, HeldSignerCompromised         bool
	Floor, EntryHeight                                uint64
}

// Order returns the first holding row, before persistence or application.
func Order(in OrderInput) Row {
	switch {
	case in.ConfigRefused:
		return C1
	case in.StoreUnreadable && in.Start:
		return D14
	case in.CapRefused:
		return C1
	case in.Overlap:
		return D16
	case in.ConfigChecksRefused:
		return D19
	case in.Held == nil:
		if in.Offered != nil {
			return D2
		}
		return D1
	}
	s, f := in.Held, in.Offered
	if in.HeldSignerCompromised {
		bound := max(in.Floor, in.EntryHeight)
		if in.Floor != 0 && f != nil && f.Payload.Mesh == s.Payload.Mesh && f.Payload.Height >= bound {
			return D9
		}
		return D24
	}
	if f == nil {
		if in.HeldSignerEligible {
			return D13
		}
		return D11
	}
	if f.Payload.Mesh != s.Payload.Mesh {
		return D12
	}
	if in.HeldSignerEligible {
		switch {
		case f.Payload.Height == s.Payload.Height && f.Digest == s.Digest:
			return D3
		case f.Payload.Height < s.Payload.Height:
			return D4
		case f.Payload.Height == s.Payload.Height:
			return D5
		case f.Payload.Height == s.Payload.Height+1 && (f.Payload.Previous == nil || *f.Payload.Previous != s.Digest):
			return D6
		case f.Payload.Height == s.Payload.Height+1:
			return D7
		default:
			return D8
		}
	}
	switch {
	case f.Payload.Height == s.Payload.Height && f.Digest == s.Digest:
		return D20
	case f.Payload.Height < s.Payload.Height:
		return D22
	case f.Payload.Height == s.Payload.Height || f.Payload.Height == s.Payload.Height+1 && (f.Payload.Previous == nil || *f.Payload.Previous != s.Digest):
		return D23
	default:
		return D21
	}
}
