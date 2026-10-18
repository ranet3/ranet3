// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"fmt"
)

// intAuthChunk is IntAuth_[i/r]*A followed by IntAuth_[i/r]*P of one IKE_INTERMEDIATE message
// raw is the message as it went on the wire without the non-ESP marker, skOffset the offset of its Encrypted payload's generic header, and inner its inner payloads in plaintext
// so both ends take the same octets, the critical bit and RESERVED of the Encrypted payload header among them
// RFC 9242 section 3.3.2: "The IntAuth_[i/r]*A chunk consists of the sequence of octets from the first octet of the IKE Header (not including the prepended four octets of zeros, if UDP encapsulation or TCP encapsulation of ESP packets is used) to the last octet of the generic header of the Encrypted payload."
// RFC 9242 section 3.3.2: "In other words, the IntAuth_[i/r]*P chunk is the inner payloads of the Encrypted payload in plaintext form, which is stressed by using the "P" suffix in its name."
// RFC 9242 section 3.3.2: "In other words, the Length field in the IKE Header (denoted as Adjusted Length in Figure 1) is set to the sum of the lengths of IntAuth_[i/r]*A and IntAuth_[i/r]*P, and the Payload Length field in the Encrypted payload header (denoted as Adjusted Payload Length in Figure 1) is set to the length of IntAuth_[i/r]*P plus the size of the Encrypted payload header (four octets)."
func intAuthChunk(raw []byte, skOffset int, inner []byte) ([]byte, error) {
	if skOffset < HeaderLen || len(raw) < skOffset+genericPayloadHeaderLen {
		return nil, fmt.Errorf("ike: IKE_INTERMEDIATE message of %d octets has no Encrypted payload header at %d", len(raw), skOffset)
	}
	a := raw[:skOffset+genericPayloadHeaderLen]
	chunk := make([]byte, 0, len(a)+len(inner))
	chunk = append(chunk, a...)
	chunk = append(chunk, inner...)
	binary.BigEndian.PutUint32(chunk[24:28], uint32(len(a)+len(inner)))
	binary.BigEndian.PutUint16(chunk[skOffset+2:skOffset+4], uint16(genericPayloadHeaderLen+len(inner)))
	return chunk, nil
}

// intAuth is IntAuth_iN and IntAuth_rN so far, both nil before the first IKE_INTERMEDIATE exchange
type intAuth struct {
	i, r []byte
}

// add takes one IKE_INTERMEDIATE exchange, its request and response as intAuthChunk gives them, under the SK_pi and SK_pr that protected it
// RFC 9242 section 3.3.2: "IntAuth_iN = prf(SK_piN, IntAuth_iN-1 | IntAuth_iNA [| IntAuth_iNP])" and "IntAuth_rN = prf(SK_prN, IntAuth_rN-1 | IntAuth_rNA [| IntAuth_rNP])"
// RFC 9242 section 3.3.2: "Note that if keys are updated, then for any given IKE_INTERMEDIATE exchange, the keys SK_e[i/r] and SK_a[i/r] used for protection of its messages (see Section 3.3.1) and the key SK_p[i/r] for its authentication are always from the same generation."
func (a intAuth) add(prfID uint16, skpi, skpr, request, response []byte) intAuth {
	return intAuth{
		i: prf(prfID, skpi, concat(a.i, request)),
		r: prf(prfID, skpr, concat(a.r, response)),
	}
}

// octets is IntAuth, which each end appends to the octets its AUTH covers, and nothing where no IKE_INTERMEDIATE exchange ran
// RFC 9242 section 3.3.2: "If one or more IKE_INTERMEDIATE exchanges took place, the definition of the blob to be signed (or MACed) from Section 2.15 of [RFC7296] is modified as follows:"
// RFC 9242 section 3.3.2: "IntAuth =  IntAuth_iN | IntAuth_rN | IKE_AUTH_MID"
// RFC 9242 section 3.3.2: "It is represented as a four-octet integer in network byte order (in other words, exactly as it appears on the wire)."
func (a intAuth) octets(authMID uint32) []byte {
	if a.i == nil {
		return nil
	}
	return binary.BigEndian.AppendUint32(concat(a.i, a.r), authMID)
}
