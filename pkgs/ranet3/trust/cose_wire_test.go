// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"runtime"
	"testing"
)

func wireExample(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	_, payload := payloadExample(t)
	header := append([]byte{0xa2, 0x01, 0x32, 0x03, 0x78, 0x21}, "application/vnd.ranet3.trust+cbor"...)
	file := append([]byte{0xd2, 0x84, 0x58, 0x27}, header...)
	file = append(file, 0xa0, 0x58, byte(len(payload)))
	file = append(file, payload...)
	file = append(file, 0x58, 0x40)
	file = append(file, bytes.Repeat([]byte{0x11}, 64)...)
	return file, header, payload
}

func TestCOSEWireAndBorrowedSlices(t *testing.T) {
	file, header, payload := wireExample(t)
	envelope, err := parseEnvelope(file)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Algorithm != -19 || !bytes.Equal(envelope.Protected, header) || !bytes.Equal(envelope.Payload, payload) || len(envelope.Signature) != 64 {
		t.Fatalf("wrong COSE envelope %+v", envelope)
	}
	if &envelope.Protected[0] != &file[4] || &envelope.Payload[0] != &file[bytes.Index(file, payload)] || &envelope.Signature[0] != &file[len(file)-64] {
		t.Fatal("outer layer copied an embedded byte string")
	}
	wantSigInput := append([]byte{0x84, 0x6a}, "Signature1"...)
	wantSigInput = append(wantSigInput, 0x58, 0x27)
	wantSigInput = append(wantSigInput, header...)
	wantSigInput = append(wantSigInput, 0x40, 0x58, byte(len(payload)))
	wantSigInput = append(wantSigInput, payload...)
	if got := signatureStructure(header, payload); !bytes.Equal(got, wantSigInput) {
		t.Fatalf("signature structure %x, want %x", got, wantSigInput)
	}
}

func TestCOSEPreverificationAllocationGrowth(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	_, wrongKey := signTestFile(t, []byte{0xa0}, other, algorithmEd25519)
	var allocated [2]uint64
	for i, size := range [...]int{8 << 20, 16 << 20} {
		file, _ := signTestFile(t, bytes.Repeat([]byte{0xa0}, size), private, algorithmEd25519)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := AuthenticateSignedFile(file, []AuthorityKey{wrongKey})
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(file)
		if err == nil || err.Error() != "trust: no authority key verifies the signature" {
			t.Fatalf("accepted wrong key before decoding %d-byte payload: %v", size, err)
		}
		allocated[i] = after.TotalAlloc - before.TotalAlloc
	}
	if allocated[1] < allocated[0] {
		t.Fatalf("larger payload allocated less: small %d large %d", allocated[0], allocated[1])
	}
	delta := allocated[1] - allocated[0]
	if delta > (8<<20)+(1<<20) {
		t.Fatalf("preverification allocation growth %d bytes for 8 MiB more payload, small %d large %d", delta, allocated[0], allocated[1])
	}
	t.Logf("preverification allocated small=%d large=%d bytes", allocated[0], allocated[1])
}

func TestCOSEWireRefusals(t *testing.T) {
	file, _, _ := wireExample(t)
	for _, test := range []struct {
		name string
		bad  []byte
	}{
		{"tag 55799 before tag 18", append([]byte{0xd9, 0xd9, 0xf7}, file...)},
		{"no tag", file[1:]},
		{"wrong tag", append([]byte{0xd0}, file[1:]...)},
		{"wrong array length", append([]byte{0xd2, 0x83}, file[2:]...)},
		{"nonminimal protected length", append([]byte{0xd2, 0x84, 0x59, 0x00, 0x27}, file[4:]...)},
		{"trailing bytes", append(bytes.Clone(file), 0x00)},
		{"short signature", file[:len(file)-1]},
		{"indefinite signature", append(bytes.Clone(file[:len(file)-66]), append([]byte{0x5f}, file[len(file)-64:]...)...)},
		{"null signature", append(bytes.Clone(file[:len(file)-66]), 0xf6)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseEnvelope(test.bad); err == nil {
				t.Fatalf("accepted malformed COSE %x", test.bad)
			}
		})
	}
	bad := bytes.Clone(file)
	bad[6] = 0x27
	if _, err := parseEnvelope(bad); err == nil {
		t.Fatal("accepted deprecated EdDSA algorithm")
	}
	bad = bytes.Clone(file)
	bad[bytes.Index(file, []byte{0xa0, 0x58, 0x19})] = 0xa1
	if _, err := parseEnvelope(bad); err == nil {
		t.Fatal("accepted nonempty unprotected header")
	}
	bad = bytes.Clone(file[:len(file)-1])
	bad[len(bad)-64] = 0x3f
	if _, err := parseEnvelope(bad); err == nil {
		t.Fatal("accepted 63-byte signature")
	}
}

func TestSignedFileRejectsNullOuterValue(t *testing.T) {
	for _, test := range []struct {
		name string
		file []byte
	}{
		{"null", []byte{0xf6}},
		{"tagged null", []byte{0xd2, 0xf6}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseEnvelope(test.file); err == nil || err.Error() != "trust: signed file is not tagged COSE_Sign1" {
				t.Fatalf("parsed null outer value %x: %v", test.file, err)
			}
			if _, err := AuthenticateSignedFile(test.file, nil); err == nil || err.Error() != "trust: signed file is not tagged COSE_Sign1" {
				t.Fatalf("authenticated null outer value %x: %v", test.file, err)
			}
		})
	}
}
