// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"testing"

	"ranet3.com/pkgs/ranet3/esp"
)

// a packet decrypted in place reaches the tun in its own datagram, the ESP header and IV in front of it the headroom a tun write takes
// so TUNHeadroom is the whole of what every suite puts in front of the plaintext, under every key length a Child SA may name it with
// and a frame of one byte more reaches in front of the datagram and is refused
func TestHeadroomIsTheFramingOfEverySuite(t *testing.T) {
	for _, suite := range []struct {
		name     string
		id, bits uint16
		key      int
	}{
		{"AES-GCM-128", esp.ENCRAESGCM16, 128, 16 + 4},
		{"AES-GCM-192", esp.ENCRAESGCM16, 192, 24 + 4},
		{"AES-GCM-256", esp.ENCRAESGCM16, 256, 32 + 4},
		{"ChaCha20-Poly1305", esp.ENCRChaCha20Poly1305, 256, 32 + 4},
	} {
		t.Run(suite.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0xa5}, suite.key)
			child := esp.ChildSA{EncrID: suite.id, EncrKeyBits: suite.bits, LocalSPI: 1, RemoteSPI: 1, InboundKey: key, OutboundKey: key}
			out, err := esp.NewOutbound(child)
			if err != nil {
				t.Fatal(err)
			}
			in, err := esp.NewInbound(child)
			if err != nil {
				t.Fatal(err)
			}
			packet := ipv6TCPPacket(40000, 5201, 1)
			for _, headroom := range []int{TUNHeadroom, TUNHeadroom + 1} {
				datagram, err := out.Seal(packet, esp.NextHeaderIPv6)
				if err != nil {
					t.Fatal(err)
				}
				results := in.AuthenticateBatchInPlace([][]byte{datagram}, nil)
				esp.CommitBatch(results)
				frame, _, err := results[0].Frame(headroom)
				switch {
				case headroom > TUNHeadroom && err == nil:
					t.Errorf("a frame with %d bytes of headroom was taken, past the datagram's own start", headroom)
				case headroom == TUNHeadroom && err != nil:
					t.Errorf("a frame with %d bytes of headroom was refused: %v", headroom, err)
				case headroom == TUNHeadroom && (&frame[0] != &datagram[0] || !bytes.Equal(frame[TUNHeadroom:], packet)):
					t.Errorf("the frame with %d bytes of headroom does not start where its datagram does with the packet behind them", headroom)
				}
			}
		})
	}
}
