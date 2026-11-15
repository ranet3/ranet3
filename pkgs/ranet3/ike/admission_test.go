// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"ranet3.com/pkgs/ranet3/transport"
)

const largestPayloadCount = (65536 - 4 - HeaderLen) / genericPayloadHeaderLen

func TestUnclaimedHeaderPrecedesPayloadDecode(t *testing.T) {
	if runAllocationChild(t) {
		return
	}
	hub := listenHub(t)
	endpoint := observedEndpoint(t, hub, 1)
	r := &Responder{}
	r.cfg.Hub = hub
	payloads := make([]RawPayload, largestPayloadCount)
	for i := range payloads {
		payloads[i].Type = PayloadV
	}
	for name, change := range map[string]func(*Header){
		"exchange":      func(h *Header) { h.ExchangeType = INFORMATIONAL },
		"flags":         func(h *Header) { h.Flags = 0 },
		"message ID":    func(h *Header) { h.MessageID = 1 },
		"initiator SPI": func(h *Header) { h.SPIInitiator = 0 },
		"responder SPI": func(h *Header) { h.SPIResponder = 1 },
		"version":       func(h *Header) { h.MajorVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			h := Header{SPIInitiator: 1, MajorVersion: 2, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}
			change(&h)
			raw := (&Message{Header: h, Payloads: payloads}).Encode()
			raw[17] = h.MajorVersion << 4
			refuse := func() {
				if _, _, err := r.handshake(context.Background(), transport.Unclaimed{Raw: raw, Endpoint: endpoint}); err == nil {
					t.Fatal("an invalid header was admitted")
				}
			}
			refuse()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range 8 {
				refuse()
			}
			runtime.ReadMemStats(&after)
			// context and error bookkeeping fit, a decoded chain of this size does not
			const headerBudget = 4 << 10
			if got := (after.TotalAlloc - before.TotalAlloc) / 8; got > headerBudget {
				t.Errorf("a refused header allocated %d octets, past %d without a payload walk", got, headerBudget)
			}
		})
	}
}

func TestUnclaimedLengthMismatchKeepsDecodeDiagnostic(t *testing.T) {
	r := &Responder{}
	for _, messageID := range []uint32{0, 1} {
		for _, length := range []uint32{HeaderLen - 1, HeaderLen + 1} {
			raw := (&Header{SPIInitiator: 1, MajorVersion: 2, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: messageID, Length: length}).encode()
			_, want := DecodeMessage(raw)
			_, _, got := r.handshake(context.Background(), transport.Unclaimed{Raw: raw})
			if want == nil || got == nil || !strings.Contains(got.Error(), want.Error()) {
				t.Errorf("message ID %d, length %d returned %v, want the decode diagnostic %v", messageID, length, got, want)
			}
		}
	}
}

// runAllocationChild isolates process-global counts and returns true in the parent after its child passes
func runAllocationChild(t *testing.T) bool {
	t.Helper()
	const allocationChild = "RANET3_IKE_ALLOCATION_CHILD"
	if os.Getenv(allocationChild) == t.Name() {
		return false
	}
	run := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=1m", "-test.v")
	run.Env = append(os.Environ(), allocationChild+"="+t.Name())
	out, err := run.CombinedOutput()
	text := "\n" + string(out)
	if err != nil || !strings.Contains(text, "\n=== RUN   "+t.Name()+"\n") || !strings.Contains(text, "\n--- PASS: "+t.Name()+" (") {
		t.Fatalf("allocation child must run and pass %s: %v\n%s", t.Name(), err, out)
	}
	t.Logf("%s", out)
	return true
}

func TestPayloadDescriptorsStayWithinWireBound(t *testing.T) {
	if runAllocationChild(t) {
		return
	}
	if unsafe.Sizeof(uintptr(0)) == 8 && largestPayloadCount*int(unsafe.Sizeof(RawPayload{})) != 524032 {
		t.Fatal("the descriptor bound differs from design/limits.md")
	}
	for _, count := range []int{0, 1, 2, 32, largestPayloadCount} {
		payloads := make([]RawPayload, count)
		for i := range payloads {
			payloads[i].Type = PayloadNonce
		}
		raw := (&Message{Payloads: payloads}).Encode()
		allocations := testing.AllocsPerRun(1, func() {
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Payloads) != count || cap(m.Payloads) != count {
				t.Fatalf("%d payloads retain %d descriptors in capacity %d", count, len(m.Payloads), cap(m.Payloads))
			}
		})
		if allocations > 3 {
			t.Errorf("%d payloads cost %g allocations, want at most 3", count, allocations)
		}
		walkAllocations := testing.AllocsPerRun(1, func() {
			if _, _, err := walkPayloads(PayloadType(raw[16]), raw[HeaderLen:], true); err != nil {
				t.Fatal(err)
			}
		})
		if walkAllocations > 1 {
			t.Errorf("%d payloads cost %g walk allocations, want at most 1", count, walkAllocations)
		}
	}
}
