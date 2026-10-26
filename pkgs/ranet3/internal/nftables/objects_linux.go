// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// Timeout is a ct timeout object, the timeout a connection of one transport
// protocol takes in each of its states once a rule naming the object attaches
// it
type Timeout struct {
	Table   string
	Name    string
	L3Proto uint16
	L4Proto uint8
	// Policy is each state's timeout in seconds, Policy[i] that of the state
	// whose CTA_TIMEOUT_ attribute of L4Proto is i+1
	Policy []uint32
}

// Create makes the object, or leaves one of its name as it is, since nf_tables
// has no update for a ct timeout
func (t Timeout) Create(proto uint8) Request {
	var states []byte
	for i, seconds := range t.Policy {
		states = PutAttrBE32(states, uint16(i+1), seconds)
	}
	data := PutAttr(nil, ctTimeoutL3Proto, binary.BigEndian.AppendUint16(nil, t.L3Proto))
	data = PutAttr(data, ctTimeoutL4Proto, []byte{t.L4Proto})
	data = PutAttr(data, ctTimeoutData|unix.NLA_F_NESTED, states)
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_OBJ_TABLE, t.Table)
	body = PutAttrString(body, unix.NFTA_OBJ_NAME, t.Name)
	body = PutAttrBE32(body, unix.NFTA_OBJ_TYPE, unix.NFT_OBJECT_CT_TIMEOUT)
	body = PutAttr(body, unix.NFTA_OBJ_DATA|unix.NLA_F_NESTED, data)
	return Request{Kind: Command(unix.NFT_MSG_NEWOBJ), Flags: unix.NLM_F_CREATE, Body: body}
}

// DecodeTimeout reads a ct timeout object out of a dump, ok false for an
// object of another type. A state the dump leaves out reads as 0.
func DecodeTimeout(message Message) (t Timeout, ok bool) {
	for kind, value := range message.Attributes() {
		switch {
		case kind == unix.NFTA_OBJ_TABLE:
			t.Table = unix.ByteSliceToString(value)
		case kind == unix.NFTA_OBJ_NAME:
			t.Name = unix.ByteSliceToString(value)
		case kind == unix.NFTA_OBJ_TYPE && len(value) == 4:
			ok = binary.BigEndian.Uint32(value) == unix.NFT_OBJECT_CT_TIMEOUT
		case kind == unix.NFTA_OBJ_DATA:
			for _, field := range Nested(value) {
				switch {
				case field.Kind == ctTimeoutL3Proto && len(field.Value) == 2:
					t.L3Proto = binary.BigEndian.Uint16(field.Value)
				case field.Kind == ctTimeoutL4Proto && len(field.Value) == 1:
					t.L4Proto = field.Value[0]
				case field.Kind == ctTimeoutData:
					for _, state := range Nested(field.Value) {
						if state.Kind == 0 || len(state.Value) != 4 {
							continue
						}
						for len(t.Policy) < int(state.Kind) {
							t.Policy = append(t.Policy, 0)
						}
						t.Policy[state.Kind-1] = binary.BigEndian.Uint32(state.Value)
					}
				}
			}
		}
	}
	return t, ok
}

// Fault names how the object a dump holds differs from t as Create writes it,
// empty for t as written and for any other object. Any difference remakes the
// table, since nf_tables has no update for a ct timeout.
func (t Timeout) Fault(message Message) (fault string, remake bool) {
	held, ok := DecodeTimeout(message)
	if !ok || held.Table != t.Table || held.Name != t.Name {
		return "", false
	}
	if held.L3Proto == t.L3Proto && held.L4Proto == t.L4Proto && slices.Equal(held.Policy, t.Policy) {
		return "", false
	}
	return fmt.Sprintf("its ct timeout %s reads back as protocol %d in family %d with %v seconds, where protocol %d in family %d with %v seconds were written",
		t.Name, held.L4Proto, held.L3Proto, held.Policy, t.L4Proto, t.L3Proto, t.Policy), true
}

// readTimeout is t's fault among the objects a dump holds, one missing among
// them
func readTimeout(t Timeout, objects []Message) (fault string, remake bool) {
	for _, reply := range objects {
		if held, ok := DecodeTimeout(reply); ok && held.Table == t.Table && held.Name == t.Name {
			return t.Fault(reply)
		}
	}
	return fmt.Sprintf("its ct timeout %s is missing", t.Name), false
}
