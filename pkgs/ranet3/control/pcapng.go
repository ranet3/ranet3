// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unicode/utf8"
)

// TracePcap writes trace records as one pcapng section, draft-ietf-opsawg-pcapng-06
// a section of one interface of link type raw IP, each record an enhanced packet block of its payload whose comment holds the rest of its line
type TracePcap struct {
	w io.Writer
}

// NewTracePcap writes the section header and the interface to w, a pcapng file holding no packet yet
func NewTracePcap(w io.Writer) (*TracePcap, error) {
	var shb []byte
	shb = binary.LittleEndian.AppendUint32(shb, 0x1A2B3C4D)
	shb = binary.LittleEndian.AppendUint16(shb, 1)
	shb = binary.LittleEndian.AppendUint16(shb, 0)
	// a section length of -1 is one left unspecified, section 4.1
	shb = binary.LittleEndian.AppendUint64(shb, math.MaxUint64)
	// link type 101 is LINKTYPE_RAW, a packet beginning with its IPv4 or IPv6 header, draft-ietf-opsawg-pcaplinktype-18
	var idb []byte
	idb = binary.LittleEndian.AppendUint16(idb, 101)
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	idb = binary.LittleEndian.AppendUint32(idb, TracePayloadMax)
	// if_tsresol 9 counts the timestamp in nanoseconds, section 4.2
	idb = pcapngOption(idb, 9, []byte{9})
	idb = pcapngOption(idb, 0, nil)
	header := pcapngBlock(pcapngBlock(nil, 0x0A0D0D0A, shb), 1, idb)
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return &TracePcap{w: w}, nil
}

// Write writes p as one enhanced packet block in one write, refusing a record the block cannot hold as it is
func (t *TracePcap) Write(p TracePacket) error {
	comment := traceComment(p)
	switch {
	case len(p.Payload) > TracePayloadMax:
		return fmt.Errorf("a trace record of %d bytes of payload passes the capture's %d", len(p.Payload), TracePayloadMax)
	case p.Length < len(p.Payload) || int64(p.Length) > math.MaxUint32:
		return fmt.Errorf("a trace record of length %d cannot carry %d bytes of payload", p.Length, len(p.Payload))
	case p.Time.Before(time.Unix(0, 0)):
		return fmt.Errorf("a trace record of %v lies before the epoch", p.Time)
	case len(comment) > math.MaxUint16 || !utf8.ValidString(comment):
		return errors.New("a trace record's fields make no comment of valid UTF-8 within 65535 bytes")
	}
	nanoseconds := uint64(p.Time.UnixNano())
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(nanoseconds>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(nanoseconds))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(p.Payload)))
	body = binary.LittleEndian.AppendUint32(body, uint32(p.Length))
	body = pcapngPadded(append(body, p.Payload...))
	body = pcapngOption(body, 1, []byte(comment))
	body = pcapngOption(body, 0, nil)
	_, err := t.w.Write(pcapngBlock(nil, 6, body))
	return err
}

// pcapngBlock appends a block of type kind around body, whose length is a multiple of 4, section 3.1
func pcapngBlock(out []byte, kind uint32, body []byte) []byte {
	length := uint32(12 + len(body))
	out = binary.LittleEndian.AppendUint32(out, kind)
	out = binary.LittleEndian.AppendUint32(out, length)
	out = append(out, body...)
	return binary.LittleEndian.AppendUint32(out, length)
}

// pcapngOption appends the option code holding value, its length the value's without the padding, section 3.5
func pcapngOption(out []byte, code uint16, value []byte) []byte {
	out = binary.LittleEndian.AppendUint16(out, code)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(value)))
	return pcapngPadded(append(out, value...))
}

// pcapngPadded is out with the padding of section 3.6.2
func pcapngPadded(out []byte) []byte {
	return append(out, make([]byte, -len(out)&3)...)
}
