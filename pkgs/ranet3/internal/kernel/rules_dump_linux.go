// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// DumpRules reads every policy rule of both families through a socket of its
// own, so a reader off the reconcile loop never shares the loop's
func DumpRules() ([]DumpedRule, error) {
	conn, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	body := make([]byte, sizeofFibRuleHdr)
	body[0] = unix.AF_UNSPEC
	replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, body)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump rules: %w", err)
	}
	out := make([]DumpedRule, 0, len(replies))
	for _, reply := range replies {
		if rule, ok := decodeDumpedRule(reply); ok {
			out = append(out, rule)
		}
	}
	return out, nil
}

// decodeDumpedRule reads one rule of either family, whatever its owner and
// action, and reports false for a message too short to be one
func decodeDumpedRule(message nlMessage) (DumpedRule, bool) {
	if len(message.Data) < sizeofFibRuleHdr {
		return DumpedRule{}, false
	}
	var rule DumpedRule
	switch message.Data[0] {
	case unix.AF_INET:
		rule.Family = FamilyIPv4
	case unix.AF_INET6:
		rule.Family = FamilyIPv6
	default:
		return DumpedRule{}, false
	}
	dstLen, srcLen := int(message.Data[1]), int(message.Data[2])
	// the one byte table field, which FRA_TABLE overrides for a table past 255
	rule.Table = uint32(message.Data[4])
	rule.Action = actionName(message.Data[7])
	rule.Invert = binary.NativeEndian.Uint32(message.Data[8:])&unix.FIB_RULE_INVERT != 0
	for kind, value := range message.attributes(sizeofFibRuleHdr) {
		switch kind {
		case unix.FRA_PRIORITY, unix.FRA_TABLE, unix.FRA_FWMARK, unix.FRA_FWMASK:
			if len(value) != 4 {
				continue
			}
			number := binary.NativeEndian.Uint32(value)
			switch kind {
			case unix.FRA_PRIORITY:
				rule.Priority = number
			case unix.FRA_TABLE:
				rule.Table = number
			case unix.FRA_FWMARK:
				rule.FWMark = number
			case unix.FRA_FWMASK:
				rule.FWMask = number
			}
		case unix.FRA_DST:
			if address, ok := addressFromBytes(value); ok {
				rule.To = netip.PrefixFrom(address, dstLen)
			}
		case unix.FRA_SRC:
			if address, ok := addressFromBytes(value); ok {
				rule.From = netip.PrefixFrom(address, srcLen)
			}
		case unix.FRA_IIFNAME:
			rule.IIF = unix.ByteSliceToString(value)
		case unix.FRA_OIFNAME:
			rule.OIF = unix.ByteSliceToString(value)
		case unix.FRA_L3MDEV:
			rule.L3mdev = len(value) == 1 && value[0] != 0
		case unix.FRA_PROTOCOL:
			if len(value) == 1 {
				rule.Protocol = value[0]
			}
		}
	}
	return rule, true
}

// actionName is the action as `ip rule` spells it
func actionName(action uint8) string {
	switch action {
	case unix.FR_ACT_TO_TBL:
		return "lookup"
	case unix.FR_ACT_GOTO:
		return "goto"
	case unix.FR_ACT_NOP:
		return "nop"
	case unix.FR_ACT_BLACKHOLE:
		return "blackhole"
	case unix.FR_ACT_UNREACHABLE:
		return "unreachable"
	case unix.FR_ACT_PROHIBIT:
		return "prohibit"
	}
	return fmt.Sprintf("action %d", action)
}
