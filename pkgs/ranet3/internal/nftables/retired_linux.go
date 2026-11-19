// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// Retired is an object Table holds under a name an earlier version of its
// owner wrote there and the owner no longer writes: its Kind, chain, set or ct
// timeout, its Name, and HeldBy, what keeps nf_tables from deleting it once
// the owner's chains are flushed: "chain c" for a rule of chain c, "map m" for
// an element of the named map m, "a map" for an element of a map of objects,
// empty where nothing does
type Retired struct {
	Kind, Name, HeldBy string
}

// Leftovers is each object of old, an owner's retired names, that Table
// holds, its chains, then its sets, then its ct timeouts, each in old's order,
// with what holds it once a transaction has flushed every chain of owner's
// scope and of old. tables is the map Tables gave for Table earlier in its
// owner's pass, nil where the owner did not read them. Leftovers dumps the
// tables where tables is nil, nothing more where NFPROTO_INET holds no Table,
// and otherwise one dump of each kind old names, and the table's rules and
// verdict maps and chains where it finds any object. Those flushed are of the
// chains TableChains lists, with each binding chain a rule of one binds, and
// it leaves out a binding chain or an anonymous set nothing past them holds,
// which nf_tables takes out with the rule that binds it.
func Leftovers(conn *Conn, tables map[uint8]uint32, old, owner Scope) ([]Retired, error) {
	var err error
	if tables == nil {
		if tables, err = Tables(conn, Table); err != nil {
			return nil, err
		}
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil, nil
	}
	var out []Retired
	// bound is each of out that nf_tables binds to one rule, by its kind and name
	bound := map[Retired]bool{}
	if len(old.Chains) > 0 {
		chains, err := conn.Dump(Command(unix.NFT_MSG_GETCHAIN), PutNfgenmsg(nil, unix.NFPROTO_INET))
		if err != nil {
			return nil, fmt.Errorf("nftables: dump chains: %w", err)
		}
		for _, name := range old.Chains {
			if i := slices.IndexFunc(chains, func(reply netlink.Message) bool {
				table, chain, _, _, _ := DecodeChain(reply)
				return table == Table && chain == name
			}); i >= 0 {
				out = append(out, Retired{Kind: "chain", Name: name})
				bound[out[len(out)-1]] = binding(chains[i])
			}
		}
	}
	if len(old.Sets) > 0 {
		sets, err := conn.Dump(Command(unix.NFT_MSG_GETSET), netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_TABLE, Table))
		if err != nil {
			return nil, fmt.Errorf("nftables: dump sets: %w", err)
		}
		for _, name := range old.Sets {
			if i := slices.IndexFunc(sets, func(reply netlink.Message) bool {
				set := DecodeSet(reply)
				return set.Table == Table && set.Name == name
			}); i >= 0 {
				out = append(out, Retired{Kind: "set", Name: name})
				bound[out[len(out)-1]] = DecodeSet(sets[i]).Flags&unix.NFT_SET_ANONYMOUS != 0
			}
		}
	}
	uses := map[string]uint32{}
	if len(old.Timeouts) > 0 {
		objects, err := conn.Dump(Command(unix.NFT_MSG_GETOBJ), netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_OBJ_TABLE, Table))
		if err != nil {
			return nil, fmt.Errorf("nftables: dump objects: %w", err)
		}
		for _, name := range old.Timeouts {
			for _, reply := range objects {
				if held, ok := DecodeTimeout(reply); ok && held.Table == Table && held.Name == name {
					out = append(out, Retired{Kind: "ct timeout", Name: name})
					uses[name] = objectUse(reply)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	// a transaction that deletes the leftovers flushes these chains first, whose rules hold nothing
	if out, err = hold(conn, unix.NFPROTO_INET, Table, out, uses, func(chain string) bool { return owner.chain(chain) || old.chain(chain) }); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(out, func(r Retired) bool { return r.HeldBy == "" && bound[Retired{Kind: r.Kind, Name: r.Name}] }), nil
}

// hold is out, objects of table in the nf_tables family proto, each with what
// holds it once a transaction has flushed each chain TableChains lists that
// flushes names, uses being each ct timeout's NFTA_OBJ_USE by its name
func hold(conn *Conn, proto uint8, table string, out []Retired, uses map[string]uint32, flushes func(chain string) bool) ([]Retired, error) {
	rules, err := TableRules(conn, proto, table)
	if err != nil {
		return nil, err
	}
	maps, err := VerdictMaps(conn, proto, table)
	if err != nil {
		return nil, err
	}
	listed, err := TableChains(conn, proto, table)
	if err != nil {
		return nil, err
	}
	emptied := func(chain string) bool { return flushedWith(chain, listed, rules, flushes) }
	// user is the chain of the first rule naming the object that no flush empties, or the binder of its binding chain, and the count of the emptied chains' rules naming it
	user := func(names func(expressions []byte) bool) (string, uint32) {
		var count uint32
		for _, rule := range rules {
			switch {
			case !names(rule.Expressions):
			case !emptied(rule.Chain):
				return "chain " + binder(rule.Chain, listed, rules), count
			default:
				count++
			}
		}
		return "", count
	}
	for i, r := range out {
		switch r.Kind {
		case "chain":
			out[i].HeldBy = Holder(r.Name, rules, maps, listed, flushes)
		case "set":
			out[i].HeldBy, _ = user(func(expressions []byte) bool { return usesSet(expressions, r.Name) })
		default:
			heldBy, attached := user(func(expressions []byte) bool { return attaches(expressions, r.Name) })
			if heldBy == "" && uses[r.Name] > attached {
				heldBy = "a map"
			}
			out[i].HeldBy = heldBy
		}
	}
	return out, nil
}

// objectUse is NFTA_OBJ_USE of a dumped object, the count of the rules and map
// elements that attach it
func objectUse(reply netlink.Message) uint32 {
	for kind, value := range reply.Attributes(SizeofNfgenmsg) {
		if kind == unix.NFTA_OBJ_USE && len(value) == 4 {
			return binary.BigEndian.Uint32(value)
		}
	}
	return 0
}

// usesSet is whether a dumped rule's expressions name the set: a lookup's,
// a dynset's or an objref map's, the expressions that bind a set
func usesSet(held []byte, set string) bool {
	attrs := map[string]uint16{"lookup": unix.NFTA_LOOKUP_SET, "dynset": unix.NFTA_DYNSET_SET_NAME, "objref": unix.NFTA_OBJREF_SET_NAME}
	for _, element := range Nested(held) {
		name, data := expressionParts(element.Value)
		attr, binds := attrs[name]
		if !binds {
			continue
		}
		for _, field := range Nested(data) {
			if field.Kind == attr && unix.ByteSliceToString(field.Value) == set {
				return true
			}
		}
	}
	return false
}

// attaches is whether a dumped rule's expressions attach the ct timeout object
// by its name
func attaches(held []byte, object string) bool {
	for _, element := range Nested(held) {
		if name, data := expressionParts(element.Value); name == "objref" {
			var timeout, named bool
			for _, field := range Nested(data) {
				switch field.Kind {
				case unix.NFTA_OBJREF_IMM_TYPE:
					timeout = len(field.Value) == 4 && binary.BigEndian.Uint32(field.Value) == unix.NFT_OBJECT_CT_TIMEOUT
				case unix.NFTA_OBJREF_IMM_NAME:
					named = unix.ByteSliceToString(field.Value) == object
				}
			}
			if timeout && named {
				return true
			}
		}
	}
	return false
}

// Retire is the requests that delete each of leftovers nothing holds, in the
// order Leftovers gives them, sent in a transaction that flushed every chain of
// their owner's and each chain of leftovers TableChains lists ahead of them,
// as Rewrite flushes its strays: a goto in one keeps another it names from
// being deleted, and a rule in one keeps a set or object it reads
func Retire(leftovers []Retired) []Request {
	var requests []Request
	for _, r := range leftovers {
		switch {
		case r.HeldBy != "":
		case r.Kind == "chain":
			requests = append(requests, Chain{Table: Table, Name: r.Name}.Delete(unix.NFPROTO_INET))
		case r.Kind == "set":
			requests = append(requests, Set{Table: Table, Name: r.Name}.Delete(unix.NFPROTO_INET))
		default:
			requests = append(requests, Timeout{Table: Table, Name: r.Name}.Delete(unix.NFPROTO_INET))
		}
	}
	return requests
}

// Fault names r in its owner's readback, owner naming the owner as the
// readback does
func (r Retired) Fault(owner string) string {
	return r.stays(fmt.Sprintf("its %s %s is not one %s writes", r.Kind, r.Name, owner))
}

// stays is fault, which names r, with what holds r where anything does
func (r Retired) stays(fault string) string {
	using := "using it"
	if r.Kind == "chain" {
		using = "going to it"
	}
	switch {
	case r.HeldBy == "a map":
		return fmt.Sprintf("%s, and a map holds an element %s, so it stays until that element goes", fault, using)
	case strings.HasPrefix(r.HeldBy, "map "):
		return fmt.Sprintf("%s, and %s holds an element %s, so it stays until that element goes", fault, r.HeldBy, using)
	case r.HeldBy != "":
		return fmt.Sprintf("%s, and %s holds a rule %s, so it stays until that rule goes", fault, r.HeldBy, using)
	}
	return fault
}
