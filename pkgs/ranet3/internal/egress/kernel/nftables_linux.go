// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// natTables is the linux backend: the translator's chains, sets and timeout
// objects in nftables.Table for each address family in use, and the limit its
// sets count each source's flows against.
type natTables struct {
	conn     *nftables.Conn
	monitor  *nftables.Monitor
	families []uint8
	limit    int
}

// New validates the capability and opens the backend's socket and monitor, so a
// deployment that cannot have it fails at startup rather than on the first
// packet. It installs nothing. Run does that.
func New(cfg egress.Egress, rt Runtime) (*Translator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Serves(rt.Steered); err != nil {
		return nil, err
	}
	if rt.Interface == "" {
		return nil, errors.New("egress: the mesh interface is required")
	}
	if rt.Forwarding == nil {
		return nil, errors.New("egress: a forwarding reader is required")
	}
	// Resolved before the backend is opened, so a return direction with no
	// mesh address to translate to is refused with nothing to clean up.
	if err := cfg.CheckReturn(rt.MeshAddresses); err != nil {
		return nil, err
	}
	if rt.Lookup == nil || rt.Sysctl == nil {
		return nil, errors.New("egress: a route lookup and a sysctl reader are required")
	}
	if rt.Write == nil {
		return nil, errors.New("egress: the mesh's tun writer is required")
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		return nil, err
	}
	return newTranslator(cfg, rt, be), nil
}

func newBackend(cfg egress.Egress, rt Runtime) (backend, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	be := &natTables{conn: conn, families: cfg.Translated(rt.Steered), limit: cfg.SourceLimit()}
	if be.monitor, err = nftables.OpenMonitor(conn, translatorScope); err != nil {
		conn.Close()
		return nil, err
	}
	return be, nil
}

func (n *natTables) Close() error { return errors.Join(n.monitor.Close(), n.conn.Close()) }

func (n *natTables) Changed() <-chan struct{} { return n.monitor.Changed() }

func (n *natTables) Missed() <-chan struct{} { return n.monitor.Missed() }

// translatorScope is the translator's chains, those of the classes of none
// among them, the retired chain, and the sets and timeout objects of both
// families, whatever the configuration translates, so a withdrawal takes what
// an instance under another configuration left
var translatorScope = func() nftables.Scope {
	scope := translatorContents([]uint8{egress.FamilyIPv4, egress.FamilyIPv6}, 0, nil).Scope()
	scope.Chains = append(scope.Chains, retiredChain)
	scope.Prefix = NoneChain
	return scope
}()

func (n *natTables) where() string {
	return fmt.Sprintf("nftables table inet %s chains %s, %s and %s and a %s chain for each class of none", nftables.Table, LimitChain,
		familyChain(egress.FamilyIPv6), ChainName, NoneChain)
}

// nftFamily is the NFPROTO_ value for one of this package's families.
func nftFamily(family uint8) uint8 {
	if family == egress.FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// Rules reads back the translator's chains and each family's set and timeout
// objects, with the table's flags, the rules in the order desired writes them
// with the family each is placed in and the counter it has carried, and each
// chain's lines against desired. IPv6's lines at the forward hook sit in
// IPv6's chain, which the forward hook's first line sends IPv6's packets on
// to, and IPv4's past that line in the forward hook's own chain, which every
// family meets. A rule another writer put in one of the translator's chains
// changes what the chain does to a packet, so it is read back too, one with no
// comment as an empty spec. In IPv6's chain it holds IPv6 not ready, and in
// another every family, while it stays, and the next pass rewrites the chain
// without it. IPv6's chain missing holds IPv6 not ready the same way. A chain
// whose name starts as a class of none's that desired does not write, or one
// it writes that is missing, and the retired chain, hold every family not
// ready the same way, and the next pass deletes or writes it, but for a stray
// one a rule of another writer's chain or an element of a named map goes to,
// which the fault names and which stays until that rule or element goes. A
// set or an object holds its own family not ready. The elements of the set a
// line looks its sources up in are read with the line. A rule in any other
// table or chain is skipped, and never removed.
func (n *natTables) Rules(desired []Rule) (map[uint8]chainReadback, error) {
	return n.read(n.conn, desired, true)
}

func (n *natTables) Read(desired []Rule) (map[uint8]chainReadback, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return n.read(conn, desired, false)
}

// read reads the chains desired writes and each family's set and objects,
// the chains' lines against desired where lines holds. IPv6's chain is read
// whether or not IPv6 is translated, since it is written either way.
func (n *natTables) read(conn *nftables.Conn, desired []Rule, lines bool) (map[uint8]chainReadback, error) {
	tables, err := nftables.Tables(conn, nftables.Table)
	if err != nil {
		return nil, err
	}
	_, there := tables[unix.NFPROTO_INET]
	chains := translatorChains(desired)
	common := slices.DeleteFunc(slices.Clone(chains), func(chain nftables.Chain) bool { return chain.Name == forward6.Name })
	shared, err := nftables.Contents{Chains: common}.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return nil, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
	}
	fault := shared.Fault
	if there && fault == "" {
		if fault, err = noneChainsRead(conn, chains, shared.Chains); err != nil {
			return nil, err
		}
	}
	if lines && fault == "" {
		if fault, err = translatorRulesFault(conn, common, desired, shared.Rules); err != nil {
			return nil, err
		}
	}
	own, err := nftables.Contents{Chains: []nftables.Chain{forward6}}.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return nil, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
	}
	ownFault := own.Fault
	if there && ownFault == "" && !slices.Contains(own.Chains, forward6.Name) {
		ownFault = fmt.Sprintf("its chain %s is missing", forward6.Name)
	}
	if lines && ownFault == "" {
		if ownFault, err = translatorRulesFault(conn, []nftables.Chain{forward6}, desired, own.Rules); err != nil {
			return nil, err
		}
	}
	// the rules in the order desired writes them: IPv6's chain past the forward hook's
	past := slices.IndexFunc(shared.Rules, func(rule nftables.Installed) bool { return rule.Chain != LimitChain })
	if past < 0 {
		past = len(shared.Rules)
	}
	placed := placeRules(slices.Concat(shared.Rules[:past], own.Rules, shared.Rules[past:]), desired, n.families)
	families := []uint8{egress.FamilyIPv4, egress.FamilyIPv6}
	out := make(map[uint8]chainReadback, len(families))
	for _, family := range families {
		chainFault, remake := "", shared.Remake()
		if family == egress.FamilyIPv6 {
			chainFault, remake = ownFault, remake || own.Remake()
		}
		var objects nftables.Readback
		if slices.Contains(n.families, family) {
			contents := nftables.Contents{Sets: []nftables.Set{flowSet(family, n.limit)}, Timeouts: timeoutObjects(family)}
			if objects, err = contents.Read(conn, tables, unix.NFPROTO_INET); err != nil {
				return nil, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
			}
		}
		out[family] = chainReadback{rules: placed[family], fault: cmp.Or(fault, chainFault, objects.Fault), remake: remake || objects.Remake()}
	}
	return out, nil
}

// placeRules is each rule of held in the family of the rule of desired written
// under its comment, or else of IPv6's chain or the chain of a class of none it
// was read from, and a rule another writer put in a chain every family shares
// in the first of families. The forward hook's first line, which every family
// meets, is no rule of desired's and is left out.
func placeRules(held []nftables.Installed, desired []Rule, families []uint8) map[uint8][]Installed {
	bySpec, byChain := make(map[string]uint8, len(desired)), map[string]uint8{forward6.Name: egress.FamilyIPv6}
	for _, rule := range desired {
		bySpec[rule.String()] = rule.Family
		if rule.Under.IsValid() {
			byChain[rule.chain()] = rule.Family
		}
	}
	out := make(map[uint8][]Installed, len(families))
	for _, rule := range held {
		if rule.Chain == LimitChain && rule.Spec == dispatchSpec {
			continue
		}
		family, ok := bySpec[rule.Spec]
		if !ok {
			if family, ok = byChain[rule.Chain]; !ok && len(families) > 0 {
				family = families[0]
			}
		}
		out[family] = append(out[family], Installed{Spec: rule.Spec, Family: family, Chain: rule.Chain, Counted: rule.Counted, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	return out
}

// noneChainsRead is noneChainsFault of the table, whose chains are held,
// reading the table's rules and verdict maps where a chain is stray
func noneChainsRead(conn *nftables.Conn, chains []nftables.Chain, held []string) (string, error) {
	in, err := strayHolders(conn, chains, held)
	if err != nil {
		return "", err
	}
	return noneChainsFault(chains, held, in), nil
}

// holders is the rules and the verdict maps of the table, each map with the
// chains its elements go to
type holders struct {
	rules []nftables.Installed
	maps  []nftables.VerdictMap
}

// strayHolders is the rules and the verdict maps of the table where it holds a
// stray chain, so strays can name what holds one, and none where it holds none
func strayHolders(conn *nftables.Conn, chains []nftables.Chain, held []string) (holders, error) {
	if len(strays(chains, held, holders{})) == 0 {
		return holders{}, nil
	}
	rules, err := nftables.TableRules(conn, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		return holders{}, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
	}
	maps, err := nftables.VerdictMaps(conn, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		return holders{}, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
	}
	return holders{rules, maps}, nil
}

// noneChainsFault names a chain of a class of none that chains holds and the
// table, held, does not, or one held that chains does not hold, with what of
// in, the table's, goes to it, empty where neither is
func noneChainsFault(chains []nftables.Chain, held []string, in holders) string {
	for _, chain := range chains {
		if strings.HasPrefix(chain.Name, NoneChain) && !slices.Contains(held, chain.Name) {
			return fmt.Sprintf("its chain %s is missing", chain.Name)
		}
	}
	found := strays(chains, held, in)
	if len(found) == 0 {
		return ""
	}
	stray := found[0]
	writer := "a class of none"
	if stray.name == retiredChain {
		writer = "the translator"
	}
	switch {
	case strings.HasPrefix(stray.heldBy, "map "):
		return fmt.Sprintf("its chain %s is not one %s writes, and %s holds an element going to it, so it stays until that element goes", stray.name, writer, stray.heldBy)
	case stray.heldBy != "":
		return fmt.Sprintf("its chain %s is not one %s writes, and %s holds a rule going to it, so it stays until that rule goes", stray.name, writer, stray.heldBy)
	}
	return fmt.Sprintf("its chain %s is not one %s writes", stray.name, writer)
}

// noneStray is a chain named as a class of none's that no class writes, or
// the retired chain, and heldBy what goes to it, which keeps nf_tables from
// deleting it: "chain c" for chain c's rule, by a goto, a jump or its vmap,
// "map m" for an element of the named map m, empty where nothing does
type noneStray struct{ name, heldBy string }

// strays is each chain held whose name starts as a class of none's does that
// chains does not hold, and the retired chain where it is held, with what of
// in, the table's, goes to it, past the chains a pass flushes, the stray
// chains and chains
func strays(chains []nftables.Chain, held []string, in holders) []noneStray {
	written := func(name string) bool {
		return slices.ContainsFunc(chains, func(chain nftables.Chain) bool { return chain.Name == name })
	}
	var names []string
	for _, name := range held {
		if name == retiredChain || len(name) > len(NoneChain) && strings.HasPrefix(name, NoneChain) && !written(name) {
			names = append(names, name)
		}
	}
	flushed := func(chain string) bool { return slices.Contains(names, chain) || written(chain) }
	out := make([]noneStray, 0, len(names))
	for _, name := range names {
		out = append(out, noneStray{name: name, heldBy: nftables.Holder(name, in.rules, in.maps, flushed)})
	}
	return out
}

// translatorRulesFault names how a chain holds lines other than desired
// writes there, the forward hook's first its line to IPv6's chain, reading the
// elements of a set a line looks its sources up in through conn, empty where
// none does
func translatorRulesFault(conn *nftables.Conn, chains []nftables.Chain, desired []Rule, held []nftables.Installed) (string, error) {
	for _, chain := range chains {
		var want []nftables.Line
		if chain.Name == LimitChain {
			want = append(want, dispatchLine())
		}
		for _, rule := range desired {
			if rule.chain() != chain.Name {
				continue
			}
			line, err := translatorLine(rule, 0)
			if err != nil {
				return "", err
			}
			if rule.Sources != "" {
				line.Then = sourcesFault(conn, rule)
			}
			want = append(want, line)
		}
		if fault, err := nftables.ChainFault(chain.Name, want, held); fault != "" || err != nil {
			return fault, err
		}
	}
	return "", nil
}

// sourcesFault reads the elements of the one set the line of rule held looks
// its sources up in through conn, and names how they differ from Sources,
// empty where they do not. The set lives and dies with its line, so a set
// missing or another beside it is a line edited, which its expressions read.
func sourcesFault(conn *nftables.Conn, rule Rule) func(nftables.Installed) (string, error) {
	return func(held nftables.Installed) (string, error) {
		sets := nftables.LookupSets(held.Expressions)
		if len(sets) != 1 {
			return fmt.Sprintf("its chain %s's line %s looks up %v, where one set was written", rule.chain(), rule, sets), nil
		}
		set := sourceSet(rule.Family, 0)
		set.Name = sets[0]
		fault, err := set.ElementFault(conn, unix.NFPROTO_INET, nftables.Prefixes(rule.Sources.Prefixes()))
		if err != nil || fault == "" {
			return "", err
		}
		return fmt.Sprintf("its chain %s's line %s: %s", rule.chain(), rule, fault), nil
	}
}

// Apply brings the translator's chains to rules, in one transaction. Each chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime. Where remake, it
// reads its chains, sets and objects again and deletes first in the same
// transaction each that nf_tables will not change in place, then makes it
// again. A chain whose name starts as a class of none's that rules does not
// write, and the retired chain, is emptied after every chain rules writes, and
// deleted unless a rule of a chain another writer holds or an element of a
// named map goes to it, which nf_tables would refuse the whole transaction
// for, so the readback names that chain or map until it goes.
//
// The timeout objects and the sets are written on every apply and changed by
// none. nf_tables has no update for a ct timeout, so a write of an object that
// exists leaves it as it is, and a set keeps its elements, each source's count
// of flows. A deleted object detaches from every flow it timed, which then
// takes the host's timeouts, and a deleted set forgets every count, so only a
// remake deletes one, the one that reads back other than written, and leaves
// the other family's.
func (n *natTables) Apply(rules []Rule, remake bool) error {
	contents := translatorContents(n.families, n.limit, rules)
	var stale nftables.Contents
	if remake {
		tables, err := nftables.Tables(n.conn, nftables.Table)
		if err != nil {
			return err
		}
		read, err := contents.Read(n.conn, tables, unix.NFPROTO_INET)
		if err != nil {
			return fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
		}
		stale = read.Stale
	}
	held, err := nftables.TableChains(n.conn, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		return err
	}
	in, err := strayHolders(n.conn, contents.Chains, held)
	if err != nil {
		return err
	}
	requests, err := translatorBatch(contents, rules, stale, strays(contents.Chains, held, in))
	if err != nil {
		return err
	}
	return n.conn.Batch(requests)
}

// translatorContents is the translator's objects for families: the chains
// translatorChains names for rules, and each family's set, made under limit,
// and timeout objects
func translatorContents(families []uint8, limit int, rules []Rule) nftables.Contents {
	contents := nftables.Contents{Chains: translatorChains(rules)}
	for _, family := range families {
		contents.Sets = append(contents.Sets, flowSet(family, limit))
		contents.Timeouts = append(contents.Timeouts, timeoutObjects(family)...)
	}
	return contents
}

// translatorBatch is the transaction Apply sends: contents over the stale
// chains, sets and objects of stale, the stray chains as stray names them, the
// forward hook's first line, and rules in their order. Each set a rule looks
// its sources up in takes an ID of its own past the flows' sets', 1 and 2.
func translatorBatch(contents nftables.Contents, rules []Rule, stale nftables.Contents, stray []noneStray) ([]nftables.Request, error) {
	names := make([]string, 0, len(stray))
	for _, chain := range stray {
		names = append(names, chain.name)
	}
	// the head flushes every stray chain, a crashed instance's limit line among
	// their rules, before it deletes a stale set such a line uses, and before
	// any stray is deleted, since a goto in one keeps another it names from
	// being deleted
	requests := contents.Rewrite(unix.NFPROTO_INET, stale, names)
	for _, object := range contents.Timeouts {
		requests = append(requests, object.Create(unix.NFPROTO_INET))
	}
	for _, set := range contents.Sets {
		made, err := set.Create(unix.NFPROTO_INET)
		if err != nil {
			return nil, err
		}
		requests = append(requests, made)
	}
	for _, chain := range stray {
		if chain.heldBy == "" {
			requests = append(requests, regularChain(chain.name).Delete(unix.NFPROTO_INET))
		}
	}
	line := dispatchLine()
	dispatch, err := forward.Rule(unix.NFPROTO_INET, line.Spec, line.Expressions)
	if err != nil {
		return nil, err
	}
	requests = append(requests, dispatch)
	id := uint32(2)
	for _, rule := range rules {
		if rule.Sources != "" {
			id++
			sets, err := sourceRequests(rule, id)
			if err != nil {
				return nil, err
			}
			requests = append(requests, sets...)
		}
		request, err := newRule(rule, id)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// Withdraw removes the translator's chains, sets and timeout objects of both
// families, and the table with them where nothing else is in it. Both
// families' sets and objects go rather than the configured ones alone, so
// those an instance under another configuration left go with the rest.
func (n *natTables) Withdraw() error {
	_, err := nftables.Withdraw(n.conn, translatorScope)
	return err
}

// Conflicts names the other source translation this node's traffic can meet
// first: every nat chain at the postrouting hook, at natPriority or below, of
// a family this node translates or of inet, which hooks both, but the
// translator's own chain. One past natPriority runs after its chain, which has bound
// every flow it takes by then. They are reported rather than removed. Several
// such chains coexist, the first to translate a connection keeps it, and a tool
// that deleted its neighbors' rules to win that race would break docker, an
// SD-WAN agent or the operator's own ruleset, which is exactly the failure
// internal/kernel's ownership rules exist to avoid.
//
// A host still running legacy iptables rather than iptables-nft is invisible
// here, because the two are separate registries in the kernel. An iptables-nft
// rule is an ordinary nftables table and does show up.
func (n *natTables) Conflicts() ([]string, error) {
	replies, err := n.conn.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), nftables.PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump chains: %w", err)
	}
	var out []string
	for _, reply := range replies {
		if len(reply.Data) < nftables.SizeofNfgenmsg {
			continue
		}
		var name string
		switch proto := reply.Data[0]; {
		case proto == unix.NFPROTO_INET:
			name = "inet"
		case proto == unix.NFPROTO_IPV4 && slices.Contains(n.families, egress.FamilyIPv4):
			name = "ip"
		case proto == unix.NFPROTO_IPV6 && slices.Contains(n.families, egress.FamilyIPv6):
			name = "ip6"
		default:
			continue
		}
		table, chain, kind, hook, priority := nftables.DecodeChain(reply)
		own := name == "inet" && table == nftables.Table && chain == ChainName
		if own || kind != "nat" || hook != unix.NF_INET_POST_ROUTING || priority > natPriority {
			continue
		}
		out = append(out, fmt.Sprintf("%s table %s chain %s at priority %d", name, table, chain, priority))
	}
	slices.Sort(out)
	return out, nil
}

// postrouting is the translator's chain, at the source translation hook at
// natPriority
var postrouting = nftables.Chain{Table: nftables.Table, Name: ChainName, Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: natPriority}

// forward is the filter chain at the forward hook, which a forwarded packet
// meets before the translation's, at the priority of the host's own filters
var forward = nftables.Chain{Table: nftables.Table, Name: LimitChain, Type: "filter", Hook: unix.NF_INET_FORWARD, Priority: filterPriority}

// forward6 is the regular chain IPv6's lines at the forward hook sit in,
// which forward's first line sends IPv6's packets on to
var forward6 = regularChain(familyChain(egress.FamilyIPv6))

// dispatchSpec is the comment of forward's first line, which sends IPv6's
// packets on to IPv6's chain
var dispatchSpec = "ipv6 to " + forward6.Name

// dispatchLine is forward's first line. An inet chain meets IPv4 and IPv6
// alone, so an IPv4 packet goes on past it to IPv4's lines and an IPv6 one to
// IPv6's chain, and neither family's lines take a family test at their head,
// which a packet of the other family would otherwise read and fail line by
// line. IPv4's lines sit in forward itself, since a goto costs a packet more
// than the one compare IPv4 makes here.
func dispatchLine() nftables.Line {
	return nftables.Line{Spec: dispatchSpec, Expressions: append(nftables.NFProto(unix.NFPROTO_IPV6), nftables.Goto(forward6.Name))}
}

// translatorChains is the chains in the order rules writes their rules: the
// forward hook's, IPv6's, the chain of each class of none in the order of
// their passes, then the translation's. IPv6's chain is written whether or
// not IPv6 is translated, so forward's first line is the same under every
// configuration.
func translatorChains(rules []Rule) []nftables.Chain {
	out := []nftables.Chain{forward, forward6}
	for _, rule := range rules {
		if rule.Passes {
			out = append(out, regularChain(noneChain(rule.From)))
		}
	}
	return append(out, postrouting)
}

// regularChain is a regular chain by its name, which a packet enters by a
// goto alone: IPv6's, by forward's first line, or a class of none's, by its
// class's pass
func regularChain(name string) nftables.Chain {
	return nftables.Chain{Table: nftables.Table, Name: name, Hook: nftables.NoHook}
}

// flowSet is the set the limit rule of family keeps each source's count of
// flows in, a source to an element. Each element keeps the limit of the rule
// that added it, nft_dynset.c copying the rule's connlimit into it, so the
// set's comment names the limit and a set read back under another is remade.
func flowSet(family uint8, limit int) nftables.Set {
	set := nftables.Set{Table: nftables.Table, Name: flowsSet + digit(family), ID: 2, KeyType: nftables.TypeIPv6Addr, KeyLen: net.IPv6len, Flags: unix.NFT_SET_EVAL, Size: setSize,
		Comment: fmt.Sprintf("limit %d", limit)}
	if family == egress.FamilyIPv4 {
		set.ID, set.KeyType, set.KeyLen = 1, nftables.TypeIPv4Addr, net.IPv4len
	}
	return set
}

// newRule is the request writing rule, which a rule taking Sources sends
// after sourceRequests of the same id
func newRule(rule Rule, id uint32) (nftables.Request, error) {
	line, err := translatorLine(rule, id)
	if err != nil {
		return nftables.Request{}, err
	}
	return nftables.Chain{Table: nftables.Table, Name: rule.chain()}.Rule(unix.NFPROTO_INET, line.Spec, line.Expressions)
}

// sourceSet is the anonymous set a rule taking Sources of family looks them up
// in, numbered id in its transaction
func sourceSet(family uint8, id uint32) nftables.Set {
	if family == egress.FamilyIPv4 {
		return nftables.Anonymous(nftables.Table, id, nftables.TypeIPv4Addr, net.IPv4len, unix.NFT_SET_INTERVAL)
	}
	return nftables.Anonymous(nftables.Table, id, nftables.TypeIPv6Addr, net.IPv6len, unix.NFT_SET_INTERVAL)
}

// sourceRequests makes and fills the set of rule's Sources, numbered id, which
// the kernel takes no change to once the rule holds it
func sourceRequests(rule Rule, id uint32) ([]nftables.Request, error) {
	set := sourceSet(rule.Family, id)
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		return nil, err
	}
	filled, err := set.Fill(unix.NFPROTO_INET, nftables.Prefixes(rule.Sources.Prefixes()))
	if err != nil {
		return nil, err
	}
	return append([]nftables.Request{made}, filled...), nil
}

// translatorLine's expressions come in the order `nft list ruleset` prints
// them, a rule taking Sources looking them up in the set numbered id
func translatorLine(rule Rule, id uint32) (nftables.Line, error) {
	if err := nftables.DeviceName(rule.Interface); err != nil {
		return nftables.Line{}, err
	}
	proto := nftFamily(rule.Family)
	// A rule that tests the flow's state or its protocol reads it first, so a
	// packet of another state or protocol fails it at its first compare. The
	// translation's chain meets both families, so a rule there reads the
	// family ahead of that. A rule of the forward hook's meets its own
	// family's packets alone: IPv4's past forward's first line, which sends
	// IPv6's on to IPv6's chain, and a class of none's by its class's pass.
	head, match, action := protocolRule(rule)
	expressions, family := head, nftables.NFProto(proto)
	if rule.chain() == ChainName {
		expressions, family = slices.Concat(family, head), nil
	}
	kind := rule.kind()
	if kind == limiting {
		// Only the packet that creates a connection's entry is judged. A UDP
		// flow nothing has answered stays in state new, and nf_conncount ends
		// its walk at the flow's own tuple, before the stale tuples the refused
		// flows leave behind, so a later datagram of a flow admitted at the
		// limit would read their count and be refused.
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATE, nftables.CTStateNew, unix.NFT_CMP_NEQ)...)
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATUS, nftables.CTStatusConfirmed, unix.NFT_CMP_EQ)...)
	}
	if rule.Untracked {
		// ct state reads invalid for a packet conntrack gave no entry and
		// untracked for one conntrack does not track, a notrack rule's among
		// them, and nf_nat passes either unchanged.
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATE, nftables.CTStateInvalid|nftables.CTStateUntracked, unix.NFT_CMP_NEQ)...)
	}
	// Out and In match both interfaces, never one. An outbound rule that
	// checked only the arrival interface would also translate mesh transit,
	// which arrives on the mesh device and leaves by it again, and would
	// rewrite a relayed packet's source to this node. A Local rule matches the
	// departure and its own address, and a packet arriving on the mesh device
	// from that address has met the Out rules first.
	switch rule.Direction {
	case Out:
		expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rule.Interface)...)
	case In:
		// A packet this host generated itself has no arrival interface, which
		// nf_tables reports as the empty name rather than as a failure to
		// read, so "iifname != the mesh device" is true of it. Left at that,
		// an inbound rule would translate this node's own mesh traffic to the
		// return source, which for an exit is an address belonging to somebody
		// else. Ruling it out by index says so in one test that means the same
		// thing on a kernel that breaks the rule instead: a locally generated
		// packet reads as interface zero either way.
		expressions = append(expressions, nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4))...)
		expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_NEQ, rule.Interface)...)
	}
	departure := unix.NFT_CMP_NEQ
	if rule.Direction == In {
		departure = unix.NFT_CMP_EQ
	}
	expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_OIFNAME, departure, rule.Interface)...)
	// A rule outside the translation's chain reads its family just before it
	// first loads the source into a set of addresses, where only a packet past
	// every compare ahead meets the test. nft prints that load as the source
	// address only after a family test, and refuses the raw load it prints
	// otherwise as the key of a set of addresses, so the listing of such a
	// line would not load back.
	switch {
	case rule.Sources != "":
		expressions = slices.Concat(expressions, family, [][]byte{nftables.SourceLoad(proto), nftables.Lookup(sourceSet(rule.Family, id), false)})
		family = nil
	case rule.From.IsValid():
		expressions = append(expressions, nftables.SourcePrefix(rule.From)...)
	}
	switch kind {
	case limiting:
		expressions = slices.Concat(expressions, family, [][]byte{nftables.SourceLoad(proto), nftables.ConnectionsOver(flowSet(rule.Family, rule.Limit).Name, uint32(rule.Limit))})
	case timing:
		expressions = append(expressions, attachTimeouts(rule.Family, rule.Timeouts)...)
	case screening:
		expressions = append(expressions, match...)
	}
	if kind.counted() {
		expressions = append(expressions, nftables.Expression("counter", nil))
	}
	switch kind {
	case limiting:
		// The counter counts every refusal, of which the host's rate limit on ICMP
		// errors answers some. Code 1 is IPv6's administratively prohibited, RFC
		// 4443's, and IPv4's host unreachable, which RFC 6888 REQ-11 asks of a NAT
		// refusing a source past its quota, since RFC 1122 section 4.2.3.9 has TCP
		// keep a connection open on it. The kernel gives each from its ICMPX
		// code in the line's own family.
		code := uint8(unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED)
		if rule.Family == egress.FamilyIPv4 {
			code = unix.NFT_REJECT_ICMPX_HOST_UNREACH
		}
		expressions = append(expressions, nftables.RejectICMPX(code))
	case passing:
		// a class of none's packet goes on to its class's chain and none after
		// this one, past the screens and the limit of the shorter classes, and
		// the forward chain's policy passes it at that chain's end
		expressions = append(expressions, nftables.Goto(noneChain(rule.From)))
	case dropping:
		expressions = append(expressions, nftables.Verdict(nftables.Drop))
	case translating:
		expressions = append(expressions, translate(rule)...)
	case screening:
		expressions = append(expressions, action)
	}
	return nftables.Line{Spec: rule.String(), Expressions: expressions}, nil
}

// protocolRule is, for a rule taking a packet by its protocol, the expressions
// newRule puts ahead of the interfaces and the prefix it matches, those it puts
// after them, and the verdict that ends the rule, past the counter its kind
// keeps
func protocolRule(rule Rule) (head, match [][]byte, action []byte) {
	number := rule.Protocol.Number
	if rule.Drops != NoMessage {
		number = unix.IPPROTO_ICMP
	}
	if number == 0 {
		return nil, nil, nil
	}
	head = nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{number})
	if rule.Protocol.Number != 0 {
		// the direction nf_nat binds a flow's translation in, IP_CT_DIR_ORIGINAL,
		// in one byte. A packet no flow is tracked for has none and fails here,
		// which the rule taking it ahead of this one decides.
		direction := nftables.PutAttrBE32(nil, unix.NFTA_CT_DREG, unix.NFT_REG_1)
		direction = nftables.PutAttrBE32(direction, unix.NFTA_CT_KEY, unix.NFT_CT_DIRECTION)
		head = append(head, nftables.Expression("ct", direction), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{0})))
	}
	switch {
	case rule.Drops == SourceQuench:
		match = [][]byte{nftables.TransportLoad(0, 1), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{4}))}
		action = nftables.Verdict(nftables.Drop)
	case rule.Drops == Information:
		match = [][]byte{nftables.TransportLoad(0, 1),
			nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_GTE, []byte{15})), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_LTE, []byte{16}))}
		action = nftables.Verdict(nftables.Drop)
	default:
		// administratively prohibited, RFC 5508 section 6's code 13 in IPv4 and
		// RFC 4443 section 3.1's code 1 in IPv6, both of which the kernel gives
		// for the one ICMPX code
		action = nftables.RejectICMPX(unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED)
	}
	return head, match, action
}

// attachTimeouts matches a timeout rule's protocol and attaches its object,
// which the kernel does on a flow's first packet alone, leaving a confirmed
// flow's timeouts as they are. UDP to port 53 is not matched, so a query keeps
// the host's timeout, as RFC 4787 REQ-5a lets it.
func attachTimeouts(family uint8, timeouts Timeouts) [][]byte {
	protocol, _ := timeoutPolicy(timeouts)
	out := nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{protocol})
	if timeouts == UDPTimeouts {
		out = append(out, nftables.TransportLoad(udpDestinationOffset, 2),
			nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, binary.BigEndian.AppendUint16(nil, 53))))
	}
	return append(out, nftables.ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, timeoutName(family, timeouts)))
}

// timeoutName names family's object of timeouts, one per family, since an
// object keeps the family it was made for (nft_ct_timeout_obj_init)
func timeoutName(family uint8, timeouts Timeouts) string {
	return timeoutObject + timeouts.String() + digit(family)
}

func timeoutObjects(family uint8) []nftables.Timeout {
	var out []nftables.Timeout
	for _, timeouts := range familyTimeouts(family) {
		protocol, policy := timeoutPolicy(timeouts)
		out = append(out, nftables.Timeout{
			Table: nftables.Table, Name: timeoutName(family, timeouts), L3Proto: uint16(nftFamily(family)), L4Proto: protocol, Policy: policy,
		})
	}
	return out
}

// timeoutPolicy is the protocol timeouts names and the seconds of each of its
// states in the order of their CTA_TIMEOUT_ attributes: for TCP SYN_SENT,
// SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE,
// SYN_SENT2, RETRANS and UNACK, and for UDP UNREPLIED and REPLIED
func timeoutPolicy(timeouts Timeouts) (protocol uint8, policy []uint32) {
	switch timeouts {
	case UDPTimeouts:
		return unix.IPPROTO_UDP, []uint32{udpUnrepliedTimeout, udpRepliedTimeout}
	case TCPTimeouts:
		return unix.IPPROTO_TCP, []uint32{transitoryTimeout, transitoryTimeout, establishedTimeout, establishedFloor, establishedFloor,
			transitoryTimeout, timeWaitTimeout, closeTimeout, transitoryTimeout, establishedFloor, establishedFloor}
	case ICMPTimeouts:
		return unix.IPPROTO_ICMP, []uint32{icmpTimeout}
	}
	return unix.IPPROTO_ICMPV6, []uint32{icmpTimeout}
}

// translate is the statement that rewrites the source: the address written in
// the configuration, or the one the host's own routes would have used, which
// nf_tables spells as masquerade and decides per packet. A class of none
// translates the source to itself, the binding nf_nat makes for a connection
// no chain at the hook translated, made here so that a chain that runs after
// this one cannot translate it. See natPriority for which chains run after.
func translate(rule Rule) [][]byte {
	proto := nftFamily(rule.Family)
	switch {
	case rule.None:
		return [][]byte{nftables.SourceLoad(proto), nftables.SourceNAT(proto)}
	case !rule.Source.IsValid():
		return [][]byte{nftables.Expression("masq", nil)}
	}
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	immediate = netlink.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED,
		netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, netlink.AddressBytes(rule.Source)))
	return [][]byte{nftables.Expression("immediate", immediate), nftables.SourceNAT(proto)}
}
