// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// natTables is the linux backend: the tables named after this tool, one per
// address family in use, and the limit their sets count each source's flows
// against.
type natTables struct {
	conn    *nftables.Conn
	monitor *nftables.Monitor
	// reads is Read's socket, opened beside conn so it reads the namespace
	// conn writes whichever thread calls Read. readMu holds it and closed,
	// which Close sets as it closes it, for one reader at a time.
	reads    *nftables.Conn
	readMu   sync.Mutex
	closed   bool
	families []uint8
	limit    int
}

// errClosed is Read's error once Close has run
var errClosed = errors.New("egress: the exit's tables are no longer read, the exit having stopped")

// New validates the capability and opens the tables the backend owns, so a
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
	// A table this tool left behind in a family the configuration no longer
	// covers would go on translating under the old rules for as long as the
	// node ran, and nothing else here would ever look at it: every dump below
	// asks only about the families in use. It is removed once, at startup,
	// which is the only moment the set can have changed.
	if err := be.removeUnusedTables(); err != nil {
		conn.Close()
		return nil, err
	}
	if be.monitor, err = nftables.OpenMonitor(conn, translatorTables); err != nil {
		conn.Close()
		return nil, err
	}
	if be.reads, err = nftables.Dial(); err != nil {
		be.monitor.Close()
		conn.Close()
		return nil, err
	}
	return be, nil
}

func (n *natTables) Close() error {
	n.readMu.Lock()
	defer n.readMu.Unlock()
	n.closed = true
	return errors.Join(n.monitor.Close(), n.conn.Close(), n.reads.Close())
}

func (n *natTables) Changed() <-chan struct{} { return n.monitor.Changed() }

func (n *natTables) Missed() <-chan struct{} { return n.monitor.Missed() }

var (
	// translatorTables is the translator's ip and ip6 tables
	translatorTables = nftables.Scope{Name: TableName, Families: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}}
	// borderTables is the antispoof filter's inet table, which shares the name
	borderTables = nftables.Scope{Name: TableName, Families: []uint8{unix.NFPROTO_INET}}
)

// where names the tables this backend owns, for a log line.
func (n *natTables) where(egress.Egress) string {
	names := make([]string, 0, len(n.families))
	for _, family := range n.families {
		names = append(names, tableFamilyName(family))
	}
	return fmt.Sprintf("nftables table %s %s chains %s and %s and a %s chain for each class of none", strings.Join(names, " and "), TableName, LimitChain, ChainName, NoneChain)
}

// tableFamilyName is the family as `nft` spells it. The two are separate
// tables rather than one inet table because inet nat arrived long after
// nftables did, and a node whose kernel predates it would refuse the chain
// rather than the capability.
func tableFamilyName(family uint8) string {
	if family == egress.FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

// nftFamily is the NFPROTO_ value for one of this package's families.
func nftFamily(family uint8) uint8 {
	if family == egress.FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// Rules reads back the chains this tool owns in each family's table, with the
// table, the set and the timeout objects, the rules in the order desired writes
// them with the family each was read from and the counter it has carried, and
// each chain's lines against desired. A rule another writer put in one of this
// tool's chains changes what the chain does to a packet, so it is read back
// too, one with no comment as an empty spec. Its family is not ready while it
// stays, and the next pass rewrites the chain without it. A chain whose name
// starts as a class of none's that desired does not write, or one it writes
// that is missing, holds its family not ready the same way, and the next pass
// deletes or writes it, but for a stray one a rule of another writer's chain
// or an element of a named map goes to, which the fault names and which stays
// until that rule or element goes. The
// elements of the set a line looks its sources up in are read with the line.
// A rule in any other table or chain is skipped. This backend
// never removes one in another table, and one in another chain of its table
// goes with the table whenever the table is removed whole.
func (n *natTables) Rules(desired []Rule) (map[uint8]chainReadback, error) {
	return n.read(n.conn, desired, true)
}

func (n *natTables) Read(desired []Rule) (map[uint8]chainReadback, error) {
	n.readMu.Lock()
	defer n.readMu.Unlock()
	if n.closed {
		return nil, errClosed
	}
	return n.read(n.reads, desired, false)
}

// read reads each family's table and the chains desired writes there, their
// lines against desired where lines holds
func (n *natTables) read(conn *nftables.Conn, desired []Rule, lines bool) (map[uint8]chainReadback, error) {
	tables, err := nftables.Tables(conn, TableName)
	if err != nil {
		return nil, err
	}
	out := make(map[uint8]chainReadback, len(n.families))
	for _, family := range n.families {
		chains := translatorChains(family, desired)
		read, err := nftables.Contents{
			Chains: chains, Sets: []nftables.Set{flowSet(family, n.limit)}, Timeouts: timeoutObjects(family),
		}.Read(conn, tables, nftFamily(family))
		if err != nil {
			return nil, fmt.Errorf("egress: read table %s %s: %w", tableFamilyName(family), TableName, err)
		}
		held := readback(read, family)
		if _, ok := tables[nftFamily(family)]; ok && held.fault == "" {
			if held.fault, err = noneChainsRead(conn, family, chains, read.Chains); err != nil {
				return nil, err
			}
		}
		if lines && held.fault == "" {
			if held.fault, err = translatorRulesFault(conn, family, chains, desired, read.Rules); err != nil {
				return nil, err
			}
		}
		out[family] = held
	}
	return out, nil
}

// noneChainsRead is noneChainsFault of family's table, whose chains are held,
// reading the table's rules and verdict maps where a chain is stray
func noneChainsRead(conn *nftables.Conn, family uint8, chains []nftables.Chain, held []string) (string, error) {
	in, err := strayHolders(conn, family, chains, held)
	if err != nil {
		return "", err
	}
	return noneChainsFault(chains, held, in), nil
}

// holders is the rules and the verdict maps of a family's table, each map with
// the chains its elements go to
type holders struct {
	rules []nftables.Installed
	maps  []nftables.VerdictMap
}

// strayHolders is the rules and the verdict maps of family's table where it
// holds a stray chain, so strays can name what holds one, and none where it
// holds none
func strayHolders(conn *nftables.Conn, family uint8, chains []nftables.Chain, held []string) (holders, error) {
	if len(strays(chains, held, holders{})) == 0 {
		return holders{}, nil
	}
	rules, err := nftables.TableRules(conn, nftFamily(family), TableName)
	if err != nil {
		return holders{}, fmt.Errorf("egress: read table %s %s: %w", tableFamilyName(family), TableName, err)
	}
	maps, err := nftables.VerdictMaps(conn, nftFamily(family), TableName)
	if err != nil {
		return holders{}, fmt.Errorf("egress: read table %s %s: %w", tableFamilyName(family), TableName, err)
	}
	return holders{rules, maps}, nil
}

// noneChainsFault names a chain of a class of none that chains holds and the
// table, held, does not, or one held that chains does not hold, with what of
// in, the table's, goes to it, empty where neither is
func noneChainsFault(chains []nftables.Chain, held []string, in holders) string {
	for _, chain := range chains {
		if chain.Hook == nftables.NoHook && !slices.Contains(held, chain.Name) {
			return fmt.Sprintf("its chain %s is missing", chain.Name)
		}
	}
	found := strays(chains, held, in)
	if len(found) == 0 {
		return ""
	}
	stray := found[0]
	switch {
	case strings.HasPrefix(stray.heldBy, "map "):
		return fmt.Sprintf("its chain %s is not one a class of none writes, and %s holds an element going to it, so it stays until that element goes", stray.name, stray.heldBy)
	case stray.heldBy != "":
		return fmt.Sprintf("its chain %s is not one a class of none writes, and %s holds a rule going to it, so it stays until that rule goes", stray.name, stray.heldBy)
	}
	return fmt.Sprintf("its chain %s is not one a class of none writes", stray.name)
}

// noneStray is a chain named as a class of none's that no class writes, and
// heldBy what goes to it, which keeps nf_tables from deleting it: "chain c"
// for chain c's rule, by a goto, a jump or its vmap, "map m" for an element of
// the named map m, empty where nothing does
type noneStray struct{ name, heldBy string }

// strays is each chain held whose name starts as a class of none's does that
// chains does not hold, with the first rule of in, the table's, going to it,
// past those a pass flushes, the stray chains and chains, or else the first
// named map of in going to it
func strays(chains []nftables.Chain, held []string, in holders) []noneStray {
	written := func(name string) bool {
		return slices.ContainsFunc(chains, func(chain nftables.Chain) bool { return chain.Name == name })
	}
	var names []string
	for _, name := range held {
		if strings.HasPrefix(name, NoneChain) && !written(name) {
			names = append(names, name)
		}
	}
	out := make([]noneStray, 0, len(names))
	for _, name := range names {
		stray := noneStray{name: name}
		goesTo := func(m nftables.VerdictMap) bool { return slices.Contains(m.Chains, name) }
		for _, rule := range in.rules {
			if slices.Contains(names, rule.Chain) || written(rule.Chain) {
				continue
			}
			vmap := slices.ContainsFunc(nftables.LookupSets(rule.Expressions), func(set string) bool {
				return slices.ContainsFunc(in.maps, func(m nftables.VerdictMap) bool { return m.Anonymous && m.Name == set && goesTo(m) })
			})
			if vmap || slices.Contains(nftables.VerdictChains(rule.Expressions), name) {
				stray.heldBy = "chain " + rule.Chain
				break
			}
		}
		if stray.heldBy == "" {
			if i := slices.IndexFunc(in.maps, func(m nftables.VerdictMap) bool { return !m.Anonymous && goesTo(m) }); i >= 0 {
				stray.heldBy = "map " + in.maps[i].Name
			}
		}
		out = append(out, stray)
	}
	return out
}

// translatorRulesFault names how a chain of family's table holds lines other
// than desired writes there, reading the elements of a set a line looks its
// sources up in through conn, empty where none does
func translatorRulesFault(conn *nftables.Conn, family uint8, chains []nftables.Chain, desired []Rule, held []nftables.Installed) (string, error) {
	for _, chain := range chains {
		var want []nftables.Line
		for _, rule := range desired {
			if rule.Family != family || rule.chain() != chain.Name {
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
		fault, err := set.ElementFault(conn, nftFamily(rule.Family), nftables.Prefixes(rule.Sources.Prefixes()))
		if err != nil || fault == "" {
			return "", err
		}
		return fmt.Sprintf("its chain %s's line %s: %s", rule.chain(), rule, fault), nil
	}
}

// readback is a chain as read, its rules placed in family
func readback(read nftables.Readback, family uint8) chainReadback {
	rules := make([]Installed, 0, len(read.Rules))
	for _, rule := range read.Rules {
		rules = append(rules, Installed{Spec: rule.Spec, Family: family, Chain: rule.Chain, Counted: rule.Counted, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	return chainReadback{rules: rules, fault: read.Fault, remake: read.Remake}
}

// Apply brings this tool's own chains to rules, in one transaction. Each chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime. The table of a
// family in remake is deleted first in the same transaction, with every chain,
// set and timeout object in it, and made again. In any other family a chain
// whose name starts as a class of none's that rules does not write is emptied,
// and deleted unless a rule of a chain another writer holds or an element of a
// named map goes to it, which nf_tables would refuse the whole transaction
// for, so the readback names that chain or map until it goes.
//
// The timeout objects and the set are written on every apply and changed by
// none. nf_tables has no update for a ct timeout, so a write of an object that
// exists leaves it as it is, and a set keeps its elements, each source's count
// of flows. A deleted object detaches from every flow it timed, which then
// takes the host's timeouts, and a deleted set forgets every count, so only a
// remake deletes either, and one that reads back other than written asks for
// that remake.
func (n *natTables) Apply(rules []Rule, remake []uint8) error {
	stray := map[uint8][]noneStray{}
	for _, family := range n.families {
		if slices.Contains(remake, family) {
			continue
		}
		held, err := nftables.TableChains(n.conn, nftFamily(family), TableName)
		if err != nil {
			return err
		}
		chains := translatorChains(family, rules)
		in, err := strayHolders(n.conn, family, chains, held)
		if err != nil {
			return err
		}
		stray[family] = strays(chains, held, in)
	}
	requests, err := translatorBatch(n.families, n.limit, rules, remake, stray)
	if err != nil {
		return err
	}
	return n.conn.Batch(requests)
}

// translatorBatch is the transaction Apply sends over families, their sets
// made under limit, the stray chains of each family's table as stray names
// them. Each set a rule looks its sources up in takes an ID of its own past the
// flows' sets', 1 in each family.
func translatorBatch(families []uint8, limit int, rules []Rule, remake []uint8, stray map[uint8][]noneStray) ([]nftables.Request, error) {
	var requests []nftables.Request
	id := uint32(1)
	for _, family := range families {
		proto := nftFamily(family)
		if slices.Contains(remake, family) {
			requests = append(requests, delTable(family))
		}
		requests = append(requests, nftables.NewTable(proto, TableName))
		for _, object := range timeoutObjects(family) {
			requests = append(requests, object.Create(proto))
		}
		set, err := flowSet(family, limit).Create(proto)
		if err != nil {
			return nil, err
		}
		requests = append(requests, set)
		chains := translatorChains(family, rules)
		for _, chain := range chains {
			// The flush names no handle, which is how nf_tables spells "every
			// rule in this chain". It reaches only the chain named here, in the
			// table named here, both of which this tool created.
			requests = append(requests, chain.Create(proto), chain.Flush(proto))
		}
		// every stray chain is flushed before any is deleted, since a goto in
		// one keeps another it names from being deleted
		for _, chain := range stray[family] {
			requests = append(requests, regularChain(chain.name).Flush(proto))
		}
		for _, chain := range stray[family] {
			if chain.heldBy == "" {
				requests = append(requests, regularChain(chain.name).Delete(proto))
			}
		}
		for _, rule := range rules {
			if rule.Family != family {
				continue
			}
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
	}
	return requests, nil
}

// Withdraw removes the tables this tool created, and only those, each whole
// with every chain in it: the dump names them, and a name that is not this
// tool's is never deleted. Both families are swept rather than the configured
// ones alone, so a table left behind by an instance with a different
// configuration leaves with the rest.
func (n *natTables) Withdraw() error {
	return n.removeTables(func(uint8) bool { return true })
}

// removeUnusedTables is Withdraw narrowed to the families this configuration
// does not cover. See newBackend.
func (n *natTables) removeUnusedTables() error {
	return n.removeTables(func(family uint8) bool { return !slices.Contains(n.families, family) })
}

// removeTables deletes this tool's table in each family the predicate takes.
// The tables are listed first rather than deleted blind, because a delete of a
// table that is not there fails the whole transaction and would turn every
// shutdown on a node that never installed anything into an error. A table that
// goes away between the listing and the delete fails the same way, which only
// something else writing under this tool's own name can cause.
func (n *natTables) removeTables(match func(uint8) bool) error {
	held, err := nftables.Tables(n.conn, TableName)
	if err != nil {
		return err
	}
	var requests []nftables.Request
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if _, ok := held[nftFamily(family)]; ok && match(family) {
			requests = append(requests, delTable(family))
		}
	}
	return n.conn.Batch(requests)
}

// Conflicts names the other source translation this node's traffic can meet
// first: every nat chain at the postrouting hook, at natPriority or below, of
// a family this node translates or of inet, which hooks both, but this tool's
// own chain. One past natPriority runs after this tool's chain, which has bound
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
			name = tableFamilyName(egress.FamilyIPv4)
		case proto == unix.NFPROTO_IPV6 && slices.Contains(n.families, egress.FamilyIPv6):
			name = tableFamilyName(egress.FamilyIPv6)
		default:
			continue
		}
		table, chain, kind, hook, priority := nftables.DecodeChain(reply)
		own := name != "inet" && table == TableName && chain == ChainName
		if own || kind != "nat" || hook != unix.NF_INET_POST_ROUTING || priority > natPriority {
			continue
		}
		out = append(out, fmt.Sprintf("%s table %s chain %s at priority %d", name, table, chain, priority))
	}
	slices.Sort(out)
	return out, nil
}

func delTable(family uint8) nftables.Request {
	return nftables.DeleteTable(nftFamily(family), TableName)
}

// postrouting is the translator's chain, at the source translation hook at
// natPriority
var postrouting = nftables.Chain{Table: TableName, Name: ChainName, Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: natPriority}

// forward is the filter chain at the forward hook, which a forwarded packet
// meets before the translation's, at the priority of the host's own filters
var forward = nftables.Chain{Table: TableName, Name: LimitChain, Type: "filter", Hook: unix.NF_INET_FORWARD, Priority: filterPriority}

// translatorChains is family's chains in the order rules writes their rules:
// the forward hook's, the chain of each class of none in the order of their
// passes, then the translation's
func translatorChains(family uint8, rules []Rule) []nftables.Chain {
	out := []nftables.Chain{forward}
	for _, rule := range rules {
		if rule.Family == family && rule.Passes {
			out = append(out, regularChain(noneChain(rule.From)))
		}
	}
	return append(out, postrouting)
}

// regularChain is the chain of a class of none by its name, which a packet
// enters by its class's pass alone
func regularChain(name string) nftables.Chain {
	return nftables.Chain{Table: TableName, Name: name, Hook: nftables.NoHook}
}

// flowSet is the set the limit rule of family keeps each source's count of
// flows in, a source to an element. Each element keeps the limit of the rule
// that added it, nft_dynset.c copying the rule's connlimit into it, so the
// set's comment names the limit and a set read back under another is remade.
func flowSet(family uint8, limit int) nftables.Set {
	set := nftables.Set{Table: TableName, Name: flowsSet + "6", ID: 1, KeyType: nftables.TypeIPv6Addr, KeyLen: net.IPv6len, Flags: unix.NFT_SET_EVAL, Size: setSize,
		Comment: fmt.Sprintf("limit %d", limit)}
	if family == egress.FamilyIPv4 {
		set.Name, set.KeyType, set.KeyLen = flowsSet+"4", nftables.TypeIPv4Addr, net.IPv4len
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
	return nftables.Chain{Table: TableName, Name: rule.chain()}.Rule(nftFamily(rule.Family), line.Spec, line.Expressions)
}

// sourceSet is the anonymous set a rule taking Sources of family looks them up
// in, numbered id in its transaction
func sourceSet(family uint8, id uint32) nftables.Set {
	if family == egress.FamilyIPv4 {
		return nftables.Anonymous(TableName, id, nftables.TypeIPv4Addr, net.IPv4len, unix.NFT_SET_INTERVAL)
	}
	return nftables.Anonymous(TableName, id, nftables.TypeIPv6Addr, net.IPv6len, unix.NFT_SET_INTERVAL)
}

// sourceRequests makes and fills the set of rule's Sources, numbered id, which
// the kernel takes no change to once the rule holds it
func sourceRequests(rule Rule, id uint32) ([]nftables.Request, error) {
	set, proto := sourceSet(rule.Family, id), nftFamily(rule.Family)
	made, err := set.Create(proto)
	if err != nil {
		return nil, err
	}
	filled, err := set.Fill(proto, nftables.Prefixes(rule.Sources.Prefixes()))
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
	// a rule reading the flow's state reads it first, and one taking a protocol
	// reads that first, so a packet of an established flow fails the rule at its
	// first compare
	expressions, match, action := protocolRule(rule)
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
	proto := nftFamily(rule.Family)
	switch {
	case rule.Sources != "":
		expressions = append(expressions, nftables.SourceLoad(proto), nftables.Lookup(sourceSet(rule.Family, id), false))
	case rule.From.IsValid():
		expressions = append(expressions, nftables.SourcePrefix(rule.From)...)
	}
	switch kind {
	case limiting:
		expressions = append(expressions, nftables.SourceLoad(proto), nftables.ConnectionsOver(flowSet(rule.Family, rule.Limit).Name, uint32(rule.Limit)))
	case timing:
		expressions = append(expressions, attachTimeouts(rule.Timeouts)...)
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
		// keep a connection open on it.
		expressions = append(expressions, nftables.RejectUnreachable(1))
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
		// RFC 4443 section 3.1's code 1 in IPv6
		code := uint8(1)
		if rule.Family == egress.FamilyIPv4 {
			code = 13
		}
		action = nftables.RejectUnreachable(code)
	}
	return head, match, action
}

// attachTimeouts matches a timeout rule's protocol and attaches its object,
// which the kernel does on a flow's first packet alone, leaving a confirmed
// flow's timeouts as they are. UDP to port 53 is not matched, so a query keeps
// the host's timeout, as RFC 4787 REQ-5a lets it.
func attachTimeouts(timeouts Timeouts) [][]byte {
	protocol, _ := timeoutPolicy(timeouts)
	out := nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{protocol})
	if timeouts == UDPTimeouts {
		out = append(out, nftables.TransportLoad(udpDestinationOffset, 2),
			nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, binary.BigEndian.AppendUint16(nil, 53))))
	}
	return append(out, nftables.ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, timeoutObject+timeouts.String()))
}

func timeoutObjects(family uint8) []nftables.Timeout {
	var out []nftables.Timeout
	for _, timeouts := range familyTimeouts(family) {
		protocol, policy := timeoutPolicy(timeouts)
		out = append(out, nftables.Timeout{
			Table: TableName, Name: timeoutObject + timeouts.String(), L3Proto: uint16(nftFamily(family)), L4Proto: protocol, Policy: policy,
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
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED,
		nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, nftables.AddressBytes(rule.Source)))
	return [][]byte{nftables.Expression("immediate", immediate), nftables.SourceNAT(proto)}
}
