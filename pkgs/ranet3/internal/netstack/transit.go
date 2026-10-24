// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"cmp"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// transitReason names the decision's outcome for one packet, or an answer it sent about one
type transitReason uint8

const (
	// transitForwarded counts packets sent on to a peer, one cut into fragments once
	transitForwarded transitReason = iota
	// transitDelivered counts packets written to the tun, for this node's own destinations and the ones linkScoped takes
	transitDelivered
	transitExpired
	transitNoRoute
	// transitHeld counts packets inside a prefix held unreachable, RFC 8966 section 3.5.4
	transitHeld
	// transitRefused counts packets for another node while cap.transit is off
	transitRefused
	// transitInvalid counts what is not one IP packet, an IPv4 header failing RFC 1812 section 5.2.2's checks, and IPv4 options RFC 791 cannot read
	transitInvalid
	// transitMartian counts packets from or to an address no router forwards, but for those to a destination linkScoped takes to the tun
	transitMartian
	// transitSourceRoute counts IPv4 packets carrying a loose or strict source route
	transitSourceRoute
	// transitUnroutedSource counts packets that would egress through an entry counting as a default from a source the mesh routes no reply to
	transitUnroutedSource
	// transitNotReady counts packets that would egress through a prefix cap.egress advertises while their family's translation is not ready
	transitNotReady
	// transitTooBig counts packets larger than the session to their next hop, answered or past cutting
	transitTooBig
	// transitMulticast counts reads off the tun to a multicast destination or the limited broadcast, which the mesh routes none of
	transitMulticast
	transitAnswered
	transitReasonCount
)

// transitReasonNames name each reason in the drop report and its event
var transitReasonNames = [transitReasonCount]string{
	transitForwarded:      "forwarded",
	transitDelivered:      "delivered",
	transitExpired:        "expired",
	transitNoRoute:        "no_route",
	transitHeld:           "held",
	transitRefused:        "refused",
	transitInvalid:        "invalid",
	transitMartian:        "martian",
	transitSourceRoute:    "source_route",
	transitUnroutedSource: "unrouted_source",
	transitNotReady:       "not_ready",
	transitTooBig:         "too_big",
	transitMulticast:      "multicast",
	transitAnswered:       "answered",
}

// transitState is the decision's state, embedded in Mesh
type transitState struct {
	// transitOn is cap.transit, set once at start since a reload changing it is refused
	transitOn atomic.Bool
	// overlay is cap.border's overlay, which a reload may move, nil on a node with no cap.border
	overlay atomic.Pointer[[]schema.Prefix]
	// transitCounts counts each reason since startup
	transitCounts [transitReasonCount]atomic.Uint64
	// transitReport spaces the drop reports, its next claimed by the one report of each interval
	transitReport reportedCount

	// forwardFree holds the batches a session's delivery fills with the packets it forwards
	forwardFree chan *outboundBatch
	// submitMu orders a forward batch's submission against Close closing the job queue
	// closing is set under it once nothing more may be submitted
	submitMu sync.RWMutex
	closing  bool
}

// SetTransit sets whether this node forwards packets between sessions, cap.transit
// with it off a packet for another node is answered administratively prohibited, but for one an End.DT46 of this node delivers to the mesh
func (m *Mesh) SetTransit(on bool) { m.transitOn.Store(on) }

// SetOverlay sets cap.border's overlay as written, the mesh's own address space, nil for none
// an IPv4 packet no route reaches inside it is answered host unreachable, since other hosts of the overlay may be reachable
// and every entry of the table is flagged again for whether it counts as a default with it
func (m *Mesh) SetOverlay(overlay []schema.Prefix) {
	m.Routes.SetOverlay(overlay)
	if overlay == nil {
		m.overlay.Store(nil)
		return
	}
	m.overlay.Store(&overlay)
}

// SetEgressPrefixes sets the prefixes cap.egress advertises, which flags this node's own entries for them
// a packet egressing through one that counts as a default waits on the readiness SetAdvertisedReady gives its family
func (m *Mesh) SetEgressPrefixes(advertised []netip.Prefix) { m.Routes.SetEgress(advertised) }

// inOverlay reports whether address lies inside cap.border's overlay
func (m *Mesh) inOverlay(address netip.Addr) bool {
	overlay := m.overlay.Load()
	if overlay == nil {
		return false
	}
	for _, prefix := range *overlay {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// TransitCounters counts the forwarding decision's outcomes since startup
type TransitCounters struct {
	// Forwarded counts packets a session delivered that went on to a peer, and Delivered the ones written to the tun
	Forwarded, Delivered uint64
	// Expired, NoRoute, Held, Refused, Invalid, Martian, SourceRoute, UnroutedSource, NotReady and TooBig count the packets a session delivered that were dropped, by reason
	Expired, NoRoute, Held, Refused, Invalid, Martian, SourceRoute, UnroutedSource, NotReady, TooBig uint64
	// Multicast counts reads off the tun to a multicast destination or the limited broadcast, dropped
	Multicast uint64
	// Answered counts the ICMP errors sent about dropped packets
	// Unanswered counts the dropped packets the decision would answer that find no address of their family to come from
	// counted before the rules that keep an error from answering a packet and before the rate
	Answered, Unanswered uint64
}

func (m *Mesh) TransitCounters() TransitCounters {
	count := func(reason transitReason) uint64 { return m.transitCounts[reason].Load() }
	return TransitCounters{
		Forwarded:      count(transitForwarded),
		Delivered:      count(transitDelivered),
		Expired:        count(transitExpired),
		NoRoute:        count(transitNoRoute),
		Held:           count(transitHeld),
		Refused:        count(transitRefused),
		Invalid:        count(transitInvalid),
		Martian:        count(transitMartian),
		SourceRoute:    count(transitSourceRoute),
		UnroutedSource: count(transitUnroutedSource),
		NotReady:       count(transitNotReady),
		TooBig:         count(transitTooBig),
		Multicast:      count(transitMulticast),
		Answered:       count(transitAnswered),
		Unanswered:     m.unanswered.Load(),
	}
}

// transitTally is one batch's counts, added to the mesh's once the batch is decided
// so the emitters of several sessions share no counter per packet
type transitTally [transitReasonCount]uint32

func (m *Mesh) addTally(tally *transitTally) {
	for reason, n := range tally {
		if n != 0 {
			m.transitCounts[reason].Add(uint64(n))
		}
	}
}

// dropTransit counts a packet from src to dst dropped for reason in tally, and reports it
func (m *Mesh) dropTransit(tally *transitTally, reason transitReason, src, dst netip.Addr) {
	tally[reason]++
	m.reportTransitDrop(reason, src, dst)
}

// reportTransitDrop writes a line and records netstack.transit.dropped for a packet from src to dst dropped for reason
// at most once a reportInterval, the counters keeping the exact count
func (m *Mesh) reportTransitDrop(reason transitReason, src, dst netip.Addr) {
	if !m.segmentsStarted.IsZero() && !m.transitReport.claim(int64(time.Since(m.segmentsStarted)), m.transitReport.next.Load()) {
		return
	}
	name := transitReasonNames[reason]
	slog.Warn("netstack transit dropped a packet", "interface", m.Name, "reason", name, "src", src, "dst", dst)
	if m.events != nil {
		m.events("netstack.transit.dropped", "", slog.String("reason", name), slog.String("src", src.String()), slog.String("dst", dst.String()))
	}
}

// linkScoped is a destination a session's packet goes to the tun for whatever the table holds
// multicast, IPv6 link-local and the limited broadcast, none of which the mesh routes, RFC 4291 section 2.5.6
// an IPv4 link-local destination is a martian instead, since RFC 3927 section 7 has a router forward none
// and the host forwards 169.254/16 as any unicast destination, out of an exit's uplink, where it forwards no fe80::/10
// an IPv4-mapped destination is no IPv6 link scope either, whatever its IPv4 form, and the decision counts it a martian
func linkScoped(destination netip.Addr) bool {
	if destination.Is4In6() {
		return false
	}
	return destination.IsMulticast() || destination.Is6() && destination.IsLinkLocalUnicast() || destination == packet.LimitedBroadcast
}

// martianDestination is a destination no router forwards, as packet.InvalidDestination has it, and an IPv4-mapped one, which RFC 6890 has no router forward
func martianDestination(destination netip.Addr) bool {
	return packet.InvalidDestination(destination) || destination.Is4In6()
}

func addressesOf(raw []byte, version byte) (netip.Addr, netip.Addr) {
	if version == 4 {
		return netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
	}
	return netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
}

func hopLimit(raw []byte, version byte) byte {
	if version == 4 {
		return raw[8]
	}
	return raw[7]
}

// hasOptions reports an IPv4 header longer than its fixed 20 bytes, the one kind ForwardOptions has work for
// it inlines, so a packet without options pays one comparison and no clock read
func hasOptions(raw []byte) bool { return raw[0]&0x0f > 5 }

// decide runs the forwarding decision over frames, which a session delivered and no segment of this node took, in the order they came
// granted marks the frames an End.DT46 delivering to the mesh took out of their outer headers, which go on whatever cap.transit says, nil where there are none
// from is the peer of the session they came through, nil for frames of no session
// it returns the frames for the tun in the order they came, filtered in place, and hands egress the ones through a prefix cap.egress advertises that counts as a default
// the checks run in RFC 1812's order for IPv6 as for IPv4, each before any answer, so a malformed packet draws none
func (m *Mesh) decide(frames [][]byte, granted []bool, from *Peer) [][]byte {
	transit := m.transitOn.Load()
	var tally transitTally
	var egressed [][]byte
	// declared first so it runs after the tally is added, and a reader that has the frame finds it counted
	defer func() { m.egress(egressed) }()
	defer m.addTally(&tally)
	out := frames[:0]
	var b *outboundBatch
	var egress egressCheck
	for i, frame := range frames {
		// trimmed to the length its header declares, so what follows the packet in its frame is neither forwarded nor quoted
		raw, version := packet.Payload(frame[TUNHeadroom:])
		if version == 0 {
			// RFC 1812 section 5.2.2 has a router answer a truncated IPv4 packet with a parameter problem, which ip_rcv_core does not
			m.dropTransit(&tally, transitInvalid, netip.Addr{}, netip.Addr{})
			continue
		}
		frame = frame[:TUNHeadroom+len(raw)]
		src, dst := addressesOf(raw, version)
		if linkScoped(dst) {
			out = append(out, frame)
			tally[transitDelivered]++
			continue
		}
		if invalid := martianDestination(dst); packet.InvalidSource(src) || invalid {
			m.dropTransit(&tally, transitMartian, src, dst)
			// RFC 4443 section 3.1 code 2, on the session it came from, the one link its source can be on
			// RFC 3927 section 7 has no answer for an IPv4 link-local source
			if version == 6 && src.IsLinkLocalUnicast() && !invalid {
				m.answerBeyondScope(raw, from)
			}
			continue
		}
		peer, verdict, match := m.Routes.Resolve(src, dst)
		// an overlay address no node announces reaches an entry counting as a default, which would egress it
		if verdict == RouteLocal && match.Counted && m.inOverlay(dst) {
			verdict = RouteNone
		}
		// RFC 1812 section 5.2.2 before any processing, and the host's kernel checks what this node delivers to it
		if verdict != RouteLocal && version == 4 && !packet.HeaderValid(raw) {
			m.dropTransit(&tally, transitInvalid, src, dst)
			continue
		}
		switch verdict {
		case RouteLocal:
			// egress through an entry counting as a default leaves only from a source the mesh routes
			// and through a prefix cap.egress advertises only while its family's translation is ready
			if match.Counted {
				if reason, ok := m.egresses(&egress, src, dst, version, match); !ok {
					m.dropTransit(&tally, reason, src, dst)
					continue
				}
			}
			// a counted announcement of cap.route has no translator behind it, so only cap.egress's are handed to egress
			if match.Counted && match.Egress {
				if egressed == nil {
					egressed = make([][]byte, 0, len(frames)-i)
				}
				egressed = append(egressed, frame)
				tally[transitDelivered]++
				continue
			}
			out = append(out, frame)
			tally[transitDelivered]++
			continue
		case RouteNone, RouteHeld:
			reason := transitNoRoute
			if verdict == RouteHeld {
				reason = transitHeld
			}
			m.dropTransit(&tally, reason, src, dst)
			m.answer(raw, version, m.unreachable(verdict, match, dst), 0)
			continue
		}
		if !transit && (granted == nil || !granted[i]) {
			m.dropTransit(&tally, transitRefused, src, dst)
			m.answer(raw, version, answerProhibited, 0)
			continue
		}
		// RFC 8200 section 3 and RFC 1812 section 5.3.1, before the size, so an expired packet is answered as expired
		if hopLimit(raw, version) <= 1 {
			m.dropTransit(&tally, transitExpired, src, dst)
			m.answer(raw, version, answerExpired, 0)
			continue
		}
		if version == 4 && hasOptions(raw) {
			if reason, ok := m.forwardOptions(raw); !ok {
				m.dropTransit(&tally, reason, src, dst)
				continue
			}
		}
		if b == nil {
			if b = m.takeForwardBatch(); b == nil {
				return out
			}
		}
		if reason := m.forwardOne(b, raw, version, peer); reason != transitForwarded {
			m.dropTransit(&tally, reason, src, dst)
		} else {
			tally[transitForwarded]++
		}
		if b.n == len(b.packets) {
			m.submitForward(b)
			b = nil
		}
	}
	if b != nil {
		m.submitForward(b)
	}
	return out
}

// unreachable is the answer to a packet no route reaches, verdict and match being what the table answered for it
// RFC 4443 section 3.1 code 0 over IPv6, and over IPv4 RFC 1812 section 5.2.7.1's last rule
// host unreachable where other hosts of the destination's network may be reachable, inside a hold that does not count as a default or inside the overlay
// network unreachable where no network of hosts holds it, under an entry counting as a default or none
func (m *Mesh) unreachable(verdict Verdict, match Match, destination netip.Addr) answerKind {
	if destination.Is4() && (verdict == RouteHeld && !match.Counted || m.inOverlay(destination)) {
		return answerHostUnreachable
	}
	return answerNoRoute
}

// egressCheck keeps one batch's egress lookups
// each pair's answer for the batch, and the readiness words read once
type egressCheck struct {
	pairs      [egressPairs][2]netip.Addr
	routed     [egressPairs]bool
	kept       int
	ready      uint32
	advertised uint32
	readyRead  bool
}

// routed reports whether the mesh routes a reply to a packet from source to destination
// the reply's route reaching a peer, a hold or this node's own entry, its LAN or an address of its own, entries counting as a default passed over
// a route announced from a source prefix decides it, so the answer is kept per pair rather than per source
func (m *Mesh) routed(check *egressCheck, source, destination netip.Addr) bool {
	pair := [2]netip.Addr{source, destination}
	for i := range check.kept {
		if check.pairs[i] == pair {
			return check.routed[i]
		}
	}
	_, verdict, match := m.replyRoute(source, destination)
	routed := !match.Counted && (verdict == RoutePeer || verdict == RouteHeld || verdict == RouteLocal)
	if check.kept < egressPairs {
		check.pairs[check.kept], check.routed[check.kept] = pair, routed
		check.kept++
	}
	return routed
}

// replyRoute resolves the route a reply to a packet from source to destination takes, from destination to source
// so a route announced from a source prefix covers source only where that prefix covers destination, RFC 9079 section 4
func (m *Mesh) replyRoute(source, destination netip.Addr) (*Peer, Verdict, Match) {
	return m.Routes.Resolve(destination, source)
}

// readyFor reports the translation of family, an srv6 next header, ready, for the egress segments or for an advertised prefix as advertised says
// both words are read once a batch
func (m *Mesh) readyFor(check *egressCheck, family uint8, advertised bool) bool {
	if !check.readyRead {
		check.ready, check.advertised, check.readyRead = m.egressReady.Load(), m.advertisedReady.Load(), true
	}
	word := check.ready
	if advertised {
		word = check.advertised
	}
	return word&egressReadyFor(family) != 0
}

// egresses reports whether a packet of version from source to destination egresses through match, an entry of this node's counting as a default, and the reason it does not
// a packet the mesh routes no reply to is dropped with no answer, since nothing routes one back
// and a prefix cap.egress advertises waits on its family's readiness, which a counted cap.route announcement has none of
func (m *Mesh) egresses(check *egressCheck, source, destination netip.Addr, version byte, match Match) (transitReason, bool) {
	if !m.routed(check, source, destination) {
		return transitUnroutedSource, false
	}
	family := uint8(srv6.NextHeaderIPv6)
	if version == 4 {
		family = srv6.NextHeaderIPv4
	}
	if match.Egress && !m.readyFor(check, family, true) {
		return transitNotReady, false
	}
	return transitDelivered, true
}

// forwardOptions processes the options of raw, an IPv4 header HeaderValid passed that carries some, as RFC 1812 sections 5.3.13.4 to 5.3.13.6 have a router forwarding it
// Record Route and Timestamp record the IPv4 router-id, or 192.0.0.8 on a node holding none, the address errorSource answers IPv4 from
// it reports false with the reason for a packet it drops, a source route or options RFC 791 cannot read, which are answered parameter problem
func (m *Mesh) forwardOptions(raw []byte) (transitReason, bool) {
	address, _ := m.errorSource(false)
	verdict, pointer := packet.ForwardOptions(raw, address, m.ownAddress, time.Now())
	switch verdict {
	case packet.OptionsSourceRouted:
		return transitSourceRoute, false
	case packet.OptionsMalformed:
		m.answer(raw, 4, answerParameter, pointer)
		return transitInvalid, false
	}
	return transitForwarded, true
}

// ownAddress reports an address this node holds as a host route of its own, the prespecified address a timestamp option stamps at
func (m *Mesh) ownAddress(address netip.Addr) bool {
	_, verdict, match := m.Routes.Resolve(netip.Addr{}, address)
	return verdict == RouteLocal && match.Bits == address.BitLen()
}

// forwardOne puts raw, one packet of version, into b for peer, and reports what became of it
// a packet larger than peer's session is answered over IPv6 and with DF, quoting it as it arrived, and cut into fragments otherwise
// anything else has its hop limit or TTL taken down and its MSS clamped to peer's session
func (m *Mesh) forwardOne(b *outboundBatch, raw []byte, version byte, peer *Peer) transitReason {
	share, seen := b.shares[peer]
	if !seen {
		share.mtu = peer.MTU()
		b.peerOrder = append(b.peerOrder, peer)
	}
	nextHeader := byte(esp.NextHeaderIPv6)
	if version == 4 {
		nextHeader = esp.NextHeaderIPv4
	}
	reason := transitForwarded
	switch {
	// RFC 8200 section 4.5 lets only the source fragment, and DF is RFC 791 section 3.1's
	case len(raw) > share.mtu && (version == 6 || raw[6]&0x40 != 0):
		m.answer(raw, version, answerTooBig, share.mtu)
		reason = transitTooBig
	case len(raw) > share.mtu:
		packet.DecrementTTL(raw)
		// forwardOptions read every option list that reaches here, framed as the cut frames it, so a refusal names no octet at fault
		count, bytes, _ := b.cut.add(peer, nextHeader, nil, raw, share.mtu)
		if count == 0 {
			reason = transitTooBig
		}
		share.count += count
		share.bytes += bytes
	default:
		if version == 4 {
			packet.DecrementTTL(raw)
		} else {
			raw[7]--
		}
		m.ClampMSS(raw, share.mtu)
		b.packets[b.n], b.peers[b.n], b.headers[b.n] = raw, peer, nextHeader
		b.n++
		share.count++
		share.bytes += len(raw)
	}
	b.shares[peer] = share
	return reason
}

// takeForwardBatch is a batch to fill with forwarded packets
// it waits while every one is in flight, which holds back the delivery of the one session waiting, and is nil once the mesh closes
func (m *Mesh) takeForwardBatch() *outboundBatch {
	if m.forwardFree == nil {
		return nil
	}
	select {
	case b := <-m.forwardFree:
		return b
	case <-m.closed:
		return nil
	}
}

// submitForward reserves each peer's share of b in the order the session delivered it, which keeps each flow's order, and hands b to the workers that seal it
// once Close has begun to close the job queue it gives b back instead
func (m *Mesh) submitForward(b *outboundBatch) {
	m.submitMu.RLock()
	defer m.submitMu.RUnlock()
	if m.closing {
		b.reset()
		b.free <- b
		return
	}
	m.dispatchOutbound(b)
}

// answerKind is the ICMP error the decision answers a packet with
type answerKind uint8

const (
	// answerNoRoute is RFC 4443 section 3.1 code 0, and RFC 1812 section 5.2.7.1 network unreachable
	answerNoRoute answerKind = iota
	// answerHostUnreachable is RFC 1812 section 5.2.7.1 host unreachable, and code 0 over IPv6
	answerHostUnreachable
	// answerProhibited is RFC 4443 section 3.1 code 1, and RFC 1812 section 5.2.7.1 code 13
	answerProhibited
	// answerExpired is time exceeded, RFC 4443 section 3.3 and RFC 1812 section 5.3.1
	answerExpired
	// answerParameter is an IPv4 parameter problem, its pointer naming the octet at fault
	answerParameter
	// answerTooBig is packet too big, RFC 4443 section 3.2, and fragmentation needed, RFC 1191 section 4, carrying the next hop's MTU
	answerTooBig
)

// buildAnswer is the answer of kind to raw, one packet of version, from source, nil where none is built
// value is the next hop's MTU for a too-big answer and the pointer of a parameter problem
// an IPv4 answer carries ttl, and none is built under a ttl of 0
// allow is the builder's, called once raw is a packet an error may answer and before anything is built
func buildAnswer(raw []byte, version byte, kind answerKind, value int, source netip.Addr, ttl uint8, allow func() bool) []byte {
	if version == 6 {
		switch kind {
		case answerNoRoute, answerHostUnreachable:
			return srv6.NoRoute(raw, source, allow)
		case answerProhibited:
			return srv6.Prohibited(raw, source, allow)
		case answerExpired:
			return srv6.TimeExceeded(raw, source, allow)
		case answerTooBig:
			return srv6.PacketTooBig(raw, source, value, allow)
		}
		return nil
	}
	switch kind {
	case answerNoRoute:
		return packet.NetUnreachable(raw, source, ttl, allow)
	case answerHostUnreachable:
		return packet.HostUnreachable(raw, source, ttl, allow)
	case answerProhibited:
		return packet.Prohibited(raw, source, ttl, allow)
	case answerExpired:
		return packet.TimeExceeded(raw, source, ttl, allow)
	case answerParameter:
		return packet.ParameterProblem(raw, source, ttl, value, allow)
	}
	return packet.FragmentationNeeded(raw, source, ttl, value, allow)
}

// allowAnswer is the draw an answer to a packet from sender makes, on sender's bucket and the node's cap, and on the cap alone for the zero Addr
func (m *Mesh) allowAnswer(sender netip.Addr) func() bool {
	return func() bool { return m.takeICMPToken(sender) }
}

// answer sends the ICMP error of kind about raw, one packet of version a session delivered that this node does not forward
// value is the next hop's MTU for a too-big answer and the pointer of a parameter problem
// it draws as allowAnswer says, once the builder finds raw a packet an error may answer and before it builds
func (m *Mesh) answer(raw []byte, version byte, kind answerKind, value int) {
	src, dst := addressesOf(raw, version)
	// packet too big and fragmentation needed draw under the node's cap alone, as answerTooBig's do
	sender := src
	if kind == answerTooBig {
		sender = netip.Addr{}
	}
	allow := m.allowAnswer(sender)
	// an answer to a packet this host or a network behind it sent goes into the tun, from the answered packet's destination
	// the one source every reverse path check of the host takes
	// the host drops an IPv4 packet from an address of its own, fib_validate_source
	// and a strict chain one from an address it routes out of another link, nft_fib_ipv6.c, which the router-id and a SID can both be
	// a source only an entry counting as a default reaches is no network behind this host, and the mesh routes no answer to it
	if _, verdict, match := m.replyRoute(src, dst); verdict == RouteLocal {
		if match.Counted {
			return
		}
		if out := buildAnswer(raw, version, kind, value, dst, m.AnswerTTL(), allow); out != nil {
			m.writeHostPacket(out)
			m.noteAnswered(kind)
		}
		return
	}
	source, ok := m.answerSource(version, kind, dst)
	if !ok {
		return
	}
	if out := buildAnswer(raw, version, kind, value, source, m.AnswerTTL(), allow); out != nil && m.sendAnswer(out) {
		m.noteAnswered(kind)
	}
}

// answerSource is where an answer to a packet from a session comes from, which goes back through the mesh
// a session is an unnumbered link, so it is the router-id of the packet's family, RFC 1812 section 4.3.2.4
// a time exceeded, a destination unreachable or a parameter problem falls back as errorSource says, and may go unanswered
// a too-big answer over IPv6 falls back to a SID as errorSource does, an address of this node RFC 4443 section 2.2 (b) asks for
// and with neither, over either family, to the packet's destination, since path MTU discovery needs the answer more than its source
func (m *Mesh) answerSource(version byte, kind answerKind, destination netip.Addr) (netip.Addr, bool) {
	if kind != answerTooBig {
		return m.errorSource(version == 6)
	}
	sources := m.AnswerSources()
	if version == 6 {
		return cmp.Or(sources.Router6, sources.SID, destination), true
	}
	return cmp.Or(sources.Router4, destination), true
}

func (m *Mesh) noteAnswered(kind answerKind) {
	m.transitCounts[transitAnswered].Add(1)
	if kind == answerTooBig {
		m.tooBigAnswered.Add(1)
	}
}

// answerBeyondScope answers raw, an IPv6 packet from a link-local source to a wider destination, RFC 4443 section 3.1 code 2
// it goes back on the session the packet came through, the one link its source can be on, and nowhere for a packet of no session
func (m *Mesh) answerBeyondScope(raw []byte, from *Peer) {
	if from == nil {
		return
	}
	source, ok := m.errorSource(true)
	if !ok {
		return
	}
	sender, _ := addressesOf(raw, 6)
	if out := srv6.BeyondScope(raw, source, m.allowAnswer(sender)); out != nil && m.sendThrough(from, out, esp.NextHeaderIPv6) {
		m.noteAnswered(answerNoRoute)
	}
}
