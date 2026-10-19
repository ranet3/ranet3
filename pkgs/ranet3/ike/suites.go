// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// IKESuites is cap.crypto.ike, the IKE SA's transforms by name, each list most preferred first
// a list left out holds every name of its kind in the order cipherNames, prfNames and kexNames give
type IKESuites struct {
	Cipher []string `yaml:"cipher,omitempty" json:"cipher,omitempty" toml:"cipher,omitempty"`
	PRF    []string `yaml:"prf,omitempty" json:"prf,omitempty" toml:"prf,omitempty"`
	// an entry of Kex is a classical key exchange, which runs in IKE_SA_INIT or a rekey's CREATE_CHILD_SA, alone or joined with + to mlkem768 or mlkem1024, which runs after it in an IKE_INTERMEDIATE or IKE_FOLLOWUP_KE exchange of its own
	// RFC 9370 section 2.2.1: "Additional key exchanges negotiated via newly defined transforms MUST take place in a series of IKE_INTERMEDIATE exchanges following the IKE_SA_INIT exchange, performed in an order of the values of their Transform Types."
	Kex []string `yaml:"kex,omitempty" json:"kex,omitempty" toml:"kex,omitempty"`
}

// ESPSuites is cap.crypto.esp, the Child SA's ciphers by name, most preferred first
type ESPSuites struct {
	Cipher []string `yaml:"cipher,omitempty" json:"cipher,omitempty" toml:"cipher,omitempty"`
}

// suiteName is one name a cap.crypto list holds and the transform it stands for
type suiteName struct {
	name      string
	transform Transform
}

var (
	cipherNames = []suiteName{
		{"aes256gcm", Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}},
		{"aes128gcm", Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}},
		{"chacha20poly1305", Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}},
	}
	prfNames = []suiteName{
		{"sha384", Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_384}},
		{"sha256", Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256}},
	}
	kexNames = []suiteName{
		{"x25519", Transform{Type: TransDH, ID: DH_CURVE25519}},
		{"p384", Transform{Type: TransDH, ID: DH_ECP_384}},
		{"p256", Transform{Type: TransDH, ID: DH_ECP_256}},
	}
	// each of postQuantumNames runs only joined after a classical key exchange, in an IKE_INTERMEDIATE or IKE_FOLLOWUP_KE exchange of its own
	postQuantumNames = []suiteName{
		{"mlkem768", Transform{Type: TransDH, ID: ML_KEM_768}},
		{"mlkem1024", Transform{Type: TransDH, ID: ML_KEM_1024}},
	}
)

// Suites is the four cap.crypto lists as transforms and kex entries, each most preferred first
// a nil list holds every name of its kind
// so the zero Suites is a node that writes none of them
type Suites struct {
	ikeCipher, ikePRF, espCipher []Transform
	kex                          []kexEntry
}

// kexEntry is one entry of cap.crypto ike kex, the key exchange IKE_SA_INIT runs and the additional ones of RFC 9370 after it
type kexEntry struct {
	group uint16
	// additions holds the method of each additional key exchange in the order they run, zero past the last
	additions [addkeTypes]uint16
}

func (e kexEntry) classical() bool { return e.additions[0] == 0 }

func (e kexEntry) added() []uint16 {
	n := slices.Index(e.additions[:], 0)
	if n < 0 {
		n = len(e.additions)
	}
	return e.additions[:n]
}

// entry is the kex entry whose key exchanges made an SA of suite
func (s SASuite) entry() kexEntry { return kexEntry{group: s.DHGroup, additions: s.Additions} }

// authMID is the Message ID of the IKE_AUTH that makes an SA of suite, one IKE_INTERMEDIATE exchange for each additional key exchange ahead of it
// RFC 9242 section 3.2: "The Message ID for the first pair of IKE_AUTH messages is one more than the value used in the last IKE_INTERMEDIATE exchange."
func (s SASuite) authMID() uint32 { return uint32(len(s.entry().added())) + 1 }

// Suites resolves the four lists, refusing a list no session could negotiate from by the field and the name an operator wrote
func (c Crypto) Suites() (Suites, error) {
	var s Suites
	var err error
	if s.ikeCipher, err = resolve("ike cipher", c.IKE.Cipher, cipherNames); err != nil {
		return Suites{}, err
	}
	if s.ikePRF, err = resolve("ike prf", c.IKE.PRF, prfNames); err != nil {
		return Suites{}, err
	}
	if s.kex, err = resolveKex(c.IKE.Kex); err != nil {
		return Suites{}, err
	}
	if s.espCipher, err = resolve("esp cipher", c.ESP.Cipher, cipherNames); err != nil {
		return Suites{}, err
	}
	return s, nil
}

func resolve(field string, list []string, names []suiteName) ([]Transform, error) {
	if list == nil {
		return nil, nil
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("ike: cap.crypto %s is empty, which leaves nothing to negotiate", field)
	}
	out := make([]Transform, 0, len(list))
	for i, name := range list {
		if slices.Contains(list[:i], name) {
			return nil, fmt.Errorf("ike: cap.crypto %s names %s twice", field, name)
		}
		at := slices.IndexFunc(names, func(named suiteName) bool { return named.name == name })
		if at < 0 {
			return nil, fmt.Errorf("ike: cap.crypto %s names %q, which is not one of %s", field, name, spelled(namesOf(names)))
		}
		out = append(out, names[at].transform)
	}
	return out, nil
}

// resolveKex reads a joined entry whole
// so a name joined after a classical one is refused for the exchange it asks for
// an entry is a classical key exchange and at most one ML-KEM method after it, which one IKE_INTERMEDIATE or IKE_FOLLOWUP_KE exchange runs
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.1: "Thus, implementations transporting IKE over UDP and not performing Path MTU (PMTU) discovery SHOULD NOT use ML-KEM-768 or ML-KEM-1024 in the IKE_SA_INIT exchange on networks where the PMTU is unknown or restricted."
func resolveKex(list []string) ([]kexEntry, error) {
	if list == nil {
		return nil, nil
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("ike: cap.crypto ike kex is empty, which leaves nothing to negotiate")
	}
	classical, postQuantum := namesOf(kexNames), namesOf(postQuantumNames)
	out := make([]kexEntry, 0, len(list))
	for i, entry := range list {
		if slices.Contains(list[:i], entry) {
			return nil, fmt.Errorf("ike: cap.crypto ike kex names %s twice", entry)
		}
		parts := strings.Split(entry, "+")
		for _, part := range parts {
			if slices.Contains(classical, part) || slices.Contains(postQuantum, part) {
				continue
			}
			if len(parts) == 1 {
				return nil, fmt.Errorf("ike: cap.crypto ike kex names %q, which is not one of %s", entry, spelled(classical))
			}
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q names %q, which is not one of %s",
				entry, part, spelled(slices.Concat(classical, postQuantum)))
		}
		if slices.Contains(postQuantum, parts[0]) {
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q starts with %s, which runs only after a classical key exchange, as in x25519+%s",
				entry, parts[0], parts[0])
		}
		if len(parts) > 2 {
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q joins %d key exchanges after its first, and an entry joins one", entry, len(parts)-1)
		}
		resolved := kexEntry{group: kexNames[slices.Index(classical, parts[0])].transform.ID}
		if len(parts) == 2 {
			joined := parts[1]
			if slices.Contains(classical, joined) {
				return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q joins %s, and an entry joins only an ML-KEM method after its first, one of %s",
					entry, joined, spelled(postQuantum))
			}
			resolved.additions[0] = postQuantumNames[slices.Index(postQuantum, joined)].transform.ID
		}
		out = append(out, resolved)
	}
	return out, nil
}

func namesOf(table []suiteName) []string {
	names := make([]string, len(table))
	for i, named := range table {
		names[i] = named.name
	}
	return names
}

func spelled(names []string) string {
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func (s Suites) ikeCiphers() []Transform { return listed(s.ikeCipher, cipherNames) }
func (s Suites) ikePRFs() []Transform    { return listed(s.ikePRF, prfNames) }
func (s Suites) espCiphers() []Transform { return listed(s.espCipher, cipherNames) }

func (s Suites) kexEntries() []kexEntry {
	if s.kex != nil {
		return s.kex
	}
	all := make([]kexEntry, len(kexNames))
	for i, named := range kexNames {
		all[i] = kexEntry{group: named.transform.ID}
	}
	return all
}

// rekeyable is the kex entries a rekey of an IKE SA the key exchanges of current made may run
// while kex holds current, only those that keep each of its additional key exchanges, since the session proved the peer runs them
// a reload that removed current leaves the rekey every entry, as the operator chose
func (s Suites) rekeyable(current kexEntry) []kexEntry {
	entries := s.kexEntries()
	if !slices.Contains(entries, current) {
		return entries
	}
	return slices.DeleteFunc(slices.Clone(entries), func(entry kexEntry) bool { return !entry.keeps(current) })
}

// keeps reports whether e runs each additional key exchange other runs
func (e kexEntry) keeps(other kexEntry) bool {
	return !slices.ContainsFunc(other.added(), func(method uint16) bool { return !slices.Contains(e.added(), method) })
}

func listed(list []Transform, names []suiteName) []Transform {
	if list != nil {
		return list
	}
	all := make([]Transform, len(names))
	for i, named := range names {
		all[i] = named.transform
	}
	return all
}

// Changed names each list next holds otherwise, as the file spells its key
func (s Suites) Changed(next Suites) []string {
	var changed []string
	for _, list := range []struct {
		key  string
		same bool
	}{
		{"cap.crypto.ike.cipher", slices.Equal(s.ikeCiphers(), next.ikeCiphers())},
		{"cap.crypto.ike.prf", slices.Equal(s.ikePRFs(), next.ikePRFs())},
		{"cap.crypto.ike.kex", slices.Equal(s.kexEntries(), next.kexEntries())},
		{"cap.crypto.esp.cipher", slices.Equal(s.espCiphers(), next.espCiphers())},
	} {
		if !list.same {
			changed = append(changed, list.key)
		}
	}
	return changed
}

func current(suites func() Suites) Suites {
	if suites == nil {
		return Suites{}
	}
	return suites()
}

// ikeProposals is the IKE_SA_INIT offer with its KE payload in group, one proposal for each kex entry
// RFC 7296 section 1.2: "The initiator MUST again propose its full set of acceptable cryptographic suites because the rejection message was unauthenticated and otherwise an active attacker could trick the endpoints into negotiating a weaker suite than a stronger one that they both prefer."
func (s Suites) ikeProposals(group uint16) []Proposal {
	return leadingGroup(s.entryProposals(s.kexEntries(), s.ikePRFs(), nil), group)
}

// ikeRekeyProposals is the offer of a rekey replacing an IKE SA of current, with its KE payload in group, one proposal for each entry the rekey may run
func (s Suites) ikeRekeyProposals(spi []byte, current SASuite, group uint16) []Proposal {
	return leadingGroup(s.entryProposals(s.rekeyable(current.entry()), s.rekeyPRFs(current.PRFID), spi), group)
}

// asksIntermediate reports whether the IKE_SA_INIT offer of the lists holds an ADDKE type
// RFC 9370 section 2.2.1: "If the initiator includes any ADDKE Transform Types into the SA payload in the IKE_SA_INIT exchange request message, then it MUST also negotiate the use of the IKE_INTERMEDIATE exchange, as described in [RFC9242] by including an INTERMEDIATE_EXCHANGE_SUPPORTED notification in the same message."
func (s Suites) asksIntermediate() bool {
	return slices.ContainsFunc(s.kexEntries(), func(entry kexEntry) bool { return !entry.classical() })
}

// entryProposals is a proposal for each of entries offering every listed cipher, prfs and the entry's key exchanges
// RFC 9370 section 2.2.1: "When forming a proposal, the initiator adds transforms for the IKE_SA_INIT exchange using Transform Type 4." and "Additional key exchange methods are proposed using ADDKE Transform Types."
func (s Suites) entryProposals(entries []kexEntry, prfs []Transform, spi []byte) []Proposal {
	proposals := make([]Proposal, len(entries))
	for i, entry := range entries {
		transforms := slices.Concat(s.ikeCiphers(), prfs, []Transform{{Type: TransDH, ID: entry.group}})
		for at, method := range entry.additions {
			if method == 0 {
				break
			}
			transforms = append(transforms, Transform{Type: TransADDKE1 + TransformType(at), ID: method})
		}
		proposals[i] = Proposal{Protocol: ProtoIKE, SPI: spi, Transforms: transforms}
	}
	return proposals
}

// leadingGroup is proposals with the first whose Transform Type 4 is group ahead of the rest, which keep their order, numbered as they are sent
// RFC 7296 section 3.4 on the KE payload's group: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
// RFC 7296 section 3.3: "If there is more than one, they MUST be ordered from most preferred to least preferred."
// the lists' order is the preference, so the one proposal the KE payload needs first is all that moves
// RFC 7296 section 3.3.1: "When a proposal is made, the first proposal in an SA payload MUST be 1, and subsequent proposals MUST be one more than the previous proposal (indicating an OR of the two proposals)."
func leadingGroup(proposals []Proposal, group uint16) []Proposal {
	ordered := slices.Clone(proposals)
	inGroup := func(proposal Proposal) bool {
		return slices.Contains(proposal.Transforms, Transform{Type: TransDH, ID: group})
	}
	if at := slices.IndexFunc(ordered, inGroup); at > 0 {
		ordered = slices.Concat(ordered[at:at+1], ordered[:at], ordered[at+1:])
	}
	for i := range ordered {
		ordered[i].Number = uint8(i + 1)
	}
	return ordered
}

func (s Suites) espProposal(spi []byte) Proposal {
	return Proposal{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: slices.Concat(s.espCiphers(), []Transform{{Type: TransESN, ID: ESN_NO}})}
}

// espRekeyProposal is the offer of a rekey replacing old
func (s Suites) espRekeyProposal(spi []byte, old ChildSA) Proposal {
	return Proposal{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: slices.Concat(s.rekeyCiphers(old), []Transform{{Type: TransESN, ID: ESN_NO}})}
}

// rekeyPRFs is the PRF a rekey replacing an IKE SA whose PRF is prfID may take, none once ike prf left it out
// RFC 7296 section 2.18: "Because the rekeying exchange belongs to the old IKE SA, it is the old IKE SA's PRF that is used to generate SKEYSEED."
// RFC 7296 section 2.18: "SK_d, SK_ai, SK_ar, SK_ei, and SK_er are computed from SKEYSEED as specified in Section 2.14, using SPIi, SPIr, Ni, and Nr from the new exchange, and using the new IKE SA's PRF."
// strongSwan's keymat_v2.c derive_ike_keys says it will "use OLD SAs PRF functions for both prf_plus and prf"
// so a rekey that changed the PRF would leave the two ends holding different keys
func (s Suites) rekeyPRFs(prfID uint16) []Transform {
	if !s.holdsPRF(prfID) {
		return nil
	}
	return []Transform{{Type: TransPRF, ID: prfID}}
}

// RFC 7296 section 2.8: "the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one"
// a rekey this end starts offers only the cipher of the Child SA it replaces while esp cipher holds it
func (s Suites) rekeyCiphers(old ChildSA) []Transform {
	if current := wireCipher(old); slices.Contains(s.espCiphers(), current) {
		return []Transform{current}
	}
	return s.espCiphers()
}

// rekeyChoice is the order this end answers a peer's rekey of old in, the cipher old holds first while esp cipher holds it
// a peer whose own lists left that cipher out offers the others
// and refusing them would leave its SA on a cipher it removed
func (s Suites) rekeyChoice(old ChildSA) []Transform {
	return promoted(s.espCiphers(), wireCipher(old))
}

// rekeyEntries is the entries rekeyable gives, in the order this end answers a peer's rekey of an IKE SA of current
// current comes first while kex holds it and the KE payload is in its group
// so a rekey between ends whose lists order the entries differently keeps the entry and asks for no other
func (s Suites) rekeyEntries(current kexEntry, keGroup uint16) []kexEntry {
	if current.group != keGroup {
		return s.rekeyable(current)
	}
	return promoted(s.rekeyable(current), current)
}

func promoted[T comparable](list []T, first T) []T {
	if !slices.Contains(list, first) {
		return list
	}
	return slices.Concat([]T{first}, slices.DeleteFunc(slices.Clone(list), func(t T) bool { return t == first }))
}

// wireCipher is a Child SA's cipher as a proposal carries it
// RFC 7296 section 3.3.5: "The Key Length attribute MUST NOT be used with transforms that use a fixed-length key."
func wireCipher(child ChildSA) Transform {
	bits := child.EncrKeyBits
	if child.EncrID == ENCR_CHACHA20_POLY1305 {
		bits = 0
	}
	return Transform{Type: TransEncr, ID: child.EncrID, KeyLengthBits: bits}
}

// choose is the first of preferred that offered holds
// RFC 7296 section 3.3: "If there is more than one, they MUST be ordered from most preferred to least preferred."
// RFC 7296 section 3.3: "If there are multiple transforms with the same Transform Type, the proposal is an OR of those transforms."
// RFC 7296 section 3.3.6: "If there are multiple proposals, the responder MUST choose a single proposal." and "If the selected proposal has multiple transforms with the same type, the responder MUST choose a single one."
// RFC 7296 section 2.7: "The responder MUST choose a single suite, which may be any subset of the SA proposal following the rules below."
// the order binds the sender of the proposals and leaves the choice to the responder
// so this end answers in each type with its own most preferred
func choose(preferred, offered []Transform) (Transform, bool) {
	for _, candidate := range preferred {
		if slices.Contains(offered, candidate) {
			return candidate, true
		}
	}
	return Transform{}, false
}

// combinedIntegrity is the integrity transform of NONE a proposal of combined-mode ciphers offers, nil where it offers no integrity transform
// acceptable is false where it offers integrity transforms and no NONE this end takes among them, or a Transform Type outside types and the ADDKE types
// RFC 7296 section 3.3: "Combined-mode ciphers include both integrity and encryption in a single encryption algorithm, and MUST either offer no integrity algorithm or a single integrity algorithm of "NONE", with no integrity algorithm being the RECOMMENDED method."
// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable" and "other transforms with the same Transform Type are processed as usual."
// RFC 7296 section 3.3.6: "If the responder receives a proposal that contains a Transform Type it does not understand, or a proposal that is missing a mandatory Transform Type, it MUST consider this proposal unacceptable" and "other proposals in the same SA payload are processed as usual."
func combinedIntegrity(transforms []Transform, types ...TransformType) (integ *Transform, acceptable bool) {
	offered := false
	for i, transform := range transforms {
		switch {
		case transform.Type == TransInteg:
			offered = true
			if integ == nil && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
				integ = &transforms[i]
			}
		case !slices.Contains(types, transform.Type) && !additional(transform.Type):
			return nil, false
		}
	}
	return integ, !offered || integ != nil
}

// kexChoice is the key exchange transforms an answer takes from the proposal it answers
type kexChoice struct {
	// dh is its Transform Type 4: a group, NONE where a Child SA's proposal offers it and runs none, or the zero Transform where the proposal offers no group
	dh Transform
	// additions holds one transform of each ADDKE type the proposal holds, in type order
	additions []Transform
}

// entry is the key exchanges the choice runs
func (c kexChoice) entry() kexEntry {
	entry := kexEntry{group: c.dh.ID}
	at := 0
	for _, addition := range c.additions {
		if addition.ID != 0 {
			entry.additions[at] = addition.ID
			at++
		}
	}
	return entry
}

// chooseKex is the proposal of offers an offer is answered in, as its index, and the key exchanges it takes
// offers are the transforms of each proposal the lists meet in every other type, in the offer's order
// the entry is the first of entries any of them takes, and the first of them taking it is answered
// a KE payload in another group than that entry's gets the group to ask for in INVALID_KE_PAYLOAD instead
// groupOptional holds for a Child SA's proposal, which may leave out a group or offer NONE, and such a proposal is answered without one ahead of every entry while the KE payload is absent and behind every entry while it is present
// RFC 7296 section 1.3: "If the responder selects a proposal using a different Diffie-Hellman group (other than NONE), the responder MUST reject the request and indicate its preferred Diffie-Hellman group in the INVALID_KE_PAYLOAD Notify payload."
// RFC 7296 section 3.3.6: "Responders MUST select a single complete set of parameters from the offers (or reject all offers if none are acceptable)."
func chooseKex(offers [][]Transform, entries []kexEntry, keGroup uint16, groupOptional bool) (int, kexChoice, uint16, bool) {
	withoutGroup := func() (int, kexChoice, bool) {
		for i, transforms := range offers {
			var offersGroup, offersNone bool
			for _, transform := range transforms {
				if transform.Type == TransDH {
					offersGroup = true
					offersNone = offersNone || transform == (Transform{Type: TransDH})
				}
			}
			additions, ok := takeAdditions(transforms, nil)
			switch {
			case !ok:
			case offersNone:
				return i, kexChoice{dh: Transform{Type: TransDH}, additions: additions}, true
			case !offersGroup:
				return i, kexChoice{additions: additions}, true
			}
		}
		return 0, kexChoice{}, false
	}
	if groupOptional && keGroup == 0 {
		if i, choice, ok := withoutGroup(); ok {
			return i, choice, 0, true
		}
	}
	for _, entry := range entries {
		group := Transform{Type: TransDH, ID: entry.group}
		for i, transforms := range offers {
			if !slices.Contains(transforms, group) {
				continue
			}
			additions, ok := takeAdditions(transforms, entry.added())
			if !ok {
				continue
			}
			if entry.group != keGroup {
				return 0, kexChoice{}, entry.group, false
			}
			return i, kexChoice{dh: group, additions: additions}, 0, true
		}
	}
	if groupOptional {
		if i, choice, ok := withoutGroup(); ok {
			return i, choice, 0, true
		}
	}
	return 0, kexChoice{}, 0, false
}

// takeAdditions is one transform of each ADDKE type transforms hold, in type order, carrying methods over those types in order and NONE in the rest
// where methods could sit in more than one way the earlier types carry them
// RFC 9370 section 2.2.1: "On the other hand, if the initiator includes any ADDKE Transform Type in the proposal, the responder MUST select one of the algorithms proposed using this type."
// RFC 9370 section 2.2.1: "However, for the ADDKE Transform Types, the responder's choice MUST NOT contain duplicated algorithms (those with an identical Transform ID and attributes), except for the Transform ID of NONE."
// a kex entry repeats no method, so no answer from one does
// RFC 9370 section 2.2.1: "The responder MUST treat all of the omitted ADDKE transforms as if they were proposed with Transform ID NONE."
func takeAdditions(transforms []Transform, methods []uint16) ([]Transform, bool) {
	var types []TransformType
	for _, transform := range transforms {
		if additional(transform.Type) && !slices.Contains(types, transform.Type) {
			types = append(types, transform.Type)
		}
	}
	slices.Sort(types)
	var take func(at int, left []uint16) ([]Transform, bool)
	take = func(at int, left []uint16) ([]Transform, bool) {
		if at == len(types) {
			return nil, len(left) == 0
		}
		candidates := []uint16{0}
		if len(left) > 0 {
			candidates = []uint16{left[0], 0}
		}
		for _, method := range candidates {
			chosen := Transform{Type: types[at], ID: method}
			if !slices.Contains(transforms, chosen) {
				continue
			}
			rest := left
			if method != 0 {
				rest = left[1:]
			}
			if tail, ok := take(at+1, rest); ok {
				return append([]Transform{chosen}, tail...), true
			}
		}
		return nil, false
	}
	return take(0, methods)
}

// holdsIKE reports whether the lists still hold every transform of an IKE SA's suite, the entry of all its key exchanges among them
func (s Suites) holdsIKE(suite SASuite) bool {
	return slices.Contains(s.ikeCiphers(), Transform{Type: TransEncr, ID: suite.EncrID, KeyLengthBits: suite.EncrKeyBits}) &&
		s.holdsPRF(suite.PRFID) &&
		slices.Contains(s.kexEntries(), suite.entry())
}

func (s Suites) holdsPRF(prfID uint16) bool {
	return slices.Contains(s.ikePRFs(), Transform{Type: TransPRF, ID: prfID})
}

// holdsChild reports whether the lists still hold a Child SA's cipher and, for keys key exchanges of its own made, the entry of those exchanges
func (s Suites) holdsChild(child ChildSA, entry kexEntry) bool {
	return slices.Contains(s.espCiphers(), wireCipher(child)) &&
		(entry == kexEntry{} || slices.Contains(s.kexEntries(), entry))
}

// keyedEntry ties a kex entry to the local SPI of the Child SA its key exchanges keyed
type keyedEntry struct {
	spi   uint32
	entry kexEntry
}

func (s *Session) lists() Suites { return current(s.suites) }

// SuitesChanged asks Run to check each SA against the lists in force
// it never blocks
// an SA holding a cipher or a kex entry they left out is rekeyed after a delay drawn within the rekey jitter
// and no later than the rekey its schedule already holds
// a Child SA whose IKE SA also holds a cipher or a kex entry they left out draws its delay once that IKE SA's rekey has ended, unless an earlier check already drew one
// an IKE SA whose PRF they left out is deleted for a new handshake
func (s *Session) SuitesChanged() {
	select {
	case s.rechecks <- struct{}{}:
	default:
	}
}

// ErrPRFUnlisted ends a session whose IKE SA keeps a PRF cap.crypto ike prf no longer holds
// no rekey changes the PRF
// so the session deletes the SA and a new handshake under the lists in force replaces it
var ErrPRFUnlisted = errors.New("ike: cap.crypto ike prf no longer holds the IKE SA's PRF, which no rekey changes")

// Suite is the transforms a session's SAs use, each by the name cap.crypto lists it under
type Suite struct {
	IKECipher, IKEPRF, IKEKex string
	// ESPCipher is empty while the session holds no Child SA
	ESPCipher string
	// ESPKex is the kex entry of the Child SA's own key exchanges
	// it is empty for a Child SA SK_d alone keyed
	ESPKex string
}

// IKE is the IKE SA's cipher, PRF and kex entry joined by /
// it is empty for a session no handshake built
func (s Suite) IKE() string {
	if s.IKECipher == "" {
		return ""
	}
	return s.IKECipher + "/" + s.IKEPRF + "/" + s.IKEKex
}

// ESP is the Child SA's cipher, with the kex entry of its own key exchanges after a / where it ran any
func (s Suite) ESP() string {
	if s.ESPKex == "" {
		return s.ESPCipher
	}
	return s.ESPCipher + "/" + s.ESPKex
}

// Suite is the transforms the session's SAs use now
// it is empty for a Session no handshake built
func (s *Session) Suite() Suite {
	var suite Suite
	if current := s.currentContext(); current != nil {
		suite = ikeSuite(current.suite)
	}
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	suite.ESPCipher, suite.ESPKex = childSuite(s.Child, s.childEntryLocked())
	return suite
}

// childEntryLocked is the entry of the key exchanges that keyed the Child SA, or the zero entry, with childMu held
func (s *Session) childEntryLocked() kexEntry {
	if s.childKex.spi != s.Child.LocalSPI {
		return kexEntry{}
	}
	return s.childKex.entry
}

// unlisted names the suite of each SA holding a transform the lists in force left out
// it is empty for an SA they hold
// prf reports that the IKE SA's PRF is among those left out
func (s *Session) unlisted() (child, ikeSA string, prf bool) {
	if s.suites == nil {
		return "", "", false
	}
	lists := s.suites()
	if suite := s.currentContext().suite; !lists.holdsIKE(suite) {
		ikeSA, prf = ikeSuite(suite).IKE(), !lists.holdsPRF(suite.PRFID)
	}
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	if entry := s.childEntryLocked(); s.Child.LocalSPI != 0 && !lists.holdsChild(s.Child, entry) {
		cipher, kex := childSuite(s.Child, entry)
		child = Suite{ESPCipher: cipher, ESPKex: kex}.ESP()
	}
	return child, ikeSA, prf
}

func transformName(t Transform) string {
	for _, table := range [][]suiteName{cipherNames, prfNames, kexNames, postQuantumNames} {
		for _, named := range table {
			if named.transform == t {
				return named.name
			}
		}
	}
	return fmt.Sprintf("%d:%d", t.Type, t.ID)
}

// ikeSuite is an IKE SA's cipher, PRF and kex entry by the names cap.crypto gives them
func ikeSuite(suite SASuite) Suite {
	return Suite{
		IKECipher: transformName(Transform{Type: TransEncr, ID: suite.EncrID, KeyLengthBits: suite.EncrKeyBits}),
		IKEPRF:    transformName(Transform{Type: TransPRF, ID: suite.PRFID}),
		IKEKex:    kexName(suite.entry()),
	}
}

// RFC 9370 section 2.2.1: "The allowed Transform IDs for these transform types are the same as the IDs for Transform Type 4, so they all share a single IANA registry for Transform IDs."
func kexName(entry kexEntry) string {
	names := []string{transformName(Transform{Type: TransDH, ID: entry.group})}
	for _, method := range entry.added() {
		names = append(names, transformName(Transform{Type: TransDH, ID: method}))
	}
	return strings.Join(names, "+")
}

// childSuite is a Child SA's cipher by its cap.crypto name, and the kex entry of key exchanges of its own
func childSuite(child ChildSA, entry kexEntry) (cipher, kex string) {
	if child.LocalSPI == 0 {
		return "", ""
	}
	cipher = transformName(wireCipher(child))
	if entry != (kexEntry{}) {
		kex = kexName(entry)
	}
	return cipher, kex
}
