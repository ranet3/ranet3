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
	// an entry of Kex joins key exchanges with +
	// the first runs in IKE_SA_INIT and each after it as one more exchange
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
	// postQuantumKex runs only joined after a classical key exchange
	postQuantumKex = []string{"mlkem512", "mlkem768", "mlkem1024"}
)

// Suites is the four cap.crypto lists as transforms, each most preferred first
// a nil list holds every name of its kind
// so the zero Suites is a node that writes none of them
type Suites struct {
	ikeCipher, ikePRF, kex, espCipher []Transform
}

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
func resolveKex(list []string) ([]Transform, error) {
	if list == nil {
		return nil, nil
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("ike: cap.crypto ike kex is empty, which leaves nothing to negotiate")
	}
	classical := namesOf(kexNames)
	out := make([]Transform, 0, len(list))
	for i, entry := range list {
		if slices.Contains(list[:i], entry) {
			return nil, fmt.Errorf("ike: cap.crypto ike kex names %s twice", entry)
		}
		parts := strings.Split(entry, "+")
		for _, part := range parts {
			if slices.Contains(classical, part) || slices.Contains(postQuantumKex, part) {
				continue
			}
			if len(parts) == 1 {
				return nil, fmt.Errorf("ike: cap.crypto ike kex names %q, which is not one of %s", entry, spelled(classical))
			}
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q names %q, which is not one of %s",
				entry, part, spelled(slices.Concat(classical, postQuantumKex)))
		}
		if slices.Contains(postQuantumKex, parts[0]) {
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q starts with %s, which runs only after a classical key exchange, as in x25519+%s",
				entry, parts[0], parts[0])
		}
		if len(parts) > 1 {
			return nil, fmt.Errorf("ike: cap.crypto ike kex entry %q joins key exchanges, and the additional key exchanges of RFC 9370 are not implemented", entry)
		}
		out = append(out, kexNames[slices.Index(classical, entry)].transform)
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
func (s Suites) kexGroups() []Transform  { return listed(s.kex, kexNames) }
func (s Suites) espCiphers() []Transform { return listed(s.espCipher, cipherNames) }

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
		key     string
		was, is []Transform
	}{
		{"cap.crypto.ike.cipher", s.ikeCiphers(), next.ikeCiphers()},
		{"cap.crypto.ike.prf", s.ikePRFs(), next.ikePRFs()},
		{"cap.crypto.ike.kex", s.kexGroups(), next.kexGroups()},
		{"cap.crypto.esp.cipher", s.espCiphers(), next.espCiphers()},
	} {
		if !slices.Equal(list.was, list.is) {
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

// ikeProposal is the IKE_SA_INIT offer with its KE payload in group, every listed transform in list order but group first
// RFC 7296 section 3.4: "This Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified in a proposal in the SA payload that is sent in the same message, and SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
// RFC 7296 section 1.2: "The initiator MUST again propose its full set of acceptable cryptographic suites because the rejection message was unauthenticated and otherwise an active attacker could trick the endpoints into negotiating a weaker suite than a stronger one that they both prefer."
func (s Suites) ikeProposal(group uint16) Proposal {
	return Proposal{Number: 1, Protocol: ProtoIKE, Transforms: slices.Concat(s.ikeCiphers(), s.ikePRFs(), s.leadingGroup(group))}
}

// ikeRekeyProposal is the offer of a rekey replacing an IKE SA whose PRF is prfID, with its KE payload in group
func (s Suites) ikeRekeyProposal(spi []byte, prfID, group uint16) Proposal {
	return Proposal{Number: 1, Protocol: ProtoIKE, SPI: spi,
		Transforms: slices.Concat(s.ikeCiphers(), s.rekeyPRFs(prfID), s.leadingGroup(group))}
}

// leadingGroup is the kex groups with group first and the rest in list order, the order every IKE SA offer this end sends lists them in
// RFC 7296 section 3.4 on the KE payload's group: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
func (s Suites) leadingGroup(group uint16) []Transform {
	return promoted(s.kexGroups(), Transform{Type: TransDH, ID: group})
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

// rekeyGroups is the order this end answers a peer's rekey in, for an SA keyed in group current
// that group comes first while kex holds it and the KE payload is in it
// so a rekey between ends whose lists order the groups differently keeps the group and asks for no other
// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
func (s Suites) rekeyGroups(current, keGroup uint16) []Transform {
	if current != keGroup {
		return s.kexGroups()
	}
	return promoted(s.kexGroups(), Transform{Type: TransDH, ID: current})
}

func promoted(list []Transform, first Transform) []Transform {
	if !slices.Contains(list, first) {
		return list
	}
	return slices.Concat([]Transform{first}, slices.DeleteFunc(slices.Clone(list), func(t Transform) bool { return t == first }))
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

// groupRule tells chooseGroup whether an answer may go without a group
type groupRule int

const (
	// an IKE SA's group, in IKE_SA_INIT and in its rekey
	// RFC 7296 section 2.18: "an initiator MUST NOT propose the value "NONE" for the Diffie-Hellman transform, and a responder MUST NOT accept such a proposal."
	groupRequired groupRule = iota
	// a Child SA's group, which a proposal may leave out or offer as NONE
	groupOptional
)

// chooseGroup is the proposal of offers an offer is answered in, as its index, and the group it takes
// offers are the transforms of each proposal the lists meet in every other type, in the offer's order
// the group is the first of groups any of them holds, and the first of them holding it is answered
// a KE payload in another group gets the group to ask for in INVALID_KE_PAYLOAD instead
// a Child SA's proposal offering NONE or no group is answered without one ahead of every group while the KE payload is absent and behind every group while it is present
// RFC 7296 section 1.3: "If the responder selects a proposal using a different Diffie-Hellman group (other than NONE), the responder MUST reject the request and indicate its preferred Diffie-Hellman group in the INVALID_KE_PAYLOAD Notify payload."
// RFC 7296 section 3.3.6: "Responders MUST select a single complete set of parameters from the offers (or reject all offers if none are acceptable)."
func chooseGroup(offers [][]Transform, groups []Transform, keGroup uint16, rule groupRule) (int, Transform, uint16, bool) {
	withoutGroup := func() (int, Transform, bool) {
		for i, transforms := range offers {
			var offersGroup, offersNone bool
			for _, transform := range transforms {
				if transform.Type == TransDH {
					offersGroup = true
					offersNone = offersNone || transform == (Transform{Type: TransDH})
				}
			}
			if offersNone {
				return i, Transform{Type: TransDH}, true
			}
			if !offersGroup {
				return i, Transform{}, true
			}
		}
		return 0, Transform{}, false
	}
	if rule == groupOptional && keGroup == 0 {
		if i, none, ok := withoutGroup(); ok {
			return i, none, 0, true
		}
	}
	for _, group := range groups {
		for i, transforms := range offers {
			if !slices.Contains(transforms, group) {
				continue
			}
			if group.ID != keGroup {
				return 0, Transform{}, group.ID, false
			}
			return i, group, 0, true
		}
	}
	if rule == groupOptional {
		if i, none, ok := withoutGroup(); ok {
			return i, none, 0, true
		}
	}
	return 0, Transform{}, 0, false
}

// holdsIKE reports whether the lists still hold every transform of an IKE SA's suite
func (s Suites) holdsIKE(suite SASuite) bool {
	return slices.Contains(s.ikeCiphers(), Transform{Type: TransEncr, ID: suite.EncrID, KeyLengthBits: suite.EncrKeyBits}) &&
		s.holdsPRF(suite.PRFID) &&
		slices.Contains(s.kexGroups(), Transform{Type: TransDH, ID: suite.DHGroup})
}

func (s Suites) holdsPRF(prfID uint16) bool {
	return slices.Contains(s.ikePRFs(), Transform{Type: TransPRF, ID: prfID})
}

// holdsChild reports whether the lists still hold a Child SA's cipher and, for keys a key exchange of its own made, its group
func (s Suites) holdsChild(child ChildSA, group uint16) bool {
	return slices.Contains(s.espCiphers(), wireCipher(child)) &&
		(group == 0 || slices.Contains(s.kexGroups(), Transform{Type: TransDH, ID: group}))
}

type childPFS struct {
	spi   uint32
	group uint16
}

func (s *Session) lists() Suites { return current(s.suites) }

// SuitesChanged asks Run to check each SA against the lists in force
// it never blocks
// an SA holding a cipher or a group they left out is rekeyed after a delay drawn within the rekey jitter
// and no later than the rekey its schedule already holds
// a Child SA whose IKE SA they left out as well draws its delay once that IKE SA's rekey has ended, unless an earlier check already drew one
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
	// ESPKex is the group of the Child SA's own key exchange
	// it is empty for a Child SA SK_d alone keyed
	ESPKex string
}

// IKE is the IKE SA's cipher, PRF and group joined by /
// it is empty for a session no handshake built
func (s Suite) IKE() string {
	if s.IKECipher == "" {
		return ""
	}
	return s.IKECipher + "/" + s.IKEPRF + "/" + s.IKEKex
}

// ESP is the Child SA's cipher, with the group of its own key exchange after a / where it ran one
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
	suite.ESPCipher, suite.ESPKex = childSuite(s.Child, s.childGroupLocked())
	return suite
}

// childGroupLocked is the group of the key exchange that keyed the Child SA, or zero, with childMu held
func (s *Session) childGroupLocked() uint16 {
	if s.childGroup.spi != s.Child.LocalSPI {
		return 0
	}
	return s.childGroup.group
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
	if group := s.childGroupLocked(); s.Child.LocalSPI != 0 && !lists.holdsChild(s.Child, group) {
		cipher, kex := childSuite(s.Child, group)
		child = Suite{ESPCipher: cipher, ESPKex: kex}.ESP()
	}
	return child, ikeSA, prf
}

func transformName(t Transform) string {
	for _, table := range [][]suiteName{cipherNames, prfNames, kexNames} {
		for _, named := range table {
			if named.transform == t {
				return named.name
			}
		}
	}
	return fmt.Sprintf("%d:%d", t.Type, t.ID)
}

// ikeSuite is an IKE SA's cipher, PRF and group by the names cap.crypto gives them
func ikeSuite(suite SASuite) Suite {
	return Suite{
		IKECipher: transformName(Transform{Type: TransEncr, ID: suite.EncrID, KeyLengthBits: suite.EncrKeyBits}),
		IKEPRF:    transformName(Transform{Type: TransPRF, ID: suite.PRFID}),
		IKEKex:    transformName(Transform{Type: TransDH, ID: suite.DHGroup}),
	}
}

// childSuite is a Child SA's cipher by its cap.crypto name, and the group of a key exchange of its own
func childSuite(child ChildSA, group uint16) (cipher, kex string) {
	if child.LocalSPI == 0 {
		return "", ""
	}
	cipher = transformName(wireCipher(child))
	if group != 0 {
		kex = transformName(Transform{Type: TransDH, ID: group})
	}
	return cipher, kex
}
