// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// keyTexts is the texts the walk looks for a key as. They are the octets
// themselves, hex in either case with and without a space between octets,
// base64 in either alphabet with and without padding, the list of numbers fmt
// prints with and without its brackets and with commas between the numbers,
// fmt's %#v and %q of the octets without what encloses them, and base64 in
// either alphabet of the longest run of whole 3-octet groups from the key's
// first, second and third octet. Base64 in either alphabet of a longer run of
// octets that holds the key holds one of those six, whatever the key's offset
// in the run, where no line break falls inside it. A longer slice printed by
// fmt's %v or %#v holds the unenclosed text of the key's own, and so does a
// longer string printed by %q unless an octet beside the key makes one UTF-8
// character with the key's first or last octet.
func keyTexts(key []byte) []string {
	numbers := strings.Trim(fmt.Sprint(key), "[]")
	goSyntax, quoted := fmt.Sprintf("%#v", key), fmt.Sprintf("%q", key)
	texts := []string{
		string(key),
		hex.EncodeToString(key), strings.ToUpper(hex.EncodeToString(key)),
		fmt.Sprintf("% x", key), fmt.Sprintf("% X", key),
		base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key),
		fmt.Sprint(key), numbers, strings.ReplaceAll(numbers, " ", ","),
		goSyntax[strings.Index(goSyntax, "{")+1 : len(goSyntax)-1], quoted[1 : len(quoted)-1],
	}
	for skip := range 3 {
		groups := key[skip:][:(len(key)-skip)/3*3]
		texts = append(texts, base64.RawStdEncoding.EncodeToString(groups), base64.RawURLEncoding.EncodeToString(groups))
	}
	return texts
}

// keyAt is where under v, named at, one of texts sits inside a string, a
// map's key or a run of bytes, empty where none does. It reads every exported
// field, element, map key and value. It names a map's entry by its place among
// the entries sorted by how fmt prints their keys, and never by its key, which
// can hold a key's text.
func keyAt(v reflect.Value, texts []string, at string) string {
	switch v.Kind() {
	case reflect.String:
		for _, text := range texts {
			if strings.Contains(v.String(), text) {
				return at
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return keyAt(v.Elem(), texts, at)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			octets := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(octets), v)
			return keyAt(reflect.ValueOf(string(octets)), texts, at)
		}
		for i := range v.Len() {
			if found := keyAt(v.Index(i), texts, fmt.Sprintf("%s[%d]", at, i)); found != "" {
				return found
			}
		}
	case reflect.Map:
		entries := v.MapKeys()
		slices.SortFunc(entries, func(a, b reflect.Value) int { return strings.Compare(fmt.Sprint(a), fmt.Sprint(b)) })
		for i, entry := range entries {
			name := fmt.Sprintf("%s[entry %d of %d]", at, i+1, len(entries))
			if found := keyAt(entry, texts, name+"'s key"); found != "" {
				return found
			}
			if found := keyAt(v.MapIndex(entry), texts, name); found != "" {
				return found
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if field := v.Type().Field(i); field.IsExported() {
				if found := keyAt(v.Field(i), texts, at+"."+field.Name); found != "" {
					return found
				}
			}
		}
	}
	return ""
}

// stateField is v's field name, which must be of type want where want is not nil
func stateField(t *testing.T, v reflect.Value, name string, want reflect.Type) reflect.Value {
	t.Helper()
	found := v.FieldByName(name)
	if !found.IsValid() {
		t.Fatalf("%s holds no field %s", v.Type(), name)
	}
	if want != nil && found.Type() != want {
		t.Fatalf("%s's field %s is of type %s, not %s", v.Type(), name, found.Type(), want)
	}
	return found
}

// ikeParts are the fields of an IKE SA's context that hold its keys, by the
// names of RFC 7296 section 2.14
var ikeParts = []struct{ field, name string }{{"skD", "SK_d"}, {"skei", "SK_ei"}, {"sker", "SK_er"}, {"skpi", "SK_pi"}, {"skpr", "SK_pr"}}

// ikeContext calls read with the IKE SA that the field which of node's
// session holds, current or old, while it holds the session's state lock. It
// passes the nil pointer where the field holds no SA.
func ikeContext(t *testing.T, node *loopbackNode, which string, read func(sa reflect.Value)) {
	t.Helper()
	held := node.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("%s holds %d sessions, want the one alpha dialed", node.name, len(held))
	}
	session := reflect.ValueOf(held[0].session).Elem()
	lock := (*sync.RWMutex)(unsafe.Pointer(stateField(t, session, "stateMu", reflect.TypeFor[sync.RWMutex]()).UnsafeAddr()))
	lock.RLock()
	defer lock.RUnlock()
	sa := stateField(t, session, which, nil)
	if sa.Kind() != reflect.Pointer || sa.Type().Elem().Kind() != reflect.Struct {
		t.Fatalf("%s's field %s is of type %s, not a pointer to an IKE SA", session.Type(), which, sa.Type())
	}
	read(sa)
}

// contextKeys is the keys of the IKE SA the field which of node's session
// holds, each by its name in ikeParts, and the keying material the five are cut
// from, nil where the field holds no SA. A field of bytes that the SA's context
// holds directly and ikeParts does not name fails the test.
func contextKeys(t *testing.T, node *loopbackNode, which string) map[string][]byte {
	t.Helper()
	var keys map[string][]byte
	ikeContext(t, node, which, func(sa reflect.Value) {
		if sa.IsNil() {
			return
		}
		context := sa.Elem()
		for i := range context.NumField() {
			field := context.Type().Field(i)
			bytesField := (field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array) && field.Type.Elem().Kind() == reflect.Uint8
			if bytesField && !slices.ContainsFunc(ikeParts, func(part struct{ field, name string }) bool { return part.field == field.Name }) {
				t.Fatalf("%s's IKE SA holds the bytes of field %s, which the walk does not look for", node.name, field.Name)
			}
		}
		keys = map[string][]byte{}
		var material []byte
		for _, part := range ikeParts {
			octets := stateField(t, context, part.field, reflect.TypeFor[[]byte]()).Bytes()
			keys[part.name], material = octets, append(material, octets...)
		}
		keys["keying material"] = material
	})
	return keys
}

// ikeKeys is the keys of the IKE SA that alpha and bravo hold as current, as
// contextKeys gives them. An AEAD suite, the one kind ike negotiates, has SK_ai
// and SK_ar of zero octets, by RFC 5282 section 7.1 for AES-GCM and RFC 7634
// section 3 for ChaCha20-Poly1305. The test fails unless both ends hold the
// same keys and none is empty.
func ikeKeys(t *testing.T, alpha, bravo *loopbackNode) map[string][]byte {
	t.Helper()
	ends := [2]map[string][]byte{contextKeys(t, alpha, "current"), contextKeys(t, bravo, "current")}
	for i, node := range []*loopbackNode{alpha, bravo} {
		if ends[i] == nil {
			t.Fatalf("%s's session holds no IKE SA", node.name)
		}
	}
	for name, key := range ends[0] {
		if len(key) == 0 || !bytes.Equal(key, ends[1][name]) {
			t.Fatalf("alpha and bravo hold %s of %d and %d octets, not one key of the IKE SA", name, len(key), len(ends[1][name]))
		}
	}
	return ends[0]
}

// keyFile is the PKCS #8 DER of node's private key and the base64 body of the
// PEM in node's key file, with the file's line breaks. The test fails unless
// the file's PEM holds that DER.
func keyFile(t *testing.T, node *loopbackNode) (der, body []byte) {
	t.Helper()
	file, err := os.ReadFile(node.cfg.Auth.Key)
	if err != nil {
		t.Fatal(err)
	}
	if der, err = x509.MarshalPKCS8PrivateKey(node.client.privateKey); err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(file); block == nil || !bytes.Equal(block.Bytes, der) {
		t.Fatalf("%s's key file holds no PEM of its key's PKCS #8 DER", node.name)
	}
	_, text, _ := strings.Cut(string(file), "\n")
	text, _, _ = strings.Cut(text, "-----END")
	return der, []byte(strings.TrimSpace(text))
}

// deleteRelay carries every datagram between alpha and bravo, alpha sending to
// it in place of bravo's port. Once armed with an IKE SA's SPIs and once bravo
// has answered a CREATE_CHILD_SA on that SA, it keeps from bravo each
// INFORMATIONAL request alpha sends on that SA until release, which sends bravo
// what it kept. Alpha makes the replacement current before it sends the Delete
// of the replaced SA, the last request on it by RFC 7296 section 2.8, so the
// relay keeps that Delete and its resend unless a liveness check started on
// that SA between bravo's answer and that switch. Bravo holds the replaced SA
// until it has the Delete, and alpha until the Delete is answered or its two
// sends go unanswered.
type deleteRelay struct {
	alphaSide, bravoSide *net.UDPConn
	bravo                *net.UDPAddr
	// caught is closed once the first request is kept
	caught chan struct{}

	mu                        sync.Mutex
	alpha                     *net.UDPAddr
	spis                      [2]uint64
	armed, answered, released bool
	kept                      [][]byte
}

// newDeleteRelay starts the relay and stores in alpha a trust index that names
// the relay in place of bravo's endpoint, so it must run before either node
// does
func newDeleteRelay(t *testing.T, alpha, bravo *loopbackNode) *deleteRelay {
	t.Helper()
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	alphaSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	bravoSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	r := &deleteRelay{alphaSide: alphaSide, bravoSide: bravoSide, bravo: &net.UDPAddr{IP: loopback.IP, Port: int(bravo.port)}, caught: make(chan struct{})}
	raw, err := os.ReadFile(alpha.cfg.Auth.Trust)
	if err != nil {
		t.Fatal(err)
	}
	var document registry.Registry
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	moved := false
	for _, organization := range document {
		for _, node := range organization.Nodes {
			if node.CommonName == bravo.name {
				node.Endpoints[0].Port, moved = uint16(alphaSide.LocalAddr().(*net.UDPAddr).Port), true
			}
		}
	}
	if !moved {
		t.Fatalf("alpha's trust document names no %s", bravo.name)
	}
	alpha.client.storeIndex(trust(t, document))
	var relaying sync.WaitGroup
	relaying.Go(r.fromAlpha)
	relaying.Go(r.fromBravo)
	t.Cleanup(func() {
		_ = alphaSide.Close()
		_ = bravoSide.Close()
		relaying.Wait()
	})
	return r
}

// matches is whether datagram is an IKE message on the armed SA of the
// exchange given, a response or a request as response says
func (r *deleteRelay) matches(datagram []byte, exchange ike.ExchangeType, response bool) bool {
	// the four zero octets of RFC 3948 section 2.2 come before an IKE header
	if !r.armed || len(datagram) < 4+ike.HeaderLen || binary.BigEndian.Uint32(datagram) != 0 {
		return false
	}
	header := datagram[4:]
	return binary.BigEndian.Uint64(header) == r.spis[0] && binary.BigEndian.Uint64(header[8:]) == r.spis[1] &&
		ike.ExchangeType(header[18]) == exchange && (header[19]&ike.FlagResponse != 0) == response
}

func (r *deleteRelay) fromAlpha() {
	buf := make([]byte, 65536)
	for {
		n, from, err := r.alphaSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.alpha = from
		keep := r.answered && !r.released && r.matches(buf[:n], ike.INFORMATIONAL, false)
		if keep {
			if len(r.kept) == 0 {
				close(r.caught)
			}
			r.kept = append(r.kept, bytes.Clone(buf[:n]))
		}
		r.mu.Unlock()
		if !keep {
			_, _ = r.bravoSide.WriteToUDP(buf[:n], r.bravo)
		}
	}
}

func (r *deleteRelay) fromBravo() {
	buf := make([]byte, 65536)
	for {
		n, _, err := r.bravoSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.matches(buf[:n], ike.CREATE_CHILD_SA, true) {
			r.answered = true
		}
		alpha := r.alpha
		r.mu.Unlock()
		if alpha != nil {
			_, _ = r.alphaSide.WriteToUDP(buf[:n], alpha)
		}
	}
}

func (r *deleteRelay) arm(spiI, spiR uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spis, r.armed = [2]uint64{spiI, spiR}, true
}

func (r *deleteRelay) release() {
	r.mu.Lock()
	r.released = true
	kept := r.kept
	r.mu.Unlock()
	for _, datagram := range kept {
		_, _ = r.bravoSide.WriteToUDP(datagram, r.bravo)
	}
}

// no debug view of either end of a live session, the events among them, holds
// in any string, map key or run of bytes any key the keys map below collects,
// in any spelling keyTexts gives. The views are read twice, first while each
// end still holds the IKE SA a rekey replaced, which the test checks at each
// end once its views are read, and then once both have dropped it. A debug path
// the daemon serves that is neither walked nor left out with its reason fails,
// so a new view joins the walk. The paths left out must be probe and trace
// alone, the two the promise at the top of development/debug.md leaves out.
func TestDebugViewsCarryNoKeyOfALiveSession(t *testing.T) {
	leftOut := map[string]string{
		control.PathDebugProbe: "it asks the sessions to prove their path and answers with the call's result, not a state the node holds",
		control.PathDebugTrace: "it streams each packet's forwarding decision as the node makes it, not a state the node holds",
	}
	for _, path := range slices.Sorted(maps.Keys(leftOut)) {
		if path != control.PathDebugProbe && path != control.PathDebugTrace {
			t.Errorf("%s is left out of the walk, while the promise at the top of development/debug.md leaves out probe and trace alone", path)
		}
	}
	for _, path := range []string{control.PathDebugProbe, control.PathDebugTrace} {
		if _, left := leftOut[path]; !left {
			t.Errorf("%s is not left out of the walk, while the promise at the top of development/debug.md names it as outside", path)
		}
	}
	walked := map[string]bool{}
	alpha, bravo := newLoopbackMeshKeyed(t)
	// bravo answers and never dials, so both ends hold the one session alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	relay := newDeleteRelay(t, alpha, bravo)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})
	held := alpha.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("alpha holds %d sessions, want the one it dialed", len(held))
	}
	replaced := held[0].session.Child()
	if err := held[0].session.RekeyChild(); err != nil {
		t.Fatalf("alpha could not rekey its session: %v", err)
	}
	child := held[0].session.Child()
	if child.LocalSPI == replaced.LocalSPI {
		t.Fatalf("the rekey left the Child SA of SPI %08x in place", child.LocalSPI)
	}
	replacedIKE := ikeKeys(t, alpha, bravo)
	ikeContext(t, alpha, "current", func(sa reflect.Value) {
		spi := reflect.TypeFor[uint64]()
		relay.arm(stateField(t, sa.Elem(), "spiI", spi).Uint(), stateField(t, sa.Elem(), "spiR", spi).Uint())
	})
	rekeyed := make(chan error, 1)
	go func() { rekeyed <- held[0].session.RekeyIKE() }()
	select {
	case <-relay.caught:
	case err := <-rekeyed:
		t.Fatalf("alpha's IKE SA rekey ended before it sent the Delete of the SA it replaced: %v", err)
	case <-time.After(convergeBudget):
		t.Fatal("alpha sent no Delete of the IKE SA its rekey replaced")
	}
	liveIKE := ikeKeys(t, alpha, bravo)
	if bytes.Equal(liveIKE["SK_d"], replacedIKE["SK_d"]) {
		t.Fatal("the IKE SA rekey left SK_d in place")
	}
	if alpha.client.privateKey.Equal(bravo.client.privateKey) {
		t.Fatal("alpha and bravo run on one private key")
	}
	keys := map[string][]byte{}
	for _, node := range []*loopbackNode{alpha, bravo} {
		role, _, _ := strings.Cut(node.name, "-")
		keys[role+"'s private key"], keys[role+"'s private key's seed"] = node.client.privateKey, node.client.privateKey.Seed()
		keys[role+"'s private key's PKCS #8 DER"], keys[role+"'s key file's PEM body"] = keyFile(t, node)
	}
	for name, key := range map[string][]byte{
		"the Child SA's inbound key": child.InboundKey, "the Child SA's outbound key": child.OutboundKey,
		"the replaced Child SA's inbound key": replaced.InboundKey, "the replaced Child SA's outbound key": replaced.OutboundKey,
	} {
		keys[name], keys[name+" less its salt"] = key, key[:len(key)-4]
	}
	for owner, derived := range map[string]map[string][]byte{"the IKE SA's": liveIKE, "the replaced IKE SA's": replacedIKE} {
		for name, key := range derived {
			keys[owner+" "+name] = key
		}
		for _, name := range []string{"SK_ei", "SK_er"} {
			keys[owner+" "+name+" less its salt"] = derived[name][:len(derived[name])-4]
		}
	}
	walk := func(holding bool) {
		moment := "neither end holds the replaced IKE SA"
		if holding {
			moment = "both ends hold the replaced IKE SA"
		}
		for _, node := range []*loopbackNode{alpha, bravo} {
			c := node.client
			peer := c.sessions.snapshot()
			if len(peer) != 1 {
				t.Fatalf("%s holds %d sessions, want the one alpha dialed", node.name, len(peer))
			}
			other := alpha
			if node == alpha {
				other = bravo
			}
			route, err := c.DebugRoute(other.prefix.Addr().Next(), node.prefix.Addr().Next(), "", peer[0].path)
			if err != nil {
				t.Fatalf("%s's route view of a packet from %s: %v", node.name, peer[0].path, err)
			}
			views := map[string]any{
				control.PathDebugEgress:   c.DebugEgress(),
				control.PathDebugEvents:   c.DebugEvents(control.EventQuery{}),
				control.PathDebugNetmon:   c.DebugNetmon(),
				control.PathDebugPMTU:     c.DebugPMTU(""),
				control.PathDebugRoute:    route,
				control.PathDebugRules:    c.DebugRules(),
				control.PathDebugRuntime:  c.DebugRuntime(),
				control.PathDebugSegments: c.DebugSegments(),
				control.PathDebugSender:   c.DebugSender(""),
				control.PathDebugUpDown:   c.DebugUpDown(),
			}
			// an end holds the replaced SA from before the walk, drops it once
			// and never takes it back, so one held after the reads was held
			// during them
			if retained := contextKeys(t, node, "old"); holding && !maps.EqualFunc(retained, replacedIKE, bytes.Equal) {
				t.Fatalf("%s no longer holds the IKE SA the rekey replaced once its views are read", node.name)
			}
			for path, view := range views {
				walked[path] = true
				for name, key := range keys {
					if at := keyAt(reflect.ValueOf(view), keyTexts(key), "answer"); at != "" {
						t.Errorf("%s's %s carries %s at %s while %s", node.name, path, name, at, moment)
					}
				}
			}
		}
	}
	walk(true)
	relay.release()
	if err := <-rekeyed; err != nil {
		t.Fatalf("alpha could not rekey its IKE SA: %v", err)
	}
	waitFor(t, convergeBudget, "both ends dropping the IKE SA the rekey replaced", func() bool {
		return contextKeys(t, alpha, "old") == nil && contextKeys(t, bravo, "old") == nil
	})
	walk(false)
	for path := range control.DebugPaths() {
		if _, left := leftOut[path]; !walked[path] && !left {
			t.Errorf("%s is served, and the walk neither reads it nor leaves it out with its reason", path)
		}
	}
}
