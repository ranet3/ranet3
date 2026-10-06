// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/schema"
)

// A file spells a link quality as etx or none and nothing else. Any other
// value passed Validate, and then the speaker ran it as none while the
// marshaller wrote it as etx, so the file a node renders describes another
// speaker than the one it runs.
func TestValidateRefusesALinkQualityWithNoSpelling(t *testing.T) {
	for _, quality := range []LinkQuality{LinkQualityETX, LinkQualityNone} {
		if err := (Config{Quality: quality}).Validate(); err != nil {
			t.Errorf("quality %s was refused: %v", quality, err)
		}
	}
	for _, quality := range []LinkQuality{2, 255} {
		if err := (Config{Quality: quality}).Validate(); err == nil {
			t.Errorf("quality %d was accepted", quality)
		}
	}
}

// a link quality written as a list or a mapping is refused with its line
// the scalar half took the empty text such a node leaves for the default, so quality: [none] ran as etx
func TestQualityWrittenAsAListOrAMappingIsRefused(t *testing.T) {
	for _, written := range []string{"[none]", "{ none: true }", "[]", "{}"} {
		var c Config
		err := yaml.Unmarshal([]byte("quality: "+written+"\n"), &c)
		if err == nil {
			t.Errorf("quality: %s was taken as %s", written, c.Quality)
			continue
		}
		if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("quality: %s was refused with %q, which names no line", written, err)
		}
	}
}

// an announcement carrying a source is advertised under that source
// an exit announcing a default from its own transit prefix sent every peer a plain default, which each of them took for every source
func TestAnnouncementCarryingASourceReachesThePeerWithIt(t *testing.T) {
	dest, source := netip.MustParsePrefix("::/0"), netip.MustParsePrefix("2001:db8::/48")
	announced := Routes{Announce: []schema.Announce{{Prefix: schema.PrefixFrom(dest), From: schema.PrefixFrom(source)}}}
	fabric := newRoutedFabric(t, Config{}, announced, "a-b")
	fabric.flush("a", "b")
	var sources []netip.Prefix
	for _, update := range updatesFor(t, fabric.tlvs("a", "b"), dest) {
		sources = append(sources, update.SourcePrefix)
	}
	if !slices.Contains(sources, source) {
		t.Errorf("a announced %s from %s and its updates carry the sources %v", dest, source, sources)
	}
}

// the update interval a file writes is the one the speaker advertises its routes under
// a node writing one other than four hellos ran four hellos, and its peers expired its routes by that
func TestSpeakerAdvertisesTheConfiguredUpdateInterval(t *testing.T) {
	const update = 30 * time.Second
	fabric := newMeshFabric(t, Config{Hello: dur(4 * time.Second), Update: dur(update)}, "a-b")
	dest := netip.MustParsePrefix("fd00:a::/64")
	fabric.speakers["a"].Originate(dest)
	fabric.flush("a")
	updates := updatesFor(t, fabric.tlvs("a", "b"), dest)
	if len(updates) == 0 {
		t.Fatal("a advertised nothing, so this measures nothing")
	}
	for _, advertised := range updates {
		if got := time.Duration(advertised.Interval) * 10 * time.Millisecond; got != update {
			t.Errorf("an update carries the interval %s, want the %s the file writes", got, update)
		}
	}
}
