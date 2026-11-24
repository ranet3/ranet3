// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestPeakMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peak RSS is read from Linux procfs")
	}
	const childEnv = "RANET3_TRUST_INDEX_PEAK_CHILD"
	if os.Getenv(childEnv) != "" {
		peakRSS, signedBytes, targets := indexWorstSignedSnapshot(t)
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		fmt.Printf("INDEX_PEAK %d %d %d %d %d\n", os.Getpid(), peakRSS, signedBytes, targets, after.HeapAlloc)
		return
	}
	run := exec.Command(os.Args[0], "-test.run=^TestPeakMemory$", "-test.count=1", "-test.v")
	run.Env = append(os.Environ(), childEnv+"=1")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated Index measurement: %v\n%s", err, out)
	}
	marker := strings.Index(string(out), "INDEX_PEAK ")
	if marker < 0 {
		t.Fatalf("isolated Index measurement has no peak: %s", out)
	}
	var pid, signedBytes, targets int
	var peakRSS, afterGCHeap uint64
	if _, err := fmt.Sscanf(string(out[marker:]), "INDEX_PEAK %d %d %d %d %d", &pid, &peakRSS, &signedBytes, &targets, &afterGCHeap); err != nil {
		t.Fatalf("isolated Index measurement: %v\n%s", err, out)
	}
	if pid == os.Getpid() || peakRSS <= afterGCHeap {
		t.Fatalf("Index child %d, parent %d, peak RSS %d, after-GC heap %d", pid, os.Getpid(), peakRSS, afterGCHeap)
	}
	t.Logf("Index worst signed file: signed=%d indexed-targets=%d isolated-peak-RSS=%d after-GC-heap=%d bytes", signedBytes, targets, peakRSS, afterGCHeap)
}

// The input is signed-limit sized and has keyed nodes and distinct endpoint
// identities throughout, so Index materializes every target and its key.
func indexWorstSignedSnapshot(t *testing.T) (peakRSS uint64, signedBytes, targets int) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(der)
	const fullNodes = 139
	const endpointsPerNode = 32768
	document := Document{Nodes: make([]Node, fullNodes+1)}
	for i := range document.Nodes {
		count := endpointsPerNode
		if i == fullNodes {
			count = 22000
		}
		node := &document.Nodes[i]
		node.Name = fmt.Sprintf("example/n%d", i)
		node.Key = &key
		node.Endpoints = make([]Endpoint, count)
		for j := range node.Endpoints {
			serial := strconv.Itoa(j)
			node.Endpoints[j] = Endpoint{ID: &serial, Family: "ip4", Port: 1}
		}
		targets += count
	}
	mesh := MeshID{6: 0x70, 8: 0x80}
	body, err := encodePayload(Payload{Height: 1, Document: document, Mesh: mesh})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := signTestFile(t, body, private, algorithmEd25519)
	signedBytes = len(file)
	if signedBytes > MaxSignedBytes || signedBytes < MaxSignedBytes-(16<<10) {
		t.Fatalf("indexed snapshot has %d bytes, want within 16 KiB of the signed limit", signedBytes)
	}
	index, err := NewIndex(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Nodes()) != len(document.Nodes) || len(index.Targets(index.Nodes()[0])) != endpointsPerNode {
		t.Fatal("Index did not retain the keyed endpoints")
	}
	peakRSS = linuxPeakRSS(t)
	runtime.KeepAlive(file)
	runtime.KeepAlive(index)
	return peakRSS, signedBytes, targets
}

func linuxPeakRSS(t *testing.T) uint64 {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			t.Fatalf("unexpected VmHWM line %q", line)
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return kilobytes * 1024
	}
	t.Fatal("no VmHWM in proc status")
	return 0
}
