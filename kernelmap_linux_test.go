//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Runs against a real kernel hash map (needs root); skipped otherwise.
func TestKernelMapSync(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a BPF map")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 4, MaxEntries: 64})
	if err != nil {
		t.Fatalf("creating map: %v", err)
	}
	defer m.Close()
	km := kernelMap{m}

	a, r, err := syncBans(km, []BannedIP{{IP: "198.51.100.1"}, {IP: "198.51.100.2"}})
	if err != nil || a != 2 || r != 0 {
		t.Fatalf("add: +%d -%d err=%v", a, r, err)
	}
	a, r, err = syncBans(km, []BannedIP{{IP: "198.51.100.2"}, {IP: "198.51.100.3"}})
	if err != nil || a != 1 || r != 1 {
		t.Fatalf("swap: +%d -%d err=%v", a, r, err)
	}
	keys, _ := km.Keys()
	got := map[uint32]bool{}
	for _, k := range keys {
		got[k] = true
	}
	want1, _ := ipToUint32("198.51.100.1")
	want2, _ := ipToUint32("198.51.100.2")
	want3, _ := ipToUint32("198.51.100.3")
	if got[want1] || !got[want2] || !got[want3] || len(got) != 2 {
		t.Fatalf("kernel map holds %v", got)
	}
	if _, _, err := syncBans(km, nil); err != nil {
		t.Fatal(err)
	}
	if keys, _ = km.Keys(); len(keys) != 0 {
		t.Fatalf("empty list should clear the map, left %v", keys)
	}
}
