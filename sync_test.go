package main

import (
	"sort"
	"testing"
)

type fakeMap struct{ m map[uint32]bool }

func (f *fakeMap) Put(k uint32) error    { f.m[k] = true; return nil }
func (f *fakeMap) Remove(k uint32) error { delete(f.m, k); return nil }
func (f *fakeMap) Keys() ([]uint32, error) {
	var ks []uint32
	for k := range f.m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks, nil
}

func key(t *testing.T, ip string) uint32 {
	k, err := ipToUint32(ip)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSyncAddsNewAndRemovesUnbanned(t *testing.T) {
	f := &fakeMap{m: map[uint32]bool{}}
	a, r, _ := syncBans(f, []BannedIP{{IP: "198.51.100.1"}, {IP: "198.51.100.2"}})
	if a != 2 || r != 0 || len(f.m) != 2 {
		t.Fatalf("initial sync: +%d -%d, map=%v", a, r, f.m)
	}
	// 198.51.100.1 is unblocked in the dashboard, 198.51.100.3 is newly blocked
	a, r, _ = syncBans(f, []BannedIP{{IP: "198.51.100.2"}, {IP: "198.51.100.3"}})
	if a != 1 || r != 1 {
		t.Fatalf("second sync: +%d -%d", a, r)
	}
	if f.m[key(t, "198.51.100.1")] || !f.m[key(t, "198.51.100.2")] || !f.m[key(t, "198.51.100.3")] {
		t.Fatalf("wrong contents: %v", f.m)
	}
}

func TestSyncEmptyListClearsAndInvalidEntriesAreIgnored(t *testing.T) {
	f := &fakeMap{m: map[uint32]bool{}}
	syncBans(f, []BannedIP{{IP: "198.51.100.1"}, {IP: "not-an-ip"}, {IP: "2001:db8::1"}})
	if len(f.m) != 1 {
		t.Fatalf("only the valid IPv4 should be blocked: %v", f.m)
	}
	syncBans(f, nil)
	if len(f.m) != 0 {
		t.Fatalf("an empty list must unblock everything: %v", f.m)
	}
}

func TestIPKeyMatchesKernelLayout(t *testing.T) {
	// 130.12.180.51 was observed in the live drop map as 867437698
	if got := key(t, "130.12.180.51"); got != 867437698 {
		t.Fatalf("got %d", got)
	}
}
