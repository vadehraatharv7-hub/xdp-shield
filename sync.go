package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// dropMap is the part of the kernel drop map the agent needs; a fake stands in for tests.
type dropMap interface {
	Put(key uint32) error
	Remove(key uint32) error
	Keys() ([]uint32, error)
}

// kernelMap adapts the BPF hash map.
type kernelMap struct{ m *ebpf.Map }

func (k kernelMap) Put(key uint32) error { return k.m.Update(key, uint32(1), ebpf.UpdateAny) }
func (k kernelMap) Remove(key uint32) error {
	return k.m.Delete(key)
}
func (k kernelMap) Keys() ([]uint32, error) {
	var keys []uint32
	var key, val uint32
	it := k.m.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
	}
	return keys, it.Err()
}

// syncBans makes the kernel map equal to the dashboard's ban list: new bans are
// added and addresses that are no longer listed are removed (unblocking).
// Entries that fail to parse are ignored. It returns how many were added/removed.
func syncBans(m dropMap, banned []BannedIP) (added, removed int, err error) {
	want := map[uint32]bool{}
	for _, b := range banned {
		if k, perr := ipToUint32(b.IP); perr == nil {
			want[k] = true
		}
	}
	have, err := m.Keys()
	if err != nil {
		return 0, 0, fmt.Errorf("reading drop map: %w", err)
	}
	present := make(map[uint32]bool, len(have))
	for _, k := range have {
		present[k] = true
		if !want[k] {
			if err := m.Remove(k); err == nil {
				removed++
			}
		}
	}
	for k := range want {
		if !present[k] {
			if err := m.Put(k); err == nil {
				added++
			}
		}
	}
	return added, removed, nil
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ip), nil
}
