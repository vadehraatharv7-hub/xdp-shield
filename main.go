// main.go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf bpf ./bpf/xdp_drop.c

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "eth0", "Network interface to attach XDP to")
	flag.Parse()

	// eBPF requires locked memory; remove limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load compiled eBPF objects into kernel memory
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Find the targeted network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", *ifaceName, err)
	}

	// Attach the XDP program to the network interface
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer lnk.Close()

	fmt.Printf("[+] XDP Shield attached to %s. Awaiting ban feeds...\n", *ifaceName)

	// Keep agent running until an exit signal (Ctrl+C, SIGTERM) is received
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\n[*] Detaching XDP hook and exiting cleanly...")
}

// Helper to convert an IPv4 address to uint32 key format
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	// Kernel stores network byte order as little-endian integer in saddr on x86
	return binary.LittleEndian.Uint32(ip), nil
}