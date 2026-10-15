package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf bpf ./bpf/xdp_drop.c

type BannedIP struct {
	IP string `json:"ip"`
}

func main() {
	ifaceName := flag.String("iface", "eth0", "Network interface to attach XDP to")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", *ifaceName, err)
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropFunc,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer lnk.Close()

	fmt.Printf("[+] XDP Shield attached to %s. Awaiting ban feeds via API...\n", *ifaceName)

	apiUrl := os.Getenv("API_URL")
	if apiUrl == "" {
		apiUrl = "http://10.0.2.4:8081/api/threats/banned"
	}

	client := &http.Client{Timeout: 8 * time.Second}
	go func() {
		for {
			banned, err := fetchBans(client, apiUrl)
			if err != nil {
				// Keep the current rules: a dashboard outage must neither unblock nor block anyone.
				log.Printf("Failed to fetch banned IPs: %v", err)
				time.Sleep(10 * time.Second)
				continue
			}
			added, removed, err := syncBans(kernelMap{objs.DropMap}, banned)
			if err != nil {
				log.Printf("Failed to sync drop map: %v", err)
			} else if added > 0 || removed > 0 {
				log.Printf("Drop map updated: +%d blocked, -%d unblocked (%d listed)", added, removed, len(banned))
			}
			time.Sleep(10 * time.Second)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\n[*] Detaching XDP hook and exiting cleanly...")
}

func fetchBans(c *http.Client, url string) ([]BannedIP, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}
	var ips []BannedIP
	if err := json.NewDecoder(resp.Body).Decode(&ips); err != nil {
		return nil, fmt.Errorf("decoding ban list: %w", err)
	}
	return ips, nil
}
