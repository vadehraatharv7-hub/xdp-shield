package main

import (
	"encoding/binary"
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

	"github.com/cilium/ebpf"
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

	go func() {
		for {
			resp, err := http.Get(apiUrl)
			if err != nil {
				log.Printf("Failed to fetch banned IPs: %v", err)
				time.Sleep(10 * time.Second)
				continue
			}
			var ips []BannedIP
			if err := json.NewDecoder(resp.Body).Decode(&ips); err != nil {
				log.Printf("Failed to decode banned IPs: %v", err)
			} else {
				for _, b := range ips {
					ipKey, err := ipToUint32(b.IP)
					if err == nil {
						objs.DropMap.Update(ipKey, uint32(1), ebpf.UpdateAny)
					}
				}
			}
			resp.Body.Close()
			time.Sleep(10 * time.Second)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\n[*] Detaching XDP hook and exiting cleanly...")
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ip), nil
}
