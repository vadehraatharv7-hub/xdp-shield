// bpf/xdp_drop.c

// Linux kernel UAPI headers defining network structures and BPF types
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/*
 * 1. BPF Map Definition
 * In eBPF, a "map" is a shared data structure between kernel space and user space.
 * Here we define a Hash Table:
 * - Key: __u32 (IPv4 address stored as an unsigned 32-bit integer)
 * - Value: __u32 (1 = dropped, or a ban timestamp)
 * - Max entries: 65,536 blocked IPs simultaneously in kernel memory
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} drop_map SEC(".maps");

/*
 * 2. The Hook Function
 * SEC("xdp") tells the compiler and loader to place this bytecode inside the 
 * "xdp" ELF section so the kernel driver attaches it to the NIC ingress hook.
 */
SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx) {
    // ctx->data points to the start of the raw packet bytes in memory
    void *data = (void *)(long)ctx->data;
    // ctx->data_end points to the exact end of the packet buffer
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * 3. Layer 2: Ethernet Header Parsing
     * Cast the raw memory address 'data' into an Ethernet header struct (struct ethhdr).
     */
    struct ethhdr *eth = data;

    // BOUNDS CHECK (Mandatory for eBPF Verifier):
    // Ensure the packet actually contains enough bytes for an Ethernet header.
    // If (eth + 1) exceeds data_end, the packet is truncated/corrupt.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the Ethernet payload is IPv4.
    // ETH_P_IP is 0x0800. __builtin_bswap16 swaps bytes to match network order.
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS; // Let ARP, IPv6, etc. pass through untouched

    /*
     * 4. Layer 3: IPv4 Header Parsing
     * The IP header begins immediately after the Ethernet header: (eth + 1).
     */
    struct iphdr *ip = (void *)(eth + 1);

    // BOUNDS CHECK: Verify the IP header fits within the packet boundaries.
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Extract the source IPv4 address (32-bit integer)
    __u32 src_ip = ip->saddr;

    /*
     * 5. Kernel Map Lookup
     * bpf_map_lookup_elem searches our drop_map hash table in constant O(1) time.
     */
    __u32 *is_banned = bpf_map_lookup_elem(&drop_map, &src_ip);
    if (is_banned) {
        // Drop the packet at the NIC driver before sk_buff memory allocation
        return XDP_DROP;
    }

    // IP is not in the ban map; send it up the standard Linux network stack
    return XDP_PASS;
}

// eBPF programs require an open-source license string to access GPL BPF helpers
char _license[] SEC("license") = "GPL";