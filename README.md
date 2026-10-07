# XPD-Shield

An ultra-lightweight, eBPF/XDP-based edge mitigation agent that provides line-rate packet inspection and filtering directly at the network interface.

## 🚀 Architecture Context

This repository is part of a larger Multi-ML Active Defense Architecture, serving as the first line of defense ("Tier 1"):
- **[infra_honeypot](../infra_honeypot)**: Provisions the environment and seamlessly deploys `xpd-shield` onto honeypot nodes.
- **[sec_dash](../sec_dash)**: The central dashboard where threat intelligence is gathered (which eventually informs `xpd-shield`'s blocklists).

## 🛡️ What It Does

`xpd-shield` hooks into the Linux kernel using eBPF and XDP (eXpress Data Path) to intercept and drop malicious packets before they even reach the standard OS network stack.
- **Immediate Mitigation:** Drops known botnet signatures and IP addresses instantaneously.
- **Dynamic Ban Feeds:** Subscribes to a Redis Pub/Sub `ban_feed` channel to receive new malicious IP addresses from central ML models (like the Behaviour Model).
- **In-Kernel Data Structures:** Maintains an LRU Hash Map within the kernel, capable of tracking up to 65,536 blocked IPs simultaneously with O(1) lookup times.

## 🛠️ Tech Stack
- **Go**: User-space program responsible for loading the eBPF bytecode, managing the Redis subscription, and updating kernel maps.
- **eBPF / C**: Kernel-space packet filter written in C, compiled to eBPF bytecode using clang/llvm.
- **Cilium eBPF**: The Go library used for interacting with the eBPF subsystem.

## 📂 Project Structure
- `bpf/xdp_drop.c`: The core eBPF program that executes the packet filtering logic.
- `main.go`: The Go user-space application that attaches the XDP program and listens for Redis pub/sub ban events.

## 📖 Usage
To run the shield agent:
1. Ensure you have clang, llvm, and linux-headers installed.
2. Compile the eBPF program: `go generate`
3. Run the application as root: `sudo go run main.go --iface eth0` (Replace `eth0` with the target network interface).
4. Supply `REDIS_ADDR` environment variable to connect to the central message broker.

## 🤝 Open Source Learning
This project provides hands-on experience with cutting-edge Linux networking capabilities, demonstrating how to write kernel-safe C code for eBPF, interface it with modern Go applications, and execute high-speed threat mitigation.
