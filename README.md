# IPScoutDNS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![OpenWrt](https://img.shields.io/badge/OpenWrt-multiple_architectures-blue)](https://github.com/rashidbestry/IPScoutDNS/wiki/OpenWrt)

## What is it?

A DNS service that discovers IPv4 addresses, checks their reachability, and selects a working address. It serves filtered DNS answers on demand or scans domain lists on a schedule.

## Where is it useful?

Useful when DNS answers contain unreachable addresses or are filtered by an ISP, for generating hosts lists, and for comparing reachability through direct and proxy routes.

## Capabilities

- [Active DNS serving](https://github.com/rashidbestry/IPScoutDNS/wiki/Active-mode) with regex filtering, caching and fallback; [Passive scans](https://github.com/rashidbestry/IPScoutDNS/wiki/Passive-mode) with interval or daily schedules.
- [TCP, TLS, HTTP and ICMP probes](https://github.com/rashidbestry/IPScoutDNS/wiki/Reachability-probes), configurable concurrency and successful-IP limits.
- [Plain DNS and HTTPS DoH discovery](https://github.com/rashidbestry/IPScoutDNS/wiki/DNS-and-routing), direct/interface-bound connections and SOCKS5 routing. ICMP runs only on direct routes.
- [Hosts/domain/IP outputs and rotating logs](https://github.com/rashidbestry/IPScoutDNS/wiki/Outputs-and-logging), plus startup and post-scan command hooks.

## Minimum requirements

- **Windows:** Windows 10+ or Windows Server 2016+.
- **Linux:** kernel 3.2+; some architectures require newer kernels.
- **OpenWrt:** oldest tested baseline is 12.09 on x86 in QEMU; other CPU/firmware combinations require device testing.
- **RAM/storage:** depends on domain count, concurrency and log retention; no fixed workload minimum is established.

See [OpenWrt compatibility and device requirements](https://github.com/rashidbestry/IPScoutDNS/wiki/OpenWrt#compatibility-and-small-devices).

## Supported release architectures

| Platform        | Architectures                                                                   |
| --------------- | ------------------------------------------------------------------------------- |
| Windows / Linux | `amd64`, `arm64`                                                                |
| OpenWrt         | x86, x86-64, ARM, ARM64, MIPS/MIPS64 in both byte orders, RISC-V64, LoongArch64 |

[OpenWrt package aliases and archive families](https://github.com/rashidbestry/IPScoutDNS/wiki/OpenWrt#cpu-families-and-manual-archives).

## Installation

[Download releases](https://github.com/rashidbestry/IPScoutDNS/releases/latest) · [Windows/Linux installation](https://github.com/rashidbestry/IPScoutDNS/wiki/Installation) · [OpenWrt installation](https://github.com/rashidbestry/IPScoutDNS/wiki/OpenWrt)

## Usage

[Configuration](https://github.com/rashidbestry/IPScoutDNS/wiki/Configuration) · [Active mode](https://github.com/rashidbestry/IPScoutDNS/wiki/Active-mode) · [Passive mode](https://github.com/rashidbestry/IPScoutDNS/wiki/Passive-mode)

[Full wiki](https://github.com/rashidbestry/IPScoutDNS/wiki) · [Flowchart](https://github.com/rashidbestry/IPScoutDNS/wiki/FLOWCHART) · [Troubleshooting](https://github.com/rashidbestry/IPScoutDNS/wiki/Troubleshooting) · [Report an issue](https://github.com/rashidbestry/IPScoutDNS/issues)
