# IPScoutDNS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-multiple_architectures-blue)](https://openwrt.org/)

A DNS service for IPv4 (A) records, supporting plain DNS, DNS over HTTPS (DoH), and DNS over TLS (DoT). It offers TCP/TLS/HTTP/ICMP reachability checks and direct, interface-bound, or SOCKS5 routing. ICMP is disabled on proxy routes.

## Installation

Download the package for your OS and architecture from [GitHub Releases](https://github.com/rashidbestry/IPScoutDNS/releases/latest). Linux and Windows archives support `amd64` and `arm64`; extract the binary and its `config/` folder together.

### OpenWrt

Releases include IPKs for opkg firmware, APKs for OpenWrt 25.12+, and manual-install archives for ten CPU families: x86, x86-64, ARM, ARM64, MIPS/MIPS64 in both byte orders, RISC-V64, and LoongArch64. Packages use architecture names rather than board families; `aarch64_generic` is usable beyond Rockchip.

The oldest tested compatibility baseline is OpenWrt 12.09 on x86 with Linux 3.3.8. CI boots original 12.09 and 14.07 x86 images with 64 MiB RAM to check installation, DNS fallback, service start/stop, config preservation, and removal. Other CPU/firmware combinations require device testing; Linux 3.2+ and a supported CPU are required, and newer CPU families need firmware that supports their hardware. See [architecture names, requirements, and manual installation](packaging/openwrt/README.md).

On opkg firmware, identify the device's architecture with `opkg print-architecture`. Set `ARCH` to the matching device architecture, such as `mips_24kc`, `mipsel_24kc`, `arm_cortex-a9`, `aarch64_cortex-a53`, or the legacy `x86`:

```sh
VERSION="<version>"
ARCH="<device-architecture>"
wget "https://github.com/rashidbestry/IPScoutDNS/releases/download/v${VERSION}/ipscoutdns-${VERSION}-openwrt-${ARCH}.ipk"
opkg install "./ipscoutdns-${VERSION}-openwrt-${ARCH}.ipk"
```

On APK firmware, identify the architecture with `apk --print-arch`:

```sh
VERSION="<version>"
ARCH="$(apk --print-arch)"
wget "https://github.com/rashidbestry/IPScoutDNS/releases/download/v${VERSION}/ipscoutdns-${VERSION}-openwrt-${ARCH}.apk"
apk add --allow-untrusted "./ipscoutdns-${VERSION}-openwrt-${ARCH}.apk"
```

`--allow-untrusted` permits installation without a trusted package signature. Avoid forcing a mismatched architecture; use the matching manual-install archive if the firmware's architecture name is not listed.

## Requirements

- Prebuilt binaries do not require Go. Building from source requires the Go version in [go.mod](go.mod).
- ICMP probing requires the system `ping` command. OpenWrt releases include a current Mozilla CA bundle for TLS; keep the package and the router's clock current.
- Memory and storage requirements depend on domain count, concurrency, and saved log limits.

## Run

Edit [config/ipscoutdns.conf](config/ipscoutdns.conf) before starting. On OpenWrt, edit `/etc/ipscoutdns.conf`; domain lists are installed under `/etc/ipscoutdns/`.

- `mode=active`: DNS server that processes A queries on demand, applies regex filters from [active-domains.txt](config/active-domains.txt), and writes host outputs.
- `mode=passive`: scheduled resolution of hostnames in [passive-domains.txt](config/passive-domains.txt).

Domain-file paths resolve beside the config. The sample uses port 53; choose a free listener port.

On Linux/OpenWrt, `direct_tcp_mark` sets a socket mark for direct TCP/TLS/HTTP probes; `0` disables marking. Set `direct_tcp_mark=255` (or `0xff`) when your firewall already exempts that mark, such as the Passwall2 bypass rule. It requires root or a suitable network capability and preserves `direct_tcp_interface` source binding. A marking failure fails the probe. DNS, ICMP, and SOCKS5 connections are not marked by this setting; nonzero marks are rejected on other operating systems.

Regular Linux writes output files to `./outputs/` and saved logs to `./logs/`, relative to the working directory, without copying. Windows keeps outputs beside the executable and saved logs in its `logs/` folder.

Only OpenWrt package builds use `/tmp/ipscoutdns/` and copy outputs to `/etc/ipscoutdns/outputs/` after passive passes or at `active_copy_interval` in active mode. Saved logs are copied to `/etc/ipscoutdns/logs/` after passive passes, at `active_log_copy_interval` in active mode, and once more during a clean active shutdown. The package workflow builds with `-ldflags="-X main.openWrtPackage=true"`; ordinary Linux builds keep the local layout even when run on OpenWrt.

**Windows:**

```powershell
.\ipscoutdns.exe --config .\config\ipscoutdns.conf
```

**Linux:**

```sh
./ipscoutdns --config ./config/ipscoutdns.conf
```

**OpenWrt:** the service is disabled after installation.

```sh
/etc/init.d/ipscoutdns start
/etc/init.d/ipscoutdns enable
```

## DNS query controls

`dns_query_parallel=4` limits concurrent upstream DNS queries across the entire
service in both Active and Passive modes. Direct DNS, SOCKS5 DNS, DoH, and Active
fallback queries share this limit. Additional queries wait for a slot;
set `dns_query_parallel=0` for unlimited concurrent upstream DNS queries.
`passive_resolve_parallel` controls domain jobs and `parallel_tests` controls
candidate-IP probes separately.

`dns_timeout` applies to each upstream query after it acquires a slot, so time
spent in the queue does not consume its network timeout. Caller cancellation
and service shutdown stop queued and running queries. A domain's full discovery
round can take longer than `dns_timeout` when many resolvers are configured;
remove consistently failing resolvers to avoid spending their timeout on every
scan. Existing TLS/HTTP selection and `hosts_max_ips_per_domain` rules are unchanged.

Resolver logs report DNS response codes and A-record counts, including
`NOERROR` with zero A records, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`. DoH logs also
identify HTTP errors such as `403` and `429`, unreadable or malformed DNS bodies,
and candidates discarded by IPv4 validation. An HTTP `200` response alone does
not mean a resolver supplied usable IPv4 addresses.

## Early HTTP fallback

`http_fallback_tls_alerts=2` starts HTTP probing early when that many distinct
candidate IPs return a remote TLS `internal_error` alert after TCP success and
no TLS candidate has succeeded. Both TLS and HTTP probes must be enabled.
The same rule applies in Active and Passive modes; `0` disables early fallback.
Timeouts, EOFs, and other TLS failures do not count toward this threshold.

If HTTP succeeds, selection uses `[HTTP]` and respects `hosts_max_ips_per_domain`.
Remaining TLS candidates stay unknown, so a later TLS-capable IP may be skipped.
If HTTP fails, remaining TLS checks resume before final classification. The
threshold resets for each fresh resolution; a later pass tries TLS again.

Check out FLOWCHART [FLOWCHART](FLOWCHART.md).

## TLS ALPN compatibility retry

When a TLS probe receives the remote `insufficient_security` alert, it retries
once on a fresh connection advertising ALPN `h2` and `http/1.1`. The retry uses
the same candidate IP, hostname, port, route, and direct-interface selection,
and shares the original candidate timeout. This applies in Active and Passive
modes without a new config setting. A successful retry qualifies the IP for
`[TLS]` selection. Other alerts, EOFs, and timeouts do not trigger this retry.

