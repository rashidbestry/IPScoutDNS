# IPScoutDNS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-25.12.5-blue)](https://openwrt.org/)

A DNS service for IPv4 (A) records, supporting plain DNS, DNS over HTTPS (DoH), and DNS over TLS (DoT). It offers TCP/TLS/HTTP/ICMP reachability checks and direct, interface-bound, or SOCKS5 routing. ICMP is disabled on proxy routes.

## Installation

Download the package for your OS and architecture from [GitHub Releases](https://github.com/rashidbestry/IPScoutDNS/releases/latest). Linux and Windows archives support `amd64` and `arm64`; extract the binary and its `config/` folder together.

### OpenWrt

The APK targets OpenWrt 25.12.5 `rockchip/armv8` (`aarch64_generic`). Replace `<version>` with the release version without its leading `v`:

```sh
VERSION="<version>"
wget "https://github.com/rashidbestry/IPScoutDNS/releases/download/v${VERSION}/ipscoutdns-${VERSION}-rockchip-armv8-aarch64_generic.apk"
apk add --allow-untrusted "./ipscoutdns-${VERSION}-rockchip-armv8-aarch64_generic.apk"
```

`--allow-untrusted` permits installation without a trusted package signature.

## Requirements

- Prebuilt binaries do not require Go. Building from source requires the Go version in [go.mod](go.mod).
- ICMP probing requires the system `ping` command. The OpenWrt package depends on `ca-bundle` for TLS.
- Memory and storage requirements depend on domain count, concurrency, and saved log limits.

## Run

Edit [config/ipscoutdns.conf](config/ipscoutdns.conf) before starting. On OpenWrt, edit `/etc/ipscoutdns.conf`; domain lists are installed under `/etc/ipscoutdns/`.

- `mode=active`: DNS server that processes A queries on demand, applies regex filters from [active-domains.txt](config/active-domains.txt), and writes host outputs.
- `mode=passive`: scheduled resolution of hostnames in [passive-domains.txt](config/passive-domains.txt).

Domain-file paths resolve beside the config. The sample uses port 53; choose a free listener port.

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
