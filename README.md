# IPScoutDNS

IPScoutDNS is a local DNS proxy that resolves A-record queries by selecting an IP that is actually reachable over HTTPS/TLS, instead of blindly trusting the first upstream answer.

## What it does

- listens for UDP/TCP DNS requests on a local port
- queries configured direct resolvers first
- optionally uses a SOCKS5 tunnel for proxy resolvers
- tests candidate IPv4 addresses with a TLS handshake to port 443
- caches successful IP choices and revalidates expired entries
- falls back to a configured DNS server when no usable IP is found

## Configuration

The service reads from `/etc/ipscoutdns.conf` by default, and will also fall back to the legacy `/etc/ipselector.conf` path for compatibility. You can override this with the `IPSCOUTDNS_CONFIG` environment variable, the legacy `IPSELECTOR_CONFIG` variable, or the `--config` flag.

Example:

```ini
[direct_dns]
8.8.8.8
1.1.1.1

[proxy_dns]
9.9.9.9
https://dns.adguard-dns.com/dns-query

[socks5]
# Proxy for DNS resolvers (can also use [dns_proxy])
address=127.0.0.1:1080

[tls_proxy]
# Separate proxy for TLS reachability checking (when tls_route=proxy)
address=127.0.0.1:1080

[cache]
ttl=24h

[fallback]
address=127.0.0.1:53053

[server]
address=127.0.0.1:5354
dns_timeout=3s
tls_timeout=3s
tls_port=443
tls_route=direct
# Optional: separate proxy port for TLS reachability checks
# tls_proxy_port=1080
parallel_tests=16
answer_ttl=300
shutdown_timeout=5s
```

The config file accepts multiple entries under `[direct_dns]` and `[proxy_dns]`. Proxies for DNS resolvers (`[socks5]` / `[dns_proxy]`) and TLS reachability checking (`[tls_proxy]`, `tls_proxy_port`) can be configured separately. Durations use Go duration syntax (for example, `3s` or `24h`); `answer_ttl` is in seconds. All values above have defaults, but can be changed in the config file.

## Run

```bash
go run .
```

## Production notes

- keep the service behind a trusted local resolver chain
- ensure the upstream resolvers and SOCKS5 proxy are reachable
- monitor logs for failed upstreams and repeated TLS validation failures
- set a sane cache TTL based on your network conditions
