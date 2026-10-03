#!/usr/bin/env python3
"""Generate OpenWrt config and domain-list files from canonical inputs."""

import argparse
import shutil
from pathlib import Path


REMOVED_KEYS = {
    "proxy_dns",
    "proxy_dns_address",
    "proxy_dns_port",
    "dns_proxy",
    "dns_proxy_address",
    "dns_proxy_port",
    "tcp_proxy",
    "tcp_proxy_address",
    "tcp_proxy_port",
    "tls_proxy",
    "tls_proxy_address",
    "tls_proxy_port",
}
OVERRIDES = {
    "server": "127.0.0.1:5354",
    "tcp_route": "direct",
    "active_domains_file": "/etc/ipscoutdns/active-domains.txt",
    "passive_domains_file": "/etc/ipscoutdns/passive-domains.txt",
    "reachable_hosts": "/tmp/ipscoutdns/reachable.hosts",
    "reachable_domains_file": "/tmp/ipscoutdns/reachable.domains",
    "reachable_ips_file": "/tmp/ipscoutdns/reachable.ips",
    "unreachable_domains_file": "/tmp/ipscoutdns/unreachable.domains",
    "unreachable_ips_file": "/tmp/ipscoutdns/unreachable.ips",
}


def generate_config(source: str) -> str:
    output = []
    replaced = set()
    skipping_proxy_list = False

    for line in source.splitlines():
        stripped = line.strip()
        if skipping_proxy_list:
            if "}" in stripped:
                skipping_proxy_list = False
            continue
        if not stripped:
            output.append(line)
            continue
        if stripped.startswith(("#", ";")):
            if "proxy" not in stripped.lower() and "socks5" not in stripped.lower():
                output.append(line)
            continue

        if "=" not in stripped:
            output.append(line)
            continue

        key, value = stripped.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in REMOVED_KEYS:
            if key == "proxy_dns" and value.startswith("{") and "}" not in value:
                skipping_proxy_list = True
            continue
        if key in OVERRIDES:
            if key not in replaced:
                output.append(f"{key}={OVERRIDES[key]}")
                replaced.add(key)
            continue
        output.append(line)

    if skipping_proxy_list:
        raise ValueError("proxy_dns list is missing its closing brace")

    for key, value in OVERRIDES.items():
        if key not in replaced:
            output.append(f"{key}={value}")

    return "\n".join(output) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="canonical root config file")
    parser.add_argument("destination", type=Path, help="generated OpenWrt config file")
    parser.add_argument("--active-domains-source", type=Path, help="canonical active domains list")
    parser.add_argument("--active-domains-destination", type=Path, help="generated active domains list")
    parser.add_argument("--passive-domains-source", type=Path, help="canonical passive domains list")
    parser.add_argument("--passive-domains-destination", type=Path, help="generated passive domains list")
    args = parser.parse_args()

    for name in ("active-domains", "passive-domains"):
        argument_name = name.replace("-", "_")
        source = getattr(args, f"{argument_name}_source")
        destination = getattr(args, f"{argument_name}_destination")
        if (source is None) != (destination is None):
            parser.error(f"--{name}-source and --{name}-destination must be provided together")

    generated = generate_config(args.source.read_text(encoding="utf-8"))
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(generated, encoding="utf-8", newline="\n")

    for name in ("active-domains", "passive-domains"):
        argument_name = name.replace("-", "_")
        source = getattr(args, f"{argument_name}_source")
        destination = getattr(args, f"{argument_name}_destination")
        if source is not None and destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


if __name__ == "__main__":
    main()
