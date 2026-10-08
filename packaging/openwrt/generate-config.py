#!/usr/bin/env python3
"""Generate OpenWrt config and domain-list files from canonical inputs."""

import argparse
import shutil
from pathlib import Path


DOMAIN_PATHS = {
    "active_domains_file": "/etc/ipscoutdns/active-domains.txt",
    "passive_domains_file": "/etc/ipscoutdns/passive-domains.txt",
}


def generate_config(source: str) -> str:
    """Preserve source data, changing only nonempty packaged domain-list paths."""
    output = []

    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(("#", ";")) or "=" not in stripped:
            output.append(line)
            continue

        key, value = stripped.split("=", 1)
        key = key.strip().lower()
        if key in DOMAIN_PATHS and value.strip():
            output.append(f"{key}={DOMAIN_PATHS[key]}")
        else:
            output.append(line)

    return "\n".join(output) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="canonical config file from config/")
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
