#!/usr/bin/env python3
"""Copy canonical config and domain-list files byte-for-byte for OpenWrt."""

import argparse
import shutil
from pathlib import Path


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

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.source, args.destination)

    for name in ("active-domains", "passive-domains"):
        argument_name = name.replace("-", "_")
        source = getattr(args, f"{argument_name}_source")
        destination = getattr(args, f"{argument_name}_destination")
        if source is not None and destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


if __name__ == "__main__":
    main()
