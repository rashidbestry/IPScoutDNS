#!/usr/bin/env python3
"""Package a static Go binary for OpenWrt without target SDK/libc dependencies."""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CONFFILES = (
    "/etc/ipscoutdns.conf",
    "/etc/ipscoutdns/active-domains.txt",
    "/etc/ipscoutdns/passive-domains.txt",
)
# ELF class, byte order, e_machine. Big-endian ARM and PowerPC router CPUs
# are intentionally excluded because Go cannot build suitable binaries.
ELF_TARGETS = {
    "386": (1, 1, 3), "amd64": (2, 1, 62),
    "arm": (1, 1, 40), "arm64": (2, 1, 183),
    "mips": (1, 2, 8), "mipsle": (1, 1, 8),
    "mips64": (2, 2, 8), "mips64le": (2, 1, 8),
    "riscv64": (2, 1, 243), "loong64": (2, 1, 258),
}


def load_targets():
    targets = json.loads((HERE / "architectures.json").read_text(encoding="utf-8"))
    seen = {"goarch": set(), "ipk": set(), "apk": set()}
    for target in targets:
        if target["goarch"] not in ELF_TARGETS:
            raise ValueError(f"Unsupported Go target: {target['goarch']}")
        for kind in seen:
            values = [target[kind]] if kind == "goarch" else target[kind]
            for value in values:
                if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value) or value in seen[kind]:
                    raise ValueError(f"Invalid or duplicate {kind}: {value}")
                seen[kind].add(value)
    return targets


def validate_binary(binary, goarch):
    """Reject mislabeled or dynamically linked binaries before publishing."""
    with binary.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:4] != b"\x7fELF":
            raise ValueError("Expected a Linux ELF binary")
        elf_class, byte_order, machine = ELF_TARGETS[goarch]
        endian = "<" if byte_order == 1 else ">"
        if (header[4], header[5], struct.unpack_from(endian + "H", header, 18)[0]) != (
            elf_class, byte_order, machine
        ):
            raise ValueError(f"Binary architecture does not match {goarch}")
        if elf_class == 1:
            offset = struct.unpack_from(endian + "I", header, 28)[0]
            entry_size, count = struct.unpack_from(endian + "HH", header, 42)
            minimum_entry_size = 32
        else:
            offset = struct.unpack_from(endian + "Q", header, 32)[0]
            entry_size, count = struct.unpack_from(endian + "HH", header, 54)
            minimum_entry_size = 56
        if entry_size < minimum_entry_size or not count:
            raise ValueError("Invalid ELF program header table")
        for index in range(count):
            stream.seek(offset + index * entry_size)
            entry = stream.read(entry_size)
            if len(entry) != entry_size:
                raise ValueError("Truncated ELF program header table")
            if struct.unpack_from(endian + "I", entry)[0] in (2, 3):
                raise ValueError("Binary must be static: build with CGO_ENABLED=0")


def stage_files(root, binary, ca_bundle):
    spec = importlib.util.spec_from_file_location("generate_config", HERE / "generate-config.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    files = {
        "usr/bin/ipscoutdns": (binary.read_bytes(), 0o755),
        "etc/init.d/ipscoutdns": ((HERE / "files/ipscoutdns.init").read_bytes(), 0o755),
        "etc/ipscoutdns.conf": (
            generator.generate_config((REPO / "config/ipscoutdns.conf").read_text(encoding="utf-8")).encode(),
            0o644,
        ),
        "etc/ipscoutdns/active-domains.txt": ((REPO / "config/active-domains.txt").read_bytes(), 0o644),
        "etc/ipscoutdns/passive-domains.txt": ((REPO / "config/passive-domains.txt").read_bytes(), 0o644),
        "usr/share/licenses/ipscoutdns/LICENSE": ((REPO / "LICENSE").read_bytes(), 0o644),
        "usr/share/ipscoutdns/ca-certificates.crt": (ca_bundle.read_bytes(), 0o644),
        "usr/share/licenses/ipscoutdns/CA-NOTICE": (
            b"Mozilla CA certificate data, distributed in PEM source form.\n"
            b"Source: https://curl.se/ca/cacert.pem\n"
            b"License: Mozilla Public License 2.0\n"
            b"License text: https://www.mozilla.org/MPL/2.0/\n", 0o644,
        ),
    }
    for name, (contents, mode) in files.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
        destination.chmod(mode)
    for directory in (root, *(p for p in root.rglob("*") if p.is_dir())):
        directory.chmod(0o755)


def tar_bytes(root, epoch):
    """Use ordinary gzip/ustar and root ownership, readable by old BusyBox/opkg."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(root.rglob("*")):
                info = archive.gettarinfo(str(path), arcname="./" + path.relative_to(root).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                # Explicit permissions also make archive checks portable on
                # Windows, where chmod cannot preserve Unix execute bits.
                info.mode = 0o755 if info.isdir() or path.name in ("ipscoutdns", "postinst", "prerm") else 0o644
                with path.open("rb") if path.is_file() else io.BytesIO() as contents:
                    archive.addfile(info, contents if path.is_file() else None)
    return output.getvalue()


def build_ipk(root, control, version, architecture, output, epoch):
    control.mkdir()
    installed_size = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    (control / "control").write_text(
        f"Package: ipscoutdns\nVersion: {version}-1\nArchitecture: {architecture}\n"
        "Maintainer: IPScoutDNS contributors\nSection: net\nLicense: MIT\n"
        "Description: DNS filtering and reachability service\n"
        f"Installed-Size: {installed_size}\n",
        encoding="utf-8",
    )
    (control / "conffiles").write_text("\n".join(CONFFILES) + "\n", encoding="utf-8")
    for hook in ("postinst", "prerm"):
        shutil.copyfile(HERE / "files" / hook, control / hook)
        (control / hook).chmod(0o755)
    # OpenWrt IPKs are a gzip tar containing these three members, not an APK
    # renamed to .ipk. No recent libc/package ABI constraints are introduced.
    with tempfile.TemporaryDirectory() as temporary:
        members = Path(temporary)
        (members / "debian-binary").write_bytes(b"2.0\n")
        (members / "control.tar.gz").write_bytes(tar_bytes(control, epoch))
        (members / "data.tar.gz").write_bytes(tar_bytes(root, epoch))
        output.write_bytes(tar_bytes(members, epoch))


def build_apk(root, version, architecture, output, apk_tool):
    metadata = root / "lib/apk/packages"
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / "ipscoutdns.conffiles").write_text("\n".join(CONFFILES) + "\n", encoding="utf-8")
    (metadata / "ipscoutdns.conffiles_static").write_text(
        "".join(f"{name} {hashlib.sha256((root / name.lstrip('/')).read_bytes()).hexdigest()}\n"
                for name in CONFFILES), encoding="utf-8",
    )
    # fakeroot gives all files root ownership in the native APK v3 payload.
    environment = os.environ.copy()
    environment["STAGING_DIR_HOST"] = str(apk_tool.parent.parent)
    epoch = int(environment.get("SOURCE_DATE_EPOCH", "0"))
    for path in (root, *root.rglob("*")):
        os.utime(path, (epoch, epoch))
    subprocess.run([
        str(apk_tool.with_name("fakeroot")), str(apk_tool), "mkpkg", "--compat", "3.0.0",
        "--info", "name:ipscoutdns", "--info", f"version:{version}-r1",
        "--info", f"arch:{architecture}", "--info", "license:MIT",
        "--info", "description:DNS filtering and reachability service",
        "--script", f"post-install:{HERE / 'files/postinst'}",
        "--script", f"post-upgrade:{HERE / 'files/postinst'}",
        "--script", f"pre-deinstall:{HERE / 'files/prerm'}",
        "--files", str(root), "--output", str(output),
    ], check=True, env=environment)
    dump = subprocess.check_output([str(apk_tool), "adbdump", str(output)], text=True)
    if f"  arch: {architecture}\n" not in dump or any(
        owner != "root" for owner in re.findall(r"^\s+(?:user|group): (.+)$", dump, re.MULTILINE)
    ):
        raise ValueError(f"APK metadata or ownership is invalid: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true", help="emit the GitHub Actions build matrix")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--goarch", choices=ELF_TARGETS)
    parser.add_argument("--version", default="0.0.1")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--apk-tool", type=Path)
    parser.add_argument("--ca-bundle", type=Path, help="current Mozilla PEM CA bundle")
    args = parser.parse_args()
    targets = load_targets()
    if args.matrix:
        print(json.dumps({"include": [{"goarch": t["goarch"]} for t in targets]}, separators=(",", ":")))
        return
    if any(value is None for value in (args.binary, args.goarch, args.output, args.apk_tool, args.ca_bundle)):
        parser.error("--binary, --goarch, --output, --apk-tool and --ca-bundle are required")
    version = (args.version or "0.0.1").removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[._+-][a-zA-Z0-9._+-]+)?", version):
        parser.error("version must be a release version such as 1.2.3 or v1.2.3")
    binary = args.binary.resolve()
    validate_binary(binary, args.goarch)
    if b"-----BEGIN CERTIFICATE-----" not in args.ca_bundle.read_bytes():
        parser.error("CA bundle must contain PEM certificates")
    target = next(t for t in targets if t["goarch"] == args.goarch)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        root = work / "root"
        stage_files(root, binary, args.ca_bundle)
        (output / f"ipscoutdns-{version}-openwrt-{args.goarch}.tar.gz").write_bytes(tar_bytes(root, epoch))
        for architecture in target["ipk"]:
            control = work / f"control-{architecture}"
            build_ipk(root, control, version, architecture,
                      output / f"ipscoutdns-{version}-openwrt-{architecture}.ipk", epoch)
        for architecture in target["apk"]:
            build_apk(root, version, architecture,
                      output / f"ipscoutdns-{version}-openwrt-{architecture}.apk", args.apk_tool.resolve())
    print(f"Packaged {args.goarch}: {len(target['ipk'])} IPKs, {len(target['apk'])} APKs, 1 archive")


if __name__ == "__main__":
    main()
