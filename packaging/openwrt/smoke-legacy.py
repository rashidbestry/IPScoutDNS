#!/usr/bin/env python3
"""Install and run the legacy x86 IPK on archived OpenWrt kernels in QEMU."""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path


IMAGE = "openwrt-x86-generic-combined-ext4.img.gz"
# Published checksum from the archived OpenWrt image directory.
FIRMWARE = {
    "12.09": ("attitude_adjustment/12.09", "6a2df76970e0d48e74114ebe6812851d"),
    "14.07": ("barrier_breaker/14.07", "3209aa3255b74726837e351908bbcd98"),
}
SUCCESS = "IPSCOUTDNS_LEGACY_SMOKE_PASSED"

SMOKE = r'''#!/bin/sh
exec >/dev/console 2>&1
set -ex
trap 'status=$?; if [ "$status" -ne 0 ]; then logread; echo IPSCOUTDNS_LEGACY_SMOKE_FAILED; fi' EXIT
uname -r
opkg install /root/ipscoutdns.ipk
if /etc/init.d/ipscoutdns enabled; then exit 1; fi
if pidof ipscoutdns; then exit 1; fi
# Override only the test router's config, after validating package installation.
cat >/etc/ipscoutdns.conf <<'EOF'
mode=active
server=127.0.0.1:53
save_logs=false
direct_dns={127.0.0.1:5354}
fallback_dns=127.0.0.1:5354
tcp_route=direct
active_domains_file=/etc/ipscoutdns/active-domains.txt
dns_query_parallel=1
parallel_tests=1
tcp_probe=false
tls_probe=false
http_probe=false
icmp_probe=false
EOF
echo '^allowed\.test$' >/etc/ipscoutdns/active-domains.txt
/etc/init.d/dnsmasq stop
sleep 1
dnsmasq --no-daemon --port=5354 --no-resolv --no-hosts --address=/example.test/192.0.2.1 &
/etc/init.d/ipscoutdns start
sleep 3
pidof ipscoutdns
tr '\000' '\n' </proc/$(pidof ipscoutdns)/environ | grep -q 'SSL_CERT_FILE=/usr/share/ipscoutdns/ca-certificates.crt'
nslookup example.test 127.0.0.1 >/tmp/answer
cat /tmp/answer
grep -q '192.0.2.1' /tmp/answer
grep VmRSS /proc/$(pidof ipscoutdns)/status
/etc/init.d/ipscoutdns stop
sleep 2
if pidof ipscoutdns; then exit 1; fi
# opkg must preserve edited configuration across an upgrade/reinstall.
opkg install /root/ipscoutdns-upgrade.ipk
grep -q 'dns_query_parallel=1' /etc/ipscoutdns.conf
opkg remove ipscoutdns
test ! -e /usr/bin/ipscoutdns
echo IPSCOUTDNS_LEGACY_SMOKE_PASSED
'''


def download(url, destination):
    with urllib.request.urlopen(url, timeout=60) as source, destination.open("wb") as output:
        shutil.copyfileobj(source, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="IPK with Architecture: x86")
    parser.add_argument("--firmware", choices=FIRMWARE, default="12.09")
    parser.add_argument("--memory", type=int, default=128, help="guest RAM in MiB")
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    release, image_md5 = FIRMWARE[args.firmware]
    base = f"https://archive.openwrt.org/{release}/x86/generic/"
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        compressed = work / IMAGE
        download(base + IMAGE, compressed)
        if hashlib.md5(compressed.read_bytes()).hexdigest() != image_md5:
            raise RuntimeError("Archived OpenWrt image checksum mismatch")
        image = work / "openwrt.img"
        with gzip.open(compressed, "rb") as source, image.open("wb") as output:
            shutil.copyfileobj(source, output)
        with image.open("rb") as disk:
            mbr = disk.read(512)
            # Generic image: partition 1 holds the kernel, partition 2 the rootfs.
            start, sectors = struct.unpack_from("<II", mbr, 446 + 16 + 8)
            if not start or not sectors:
                raise RuntimeError("Archived image does not contain a rootfs partition")
            disk.seek(start * 512)
            partition = work / "rootfs.ext4"
            partition.write_bytes(disk.read(sectors * 512))
        smoke = work / "smoke.sh"
        smoke.write_text(SMOKE, encoding="utf-8", newline="\n")
        rc_local = work / "rc.local"
        rc_local.write_text("#!/bin/sh\nsh /root/smoke.sh\nexit 0\n", encoding="utf-8")
        # Test a real version upgrade, rather than old opkg's force-reinstall
        # path. The new payload has identical content and a higher version.
        spec = importlib.util.spec_from_file_location("build_packages", Path(__file__).with_name("build-packages.py"))
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        upgrade_members = work / "upgrade-members"
        upgrade_control = work / "upgrade-control"
        upgrade_members.mkdir()
        upgrade_control.mkdir()
        with tarfile.open(args.package, "r:gz") as archive:
            for name in ("debian-binary", "data.tar.gz", "control.tar.gz"):
                (upgrade_members / name).write_bytes(archive.extractfile("./" + name).read())
        with tarfile.open(fileobj=io.BytesIO((upgrade_members / "control.tar.gz").read_bytes()), mode="r:gz") as archive:
            for member in archive:
                if member.isfile():
                    destination = upgrade_control / Path(member.name).name
                    destination.write_bytes(archive.extractfile(member).read())
                    destination.chmod(member.mode)
        control_file = upgrade_control / "control"
        control_file.write_text(re.sub(r"^(Version: .+)-1$", r"\1-2", control_file.read_text(), flags=re.MULTILINE))
        (upgrade_members / "control.tar.gz").write_bytes(builder.tar_bytes(upgrade_control, 0))
        upgrade = work / "upgrade.ipk"
        upgrade.write_bytes(builder.tar_bytes(upgrade_members, 0))
        files = [(args.package.resolve(), "/root/ipscoutdns.ipk"), (upgrade, "/root/ipscoutdns-upgrade.ipk"),
                 (smoke, "/root/smoke.sh"), (rc_local, "/etc/rc.local")]
        commands = work / "debugfs.commands"
        commands.write_text("rm /etc/rc.local\n" + "".join(
            f"write {json.dumps(str(source))} {destination}\n" for source, destination in files
        ) + "set_inode_field /etc/rc.local mode 0100755\n", encoding="utf-8")
        subprocess.run(["debugfs", "-w", "-f", str(commands), str(partition)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with image.open("r+b") as disk, partition.open("rb") as source:
            disk.seek(start * 512)
            shutil.copyfileobj(source, disk)
        log = args.log.resolve() if args.log else work / "qemu.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("wb") as output:
            process = subprocess.Popen([
                "qemu-system-i386", "-machine", "pc", "-accel", "tcg", "-m", str(args.memory),
                "-drive", f"file={image},format=raw,if=ide", "-display", "none",
                "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
            ], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            try:
                # Poll the log in Python; no fragile guest console input/login.
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline and process.poll() is None:
                    if re.search(r"^(?:" + SUCCESS + r"|IPSCOUTDNS_LEGACY_SMOKE_FAILED)\r?$",
                                 log.read_text(errors="replace"), re.MULTILINE):
                        break
                    time.sleep(1)
            finally:
                process.terminate()
                process.wait(timeout=10)
        contents = log.read_text(errors="replace")
        start = contents.find("+ trap ")
        print(contents[start:] if start >= 0 else contents[-16000:])
        if not re.search(r"^" + SUCCESS + r"\r?$", contents, re.MULTILINE):
            raise RuntimeError(f"OpenWrt {args.firmware} smoke test failed; inspect {log}")


if __name__ == "__main__":
    main()
