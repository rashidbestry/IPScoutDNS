# OpenWrt service

The release workflow builds static Go binaries, then uses `build-packages.py`
to create IPKs, native APK v3 packages, and manual-install archives. The
OpenWrt 25.12.5 x86 SDK supplies only the host APK/fakeroot tools. Its target
compiler and libc are not used. IPKs use the traditional gzip/tar container
accepted by older opkg versions, with no dependency on a recent libc ABI.

`architectures.json` is the release architecture catalog. One conservative
binary is shared by the package names for each CPU family:

| CPU family / archive suffix | CPU setting | IPK architecture names |
| --- | --- | --- |
| `386` | `GO386=softfloat` | `x86`, `i386_geode`, `i386_pentium-mmx`, `i386_pentium4` |
| `amd64` | `GOAMD64=v1` | `x86_64` |
| `arm` | `GOARM=5,softfloat` | `arm_arm926ej-s`, `arm_arm1176jzf-s_vfp`, `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_vfpv4`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_vfpv3-d16`, `arm_cortex-a9_neon`, `arm_cortex-a15_neon-vfpv4`, `arm_xscale`, `kirkwood` |
| `arm64` | `GOARM64=v8.0` | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a72`, `aarch64_cortex-a76` |
| `mips` | `GOMIPS=softfloat` | `mips_24kc`, `mips_4kc`, `mips_mips32`, `ar71xx` |
| `mipsle` | `GOMIPS=softfloat` | `mipsel_24kc`, `mipsel_24kc_24kf`, `mipsel_74kc`, `mipsel_mips32`, `ramips_24kec`, `ramips_1004kc` |
| `mips64` | `GOMIPS64=softfloat` | `mips64_mips64r2`, `mips64_octeonplus`, `mips64_octeon` |
| `mips64le` | `GOMIPS64=softfloat` | `mips64el_mips64r2` |
| `riscv64` | `GORISCV64=rva20u64` | `riscv64_riscv64`, `riscv64_generic` |
| `loong64` | Go's baseline LoongArch64 ISA | `loongarch64_generic` |

APK names are the corresponding current names in the catalog; historical
opkg-only aliases are omitted. All binaries use `CGO_ENABLED=0` and
`-ldflags="-s -w -X main.openWrtPackage=true"`. ELF class, machine, byte order,
and absence of dynamic linking are checked before packaging. APK metadata and
root ownership are verified with the native APK tool.

The oldest tested firmware baseline is OpenWrt 12.09 on suitable x86 hardware.
`smoke-legacy.py` boots original 12.09 (Linux 3.3.8) and 14.07 (Linux 3.10.49)
x86 disk images in QEMU with 64 MiB RAM, then tests opkg installation without
feed dependencies, disabled installation state, service start/stop, bundled
certificate selection, a DNS fallback answer, edited config preservation,
and removal. This establishes x86 emulator coverage for a small smoke
workload; it does not establish memory requirements under a full probe
workload or physical-device coverage for every architecture.

During validation, 14.07's opkg crashed on `--force-reinstall`; normal version
upgrades passed and preserved modified config/domain files. Use a normal
version upgrade on this baseline.

[Go's runtime requirements](https://go.dev/wiki/MinimumRequirements) still
apply: normally Linux 3.2+, Pentium MMX or newer for 32-bit x86,
ARMv5 or newer in little-endian mode, MIPS32 or
newer, and ARMv8-A for ARM64. MIPS64 little-endian should use Linux 4.8+;
LoongArch64 needs Linux 5.19+. RISC-V must satisfy RVA20U64. Firmware must also
support the device itself. Big-endian ARM, ARMv4/FA526,
ARC, and OpenWrt's PowerPC/e5500 CPUs have no suitable current Go target and
are excluded. A modern Go compiler on the router is not required.

Binary size, free flash, RAM, domain count and concurrency also limit device
support. For small devices, start with `parallel_tests=2`,
`dns_query_parallel=2`, `passive_resolve_parallel=1` and `save_logs=false`,
then measure memory use with your domain lists. Release packaging preserves
the canonical config byte-for-byte, including comments and line endings. With
`/etc/ipscoutdns.conf`, the packaged binary resolves the default relative domain
filenames under `/etc/ipscoutdns/`; other relative filenames resolve beside the
selected config. Packaging does not silently lower these settings.

For an unlisted package architecture name, use the archive matching the CPU
and byte order. It contains installed paths (`usr/bin/`, `etc/`), not a
regular Linux config layout. Extract into a temporary directory and copy
files explicitly; on upgrades retain your existing config/domain lists:

```sh
mkdir -p /tmp/ipscoutdns-install
tar -xzf ipscoutdns-<version>-openwrt-<CPU-family>.tar.gz -C /tmp/ipscoutdns-install
cp /tmp/ipscoutdns-install/usr/bin/ipscoutdns /usr/bin/ipscoutdns
mkdir -p /etc/ipscoutdns
cp /tmp/ipscoutdns-install/etc/ipscoutdns.conf /etc/ipscoutdns.conf
cp /tmp/ipscoutdns-install/etc/ipscoutdns/*.txt /etc/ipscoutdns/
cp /tmp/ipscoutdns-install/etc/init.d/ipscoutdns /etc/init.d/ipscoutdns
mkdir -p /usr/share/ipscoutdns
cp /tmp/ipscoutdns-install/usr/share/ipscoutdns/ca-certificates.crt /usr/share/ipscoutdns/
```

Release packages include the current Mozilla root bundle from
[curl's CA Extract](https://curl.se/docs/caextract.html) at
`/usr/share/ipscoutdns/ca-certificates.crt`; no certificate or libc package
dependency prevents installation on old firmware. The init service selects
this file through `SSL_CERT_FILE`, preserving an explicitly configured value.
Manual binary launches on firmware without system roots must set
`SSL_CERT_FILE=/usr/share/ipscoutdns/ca-certificates.crt` too. Package upgrades
refresh the bundled roots. After an upgrade, restart the service explicitly
to run the new binary.

IPScoutDNS reads the router's `/etc/TZ` at startup, including fixed offsets and
daylight-saving rules, without installing `zoneinfo` or changing the service
environment. An explicit `TZ` override takes precedence. Restart after changing
the router timezone. `passive_resolve_time=00:00` schedules daily router-midnight
passes; `passive_resolve_interval` is ignored while a clock time is configured.
Daily waits recheck the OS clock every 30 seconds to follow NTP corrections,
without replaying missed dates or repeating a date after a backward correction.

The package installs `files/ipscoutdns.init` as `/etc/init.d/ipscoutdns`.
It runs `/usr/bin/ipscoutdns --config /etc/ipscoutdns.conf`. Firmware with
procd restarts after crashes and sends stdout/stderr to the system log.
OpenWrt 12.09 uses a classic `start-stop-daemon` fallback, with start/stop,
reload and boot enable/disable support but no automatic crash respawn.
Release packages leave the service disabled after installation.

For a manual installation, copy the binary to `/usr/bin/ipscoutdns`, the
OpenWrt config to `/etc/ipscoutdns.conf`, the domain lists to
`/etc/ipscoutdns/active-domains.txt` and `/etc/ipscoutdns/passive-domains.txt`,
and `files/ipscoutdns.init` to `/etc/init.d/ipscoutdns`. The generated config preserves all source settings and only relocates
nonempty domain-list paths to their installed files. Runtime outputs are
stored automatically under `/tmp/ipscoutdns/`. The listener and proxy settings
come from `config/ipscoutdns.conf`; choose settings suitable for the router.

```sh
chmod +x /usr/bin/ipscoutdns /etc/init.d/ipscoutdns
/etc/init.d/ipscoutdns start
```

On procd firmware, inspect status and system logs with
`/etc/init.d/ipscoutdns status` and `logread -e ipscoutdns`.
On classic init firmware, use `pidof ipscoutdns` to check the process;
saved IPScoutDNS logs follow the configured logging settings.

Enable boot startup explicitly:

```sh
/etc/init.d/ipscoutdns enable
```

After editing the config or packaged domain lists, apply changes with
`/etc/init.d/ipscoutdns reload`. On procd firmware, procd restarts the process when the tracked
files change; files are not watched automatically. If you configure domain
lists at custom paths, use `/etc/init.d/ipscoutdns restart` after editing them.
IPScoutDNS reads its INI config at startup; it does not use UCI or SIGHUP reload.

```sh
/etc/init.d/ipscoutdns restart
/etc/init.d/ipscoutdns stop
/etc/init.d/ipscoutdns disable
```

In active mode, choose a listen address and port that are free. OpenWrt's
dnsmasq normally occupies port 53. In passive mode IPScoutDNS does not open
a DNS listener. The service creates `/tmp/ipscoutdns` at every start because
`/tmp` is cleared on reboot.

