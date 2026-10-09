"""Validate architecture labeling, static linking, and legacy IPK payloads."""

import importlib.util
import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("build_packages", Path(__file__).with_name("build-packages.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def elf_header(goarch, program_type=1):
    elf_class, byte_order, machine = builder.ELF_TARGETS[goarch]
    endian = "<" if byte_order == 1 else ">"
    header = bytearray(64)
    header[:6] = b"\x7fELF" + bytes((elf_class, byte_order))
    struct.pack_into(endian + "H", header, 18, machine)
    if elf_class == 1:
        entry_size = 32
        struct.pack_into(endian + "I", header, 28, 64)
        struct.pack_into(endian + "HH", header, 42, entry_size, 1)
    else:
        entry_size = 56
        struct.pack_into(endian + "Q", header, 32, 64)
        struct.pack_into(endian + "HH", header, 54, entry_size, 1)
    return header + struct.pack(endian + "I", program_type) + bytes(entry_size - 4)


class PackageTests(unittest.TestCase):
    def test_every_cpu_family_and_endian_variant_is_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            for goarch in builder.ELF_TARGETS:
                with self.subTest(goarch=goarch):
                    binary.write_bytes(elf_header(goarch))
                    builder.validate_binary(binary, goarch)
            binary.write_bytes(elf_header("mips"))
            with self.assertRaisesRegex(ValueError, "architecture"):
                builder.validate_binary(binary, "mipsle")
            binary.write_bytes(elf_header("arm"))
            with self.assertRaisesRegex(ValueError, "architecture"):
                builder.validate_binary(binary, "arm64")

    def test_rejects_dynamic_interpreter_and_dynamic_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            for program_type in (2, 3):
                binary.write_bytes(elf_header("amd64", program_type))
                with self.assertRaisesRegex(ValueError, "static"):
                    builder.validate_binary(binary, "amd64")
            binary.write_bytes(elf_header("amd64")[:64])
            with self.assertRaisesRegex(ValueError, "Truncated"):
                builder.validate_binary(binary, "amd64")

    def test_ipk_has_legacy_container_metadata_hooks_and_preserved_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            binary = work / "binary"
            binary.write_bytes(elf_header("386"))
            root = work / "root"
            ca_bundle = work / "ca.pem"
            ca_bundle.write_bytes(b"-----BEGIN CERTIFICATE-----\ntest-fixture\n-----END CERTIFICATE-----\n")
            builder.stage_files(root, binary, ca_bundle)
            package = work / "test.ipk"
            builder.build_ipk(root, work / "control", "1.2.3", "x86", package, 123)
            first_build = package.read_bytes()
            with tarfile.open(package, "r:gz") as outer:
                self.assertEqual(set(outer.getnames()), {"./debian-binary", "./control.tar.gz", "./data.tar.gz"})
                self.assertEqual(outer.extractfile("./debian-binary").read(), b"2.0\n")
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile("./control.tar.gz").read()), mode="r:gz") as control:
                    metadata = control.extractfile("./control").read().decode()
                    self.assertIn("Architecture: x86\n", metadata)
                    self.assertIn("Version: 1.2.3-1\n", metadata)
                    self.assertNotIn("Depends:", metadata)
                    self.assertNotIn("libc", metadata)
                    self.assertEqual(control.extractfile("./conffiles").read().decode().splitlines(), list(builder.CONFFILES))
                    self.assertEqual(control.getmember("./postinst").mode, 0o755)
                    hook_commands = [line for line in control.extractfile("./postinst").read().splitlines()
                                     if line and not line.startswith(b"#")]
                    self.assertEqual(hook_commands, [b"exit 0"])
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile("./data.tar.gz").read()), mode="r:gz") as data:
                    self.assertEqual(data.extractfile("./usr/bin/ipscoutdns").read(), binary.read_bytes())
                    self.assertEqual(data.getmember("./usr/bin/ipscoutdns").mode, 0o755)
                    self.assertEqual(data.extractfile("./usr/share/ipscoutdns/ca-certificates.crt").read(), ca_bundle.read_bytes())
                    self.assertTrue(all(member.uid == member.gid == 0 for member in data))
                    self.assertNotIn("./CONTROL", data.getnames())
                    config = data.extractfile("./etc/ipscoutdns.conf").read().decode()
                    self.assertIn("active_domains_file=/etc/ipscoutdns/active-domains.txt\n", config)
                    self.assertIn("tcp_route=proxy\n", config)
            builder.build_ipk(root, work / "control2", "1.2.3", "x86", package, 123)
            self.assertEqual(package.read_bytes(), first_build)

    def test_catalog_includes_common_modern_and_legacy_architectures(self):
        targets = {target["goarch"]: target for target in builder.load_targets()}
        self.assertEqual(set(targets), set(builder.ELF_TARGETS))
        for goarch, architecture in (("mips", "ar71xx"), ("mipsle", "ramips_24kec"), ("386", "x86")):
            self.assertIn(architecture, targets[goarch]["ipk"])
            self.assertNotIn(architecture, targets[goarch]["apk"])
        self.assertIn("aarch64_cortex-a53", targets["arm64"]["apk"])


if __name__ == "__main__":
    unittest.main()
