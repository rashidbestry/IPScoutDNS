"""Check that packaging preserves every byte of config and domain inputs."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-config.py")


class GenerateConfigTests(unittest.TestCase):
    def test_cli_preserves_canonical_config_and_domain_lists_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            inputs = SCRIPT.parents[2] / "config"
            subprocess.run(
                [sys.executable, str(SCRIPT), str(inputs / "ipscoutdns.conf"),
                 str(output / "ipscoutdns.conf"),
                 "--active-domains-source", str(inputs / "active-domains.txt"),
                 "--active-domains-destination", str(output / "active-domains.txt"),
                 "--passive-domains-source", str(inputs / "passive-domains.txt"),
                 "--passive-domains-destination", str(output / "passive-domains.txt")],
                check=True, capture_output=True, text=True,
            )
            for name in ("ipscoutdns.conf", "active-domains.txt", "passive-domains.txt"):
                self.assertEqual((output / name).read_bytes(), (inputs / name).read_bytes())

    def test_cli_preserves_paths_commands_whitespace_and_line_endings(self):
        source = (
            b"# Keep this comment and its trailing spaces  \n"
            b"pre_launch_commands={\n    active_domains_file=custom.txt\n}\n"
            b"active_domains_file=active-domains.txt\n"
            b"passive_domains_file=passive-domains.txt\n"
            b"future_setting=keep-this-too"
        )
        for contents in (source, source + b"\n", source.replace(b"\n", b"\r\n")):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path = root / "source.conf"
                path.write_bytes(contents)
                output = root / "generated" / "ipscoutdns.conf"
                subprocess.run([sys.executable, str(SCRIPT), str(path), str(output)],
                               check=True, capture_output=True, text=True)
                self.assertEqual(output.read_bytes(), contents)

    def test_incomplete_domain_copy_arguments_do_not_create_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "generated.conf"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root / "source.conf"), str(destination),
                 "--active-domains-source", str(root / "active.txt")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be provided together", result.stderr)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
