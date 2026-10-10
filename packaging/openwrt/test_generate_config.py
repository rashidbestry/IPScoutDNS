"""Check that packaging preserves source config data and domain-list contents."""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-config.py")
SPEC = importlib.util.spec_from_file_location("generate_config", SCRIPT)
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class GenerateConfigTests(unittest.TestCase):
    def test_canonical_config_preserves_all_data_except_installed_input_paths(self):
        source = SCRIPT.parents[2] / "config" / "ipscoutdns.conf"
        contents = source.read_text(encoding="utf-8")
        expected = contents.replace(
            "active_domains_file=active-domains.txt",
            "active_domains_file=/etc/ipscoutdns/active-domains.txt",
        ).replace(
            "passive_domains_file=passive-domains.txt",
            "passive_domains_file=/etc/ipscoutdns/passive-domains.txt",
        )
        self.assertEqual(generator.generate_config(contents), expected)

    def test_nondefault_logging_schedules_probes_and_output_choices_survive(self):
        source = """mode=passive
server=192.0.2.10:1053
logs_enabled=false
save_logs=true
log_max_size=18MiB
log_keep_files=19
active_copy_interval=47m
active_log_copy_interval=23m
passive_resolve_time=03:27
passive_resolve_interval=13h
passive_resolve_parallel=5
ttl=37m
answer_ttl=91
dns_timeout=7s
tcp_timeout=9s
tcp_port=8443
tcp_route=proxy
tcp_probe=false
tls_probe=false
http_probe=true
icmp_probe=false
parallel_tests=6
hosts_max_ips_per_domain=0
reachable_hosts=custom.hosts
reachable_domains_file=
reachable_ips_file=custom.ips
unreachable_domains_file=custom.failures
unreachable_ips_file=
future_setting=preserve-new-fields-too
"""
        self.assertEqual(generator.generate_config(source), source)

    def test_proxy_lists_aliases_interfaces_and_comments_survive(self):
        source = """# Keep DNS and TCP SOCKS5 proxy settings.
; proxy comment
mode=active
listen=192.0.2.10:9053
tls_route=proxy
dns_socks5=192.0.2.20:1081
dns_proxy_port=1082
tls_proxy=192.0.2.30:1083
tls_proxy_port=1084
direct_dns_interface=eth0
fallback_interface=eth1
direct_tcp_interface=eth2
direct_tcp_mark=0xff
reachable_domains=custom.domains
direct_dns={
    1.1.1.1,
    https://example.com/dns-query?key=value,
}
proxy_dns={
    9.9.9.9,
    https://proxy.example.com/dns-query?key=value,
}
"""
        self.assertEqual(generator.generate_config(source), source)

    def test_blank_optional_domain_path_remains_blank(self):
        source = "active_domains_file=\npassive_domains_file=custom.txt\n"
        self.assertEqual(
            generator.generate_config(source),
            "active_domains_file=\npassive_domains_file=/etc/ipscoutdns/passive-domains.txt\n",
        )

    def test_cli_generates_config_and_copies_both_domain_lists_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.conf"
            source.write_text("mode=active\ntcp_route=proxy\nsave_logs=true\n", encoding="utf-8")
            active = root / "active.txt"
            passive = root / "passive.txt"
            active.write_bytes(b"# patterns\r\n^example\\.com$\r\n")
            passive.write_bytes(b"# hosts\r\nexample.com\r\n")
            output = root / "generated"
            subprocess.run(
                [
                    sys.executable, str(SCRIPT), str(source), str(output / "ipscoutdns.conf"),
                    "--active-domains-source", str(active),
                    "--active-domains-destination", str(output / "active.txt"),
                    "--passive-domains-source", str(passive),
                    "--passive-domains-destination", str(output / "passive.txt"),
                ],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual((output / "ipscoutdns.conf").read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))
            self.assertEqual((output / "active.txt").read_bytes(), active.read_bytes())
            self.assertEqual((output / "passive.txt").read_bytes(), passive.read_bytes())

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
