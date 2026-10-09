"""Check classic init support and preserve procd command/file tracking."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "posix", "OpenWrt shell behavior is tested on Linux")
class InitTests(unittest.TestCase):
    def run_init(self, procd, action, missing_config=False, certificate_file=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "ipscoutdns"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            config = root / "ipscoutdns.conf"
            certificates = root / "ca-certificates.crt"
            certificates.write_text("bundled test roots\n")
            if not missing_config:
                config.write_text("mode=active\n")
            script = Path(__file__).with_name("files").joinpath("ipscoutdns.init").read_text()
            script = script.replace("[ -r /lib/functions/procd.sh ]", "[ \"$TEST_PROCD\" = 1 ]")
            script = script.replace("PROG=/usr/bin/ipscoutdns", f'PROG="{binary}"')
            script = script.replace("CONFIG=/etc/ipscoutdns.conf", f'CONFIG="{config}"')
            script = script.replace("/tmp/ipscoutdns", str(root / "outputs"))
            script = script.replace("/usr/share/ipscoutdns/ca-certificates.crt", str(certificates))
            script = script.replace("start-stop-daemon", "start_stop_daemon")
            patched = root / "init"
            patched.write_text(script)
            wrapper = root / "wrapper.sh"
            wrapper.write_text('''
start_stop_daemon() { printf 'daemon %s\n' "$*"; }
sleep() { :; }
procd_open_instance() { echo open; }
procd_close_instance() { echo close; }
procd_set_param() { printf 'procd %s\n' "$*"; }
. "$1"
if [ "$TEST_PROCD" = 1 ]; then
    # Legacy handlers must not shadow procd's rc.common lifecycle.
    if command -v start >/dev/null 2>&1; then exit 90; fi
fi
"$2"
''')
            environment = os.environ.copy()
            environment["TEST_PROCD"] = "1" if procd else "0"
            environment.pop("USE_PROCD", None)
            environment.pop("SSL_CERT_FILE", None)
            if certificate_file:
                environment["SSL_CERT_FILE"] = certificate_file
            return subprocess.run(["sh", str(wrapper), str(patched), action],
                                  env=environment, capture_output=True, text=True)

    def test_classic_start_stop_and_reload(self):
        start = self.run_init(False, "start")
        self.assertEqual(start.returncode, 0, start.stderr)
        self.assertIn("daemon -S -b -x ", start.stdout)
        self.assertIn(" -- --config ", start.stdout)
        stop = self.run_init(False, "stop")
        self.assertEqual(stop.returncode, 0, stop.stderr)
        self.assertIn(" -s TERM", stop.stdout)
        reload = self.run_init(False, "reload")
        self.assertEqual(reload.returncode, 0, reload.stderr)
        self.assertLess(reload.stdout.index("daemon -K"), reload.stdout.index("daemon -S"))

    def test_procd_keeps_command_files_respawn_and_logs(self):
        result = self.run_init(True, "start_service")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("procd command ", result.stdout)
        self.assertIn(" --config ", result.stdout)
        self.assertIn("/etc/ipscoutdns/active-domains.txt /etc/ipscoutdns/passive-domains.txt", result.stdout)
        self.assertIn("procd respawn 3600 5 5", result.stdout)
        self.assertIn("procd term_timeout 10", result.stdout)
        self.assertIn("procd stdout 1", result.stdout)
        self.assertIn("procd stderr 1", result.stdout)
        self.assertIn("procd env SSL_CERT_FILE=", result.stdout)

    def test_explicit_certificate_file_is_preserved(self):
        result = self.run_init(True, "start_service", certificate_file="/custom/roots.pem")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("procd env SSL_CERT_FILE=/custom/roots.pem", result.stdout)

    def test_missing_config_never_starts_daemon(self):
        for procd in (False, True):
            result = self.run_init(procd, "start_service" if procd else "start", missing_config=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("config is not readable", result.stdout + result.stderr, repr(result))
            self.assertNotIn("daemon -S", result.stdout)
            self.assertNotIn("procd command", result.stdout)


if __name__ == "__main__":
    unittest.main()
