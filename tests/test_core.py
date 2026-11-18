"""Unit tests of the web layer's building blocks: TOTP, recovery codes, the ssh policy,
sealed secrets, API token format and backup encryption.

    python -m unittest tests.test_core
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.web import shellpolicy, totp  # noqa: E402


class Totp(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # RFC 6238 test key "12345678901234567890"

    def test_rfc6238_vectors(self):
        for t, want in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")):
            self.assertEqual(totp.code_at(self.SECRET, t // 30), want)

    def test_verify_window_and_replay(self):
        at = 1234567890
        code = totp.code_at(self.SECRET, at // 30)
        step = totp.verify(self.SECRET, code, 0, at=at)
        self.assertEqual(step, at // 30)
        self.assertEqual(totp.verify(self.SECRET, code, step, at=at), 0)          # works once
        self.assertTrue(totp.verify(self.SECRET, code, 0, at=at + 30))           # one step of drift
        self.assertEqual(totp.verify(self.SECRET, code, 0, at=at + 90), 0)
        self.assertEqual(totp.verify(self.SECRET, "12345", 0, at=at), 0)

    def test_recovery_codes(self):
        codes = totp.new_recovery_codes()
        self.assertEqual(len(set(codes)), 10)
        stored = [totp.hash_recovery(c) for c in codes]
        left = totp.use_recovery(stored, codes[3].upper())
        self.assertEqual(len(left), 9)
        self.assertIsNone(totp.use_recovery(left, codes[3]))
        self.assertTrue(totp.looks_like_recovery(codes[0]))
        self.assertFalse(totp.looks_like_recovery("123456"))


class SshPolicy(unittest.TestCase):
    def test_allowed(self):
        for ok in ("ssh host", "ssh user@host", "ssh -p 2222 -l me host", "ssh -4 -C host uptime",
                   "ssh -vvv host", "ssh -t host top", "ssh -- host"):
            self.assertEqual(shellpolicy.validate_ssh(ok)[0], "ssh", ok)

    def test_refused(self):
        for bad in ("", "bash", "sh -c id", "/usr/bin/ssh host", "ssh", "ssh -p", "ssh -o ProxyCommand=id host",
                    "ssh -oProxyCommand=id host", "ssh -F cfg host", "ssh -vF cfg host", "ssh -J j host",
                    "ssh -L 1:h:2 host", "ssh -R 1:h:2 host", "ssh -D 1080 host", "ssh -W h:2 j",
                    "ssh -i key host", "ssh -I lib.so host", "ssh -E log host", "ssh -S sock host",
                    "ssh -N host", "ssh -f host", "ssh -M host", "ssh -O exit host", "ssh -e ~ host",
                    "ssh -- -oProxyCommand=id", "ssh 'unbalanced"):
            with self.assertRaises(shellpolicy.PolicyError, msg=bad):
                shellpolicy.validate_ssh(bad)

    def test_harden_pins_own_files_first(self):
        with tempfile.TemporaryDirectory() as d:
            home = shellpolicy.user_home(d, 7)
            cdir = shellpolicy.control_dir(d, 7)
            cmd = shellpolicy.harden(["ssh", "-p", "22", "host"], home, cdir)
            self.assertTrue(cmd.startswith("ssh -F "))
            for want in ("IdentityAgent=none", "IdentitiesOnly=yes", "-e none", f"ControlPath={cdir}/%C",
                         "UserKnownHostsFile=" + os.path.join(home, ".ssh", "known_hosts")):
                self.assertIn(want, cmd)
            self.assertTrue(cmd.endswith("-p 22 host"))
            self.assertEqual(os.stat(home).st_mode & 0o777, 0o700)

    def test_own_multiplexing(self):
        self.assertIn("ControlPath=/x/%C", shellpolicy.with_own_multiplexing("ssh host", "/x"))
        self.assertEqual(shellpolicy.with_own_multiplexing("ssh -S /s host", "/x"), "ssh -S /s host")
        self.assertEqual(shellpolicy.with_own_multiplexing("htop", "/x"), "htop")


class Crypto(unittest.TestCase):
    def test_sealer(self):
        from app.web import secretbox
        with tempfile.TemporaryDirectory() as d:
            key = secretbox.app_key(Path(d))
            self.assertEqual(secretbox.app_key(Path(d)), key)             # stable once created
            a, b = secretbox.sealer(key, "sso"), secretbox.sealer(key, "mfa")
            blob = a.seal("client-secret")
            self.assertTrue(blob.startswith("v1:"))
            self.assertEqual(a.open(blob), "client-secret")
            with self.assertRaises(Exception):
                b.open(blob)                                              # another purpose's key

    def test_backup_encryption(self):
        from app.web import backup
        blob = backup.encrypt_bytes(b"payload", "a long passphrase")
        self.assertTrue(blob.startswith(b"SUITEBK1"))
        self.assertEqual(backup.decrypt_bytes(blob, "a long passphrase"), b"payload")
        with self.assertRaises(backup.BackupError):
            backup.decrypt_bytes(blob, "the wrong one!")

    def test_token_format(self):
        from app.web import tokens
        self.assertIsNone(tokens.parse("ares_xyz_abc"))
        self.assertIsNone(tokens.parse("other_deadbeef_" + "a" * 43))


if __name__ == "__main__":
    unittest.main()
