#!/usr/bin/env python3
"""Pure offline regression tests for issuer/receiver sandbox policy comparison.

Fixtures are deliberately synthetic. They are NOT extracted Apple profiles.
"""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compare_systemgroup_policy as policy


OLD_ISSUER = """
(allow file-issue-extension
    (require-all
        (subpath "/private/var/containers/Shared/SystemGroup")
        (extension-class "com.apple.sandbox.system-group")))
"""
NEW_ISSUER = """
(allow file-issue-extension
    (require-all
        (subpath "/private/var/containers/Shared/SystemGroup")
        (require-any
            (extension-class "com.apple.sandbox.system-group")
            (extension-class "com.apple.app-sandbox.read-write"))))
"""
RECEIVER = """
(allow file-write-data
    (require-all
        (subpath "/private/var/containers/Shared/SystemGroup")
        (extension "com.apple.sandbox.system-group")
        (entitlement "com.apple.security.system-group-containers")))
"""


class AuthorizationComparisonTests(unittest.TestCase):
    def test_issuer_is_discovered(self):
        found = policy.rules(OLD_ISSUER, False)
        self.assertEqual(len(found), 1)
        self.assertIn("file-issue-extension", found[0])

    def test_generic_extension_class_change_is_detected(self):
        self.assertNotEqual(policy.rules(OLD_ISSUER, False),
                            policy.rules(NEW_ISSUER, False))

    def test_receiver_write_is_found(self):
        found = policy.rules(RECEIVER, False)
        self.assertEqual(len(found), 1)
        self.assertIn("file-write-data", found[0])

    def test_wildcard_operations_are_matched(self):
        text = '(deny file-write* (subpath "/private/var/containers/Shared/SystemGroup"))'
        self.assertEqual(len(policy.rules(text, False)), 1)

    def test_unrelated_rules_filtered(self):
        src = '(allow file-write-data (subpath "/tmp/disposable"))'
        self.assertEqual(policy.rules(src, False), [])
        self.assertEqual(len(policy.rules(src, True)), 1)

    def test_parentheses_inside_strings_and_comments(self):
        src = """(allow file-issue-extension
           ; an unmatched ) in a comment
           (subpath "/private/var/containers/Shared/SystemGroup/strange(thing)")
           (extension-class "com.apple.sandbox.system-group"))"""
        self.assertEqual(len(policy.rules(src, False)), 1)

    def test_main_reports_both_authorization_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "26.sb"
            after = Path(tmp) / "27.sb"
            before.write_text(OLD_ISSUER + RECEIVER, encoding="utf-8")
            after.write_text(NEW_ISSUER + RECEIVER, encoding="utf-8")
            output = io.StringIO()
            with patch.object(sys, "argv", ["compare_systemgroup_policy.py",
                                            str(before), str(after)]):
                with contextlib.redirect_stdout(output):
                    result = policy.main()
            self.assertEqual(result, 0)
            out = output.getvalue()
            self.assertIn("ISSUER: 26=1 27=1 new=1 removed=1", out)
            self.assertIn("RECEIVER_WRITE: 26=1 27=1 new=0 removed=0", out)
            self.assertIn("com.apple.app-sandbox.read-write", out)
            self.assertIn("UNVERIFIED INPUT", out)


if __name__ == "__main__":
    unittest.main()
