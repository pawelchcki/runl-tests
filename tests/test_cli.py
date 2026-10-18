"""Observe public CLI and preference behavior without implementation imports."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re

from tests.support import RuntimeCase


def native_path(value):
    # Portable executables can report Windows drives using POSIX notation.
    # Compare the named file without requiring one spelling of its drive.
    if os.name == "nt":
        value = re.sub(r"^/([A-Za-z])/", r"\1:/", value)
    return Path(value)


class PublishedCli(RuntimeCase):
    def test_version_identifies_the_downloaded_executable(self):
        result = self.runl("--version")
        self.assert_status(result, 0)
        expected = "0.1.0+" + hashlib.sha256(self.binary.read_bytes()).hexdigest()[:40]
        try:
            version = result.stdout.decode("ascii").strip()
        except UnicodeError:
            self.fail("Version did not return an ASCII package identity")
        self.assertTrue(version in (expected, "runl " + expected), "Version does not identify the downloaded executable")

    def test_native_metadata_matches_the_executing_host(self):
        self.assertTrue(self.binary.read_bytes().startswith(b"MZ"), "Expected a portable executable")
        result = self.runl("--metadata", timeout=60)
        self.assert_status(result, 0)
        self.assertTrue(result.stdout == b"", "Metadata must use stderr")
        try:
            facts = json.loads(result.stderr)
        except (ValueError, UnicodeError):
            self.fail("Metadata did not return valid JSON")
        self.assertEqual(facts.get("os"), platform.system(), "Wrong native operating system")
        aliases = {"amd64": "x86_64", "AMD64": "x86_64", "aarch64": "arm64"}
        expected = aliases.get(platform.machine(), platform.machine())
        actual = aliases.get(facts.get("architecture"), facts.get("architecture"))
        self.assertEqual(actual, expected, "Wrong native architecture")
        self.assertEqual(facts.get("libc"), "cosmopolitan")
        self.assertTrue(facts.get("processor"), "Missing processor identity")
        self.assertTrue(facts.get("kernel_release"), "Missing kernel release")
        expected_kernel = platform.version() if os.name == "nt" else os.uname().release
        self.assertEqual(facts.get("kernel_release"), expected_kernel, "Wrong native kernel")

    def test_help_and_invalid_arguments_have_documented_exit_codes(self):
        self.assert_status(self.runl("--help"), 0)
        for arguments in [
            ("with-secrets", "A", "A", "--", "tool"),
            ("config", "set", "missing-setting", "value"),
            ("config", "set", "auto-update", "maybe"),
        ]:
            result = self.runl(*arguments)
            self.assert_status(result, 2)
            self.assertTrue(result.stdout == b"", "Invalid arguments must not return data")


class Preferences(RuntimeCase):
    def show(self):
        return self.json_result(self.runl("config", "show"))

    def set_preference(self, key, value):
        self.assert_status(self.runl("config", "set", key, value), 0)

    def test_reading_defaults_does_not_create_preferences(self):
        self.preferences.unlink()
        self.preferences.parent.rmdir()
        result = self.show()
        self.assertEqual(native_path(result["path"]), self.preferences)
        self.assertEqual(result["effective"], {
            "update_track": "production", "auto_update": True, "credential_backend": "none",
        })
        self.assertFalse(self.preferences.exists())
        self.assertFalse((self.root / "state").exists())
        path = self.runl("config", "path")
        self.assert_status(path, 0)
        self.assertEqual(native_path(path.stdout.decode().strip()), self.preferences, "Wrong preference path")

    def test_preferences_persist_and_environment_overrides_are_temporary(self):
        self.set_preference("update-track", "staging")
        self.set_preference("auto-update", "true")
        saved = self.preferences.read_bytes()
        result = self.json_result(self.runl("config", extra_env={
            "RUNL_UPDATE_TRACK": "production", "RUNL_NO_UPDATE": "1",
        }))
        self.assertEqual(result["effective"]["update_track"], "production")
        self.assertFalse(result["effective"]["auto_update"])
        self.assertEqual(self.preferences.read_bytes(), saved)
        self.assertEqual(self.show()["effective"]["update_track"], "staging")
        self.assertTrue(self.show()["effective"]["auto_update"])
        self.assertEqual(list(self.preferences.parent.glob("*.tmp-*")), [])
        if os.name != "nt":
            self.assertEqual(self.preferences.stat().st_mode & 0o777, 0o600)

    def test_reset_restores_defaults_without_a_secret_file_backend(self):
        self.set_preference("update-track", "staging")
        self.set_preference("credential-backend", "auto")
        self.assert_status(self.runl("config", "reset"), 0)
        self.assertEqual(self.show()["effective"], {
            "update_track": "production", "auto_update": True, "credential_backend": "none",
        })
        before = self.preferences.read_bytes()
        self.assert_status(self.runl("config", "set", "credential-backend", "file"), 2)
        self.assertEqual(self.preferences.read_bytes(), before)

    def test_invalid_preferences_are_reported_and_can_be_reset(self):
        for payload in ["not json", '{"auto_update":"false"}', '{"update_track":"unknown"}', '{"unknown":1}', "x" * 65537]:
            self.preferences.write_text(payload, encoding="utf-8")
            self.assert_status(self.runl("config", "show"), 1)
            self.assert_status(self.runl("config", "set", "auto-update", "false"), 1)
            self.assertEqual(self.preferences.read_text(encoding="utf-8"), payload)
        self.assert_status(self.runl("config", "reset"), 0)
        self.assertTrue(self.show()["effective"]["auto_update"])

    def test_unwritable_preference_path_is_reported(self):
        self.preferences.unlink()
        self.preferences.parent.rmdir()
        self.preferences.parent.write_text("blocked", encoding="utf-8")
        self.assert_status(self.runl("config", "set", "auto-update", "false"), 1)
        self.assertEqual(self.preferences.parent.read_text(), "blocked")
