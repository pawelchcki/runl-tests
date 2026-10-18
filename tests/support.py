"""Run the published executable with isolated preferences and safe diagnostics."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class RuntimeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("RUNL_TEST_BINARY")
        if not supplied:
            raise unittest.SkipTest("Set RUNL_TEST_BINARY to run published-binary acceptance tests")
        cls.binary = Path(supplied).resolve()
        if not cls.binary.is_file():
            raise RuntimeError("RUNL_TEST_BINARY does not identify a downloaded executable")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="runl-public-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # Keep the native login session for Keychain/Credential Manager, while
        # passing no workflow credential or pre-existing runl configuration.
        allowed = {
            "PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "WINDIR",
            "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
            "USER", "USERNAME", "LOGNAME", "SHELL", "__CF_USER_TEXT_ENCODING",
        }
        self.env = {key: value for key, value in os.environ.items() if key in allowed}
        self.env.update(
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_STATE_HOME=str(self.root / "state"),
            APPDATA=str(self.root / "config"),
            LOCALAPPDATA=str(self.root / "state"),
        )
        self.preferences = self.root / "config/runl/config.json"
        self.config(credential_backend="none", auto_update=False)

    def config(self, **settings):
        self.preferences.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.preferences.write_text(json.dumps(settings), encoding="utf-8")
        self.preferences.chmod(0o600)

    def command(self, *args):
        return ([] if os.name == "nt" else ["/bin/sh"]) + [str(self.binary), *args]

    def runl(self, *args, extra_env=None, input=None, timeout=30):
        environment = dict(self.env)
        for key, value in (extra_env or {}).items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        return subprocess.run(
            self.command(*args), env=environment, input=input,
            capture_output=True, timeout=timeout,
        )

    def assert_status(self, result, expected, message="Unexpected CLI exit status"):
        # Never attach captured output: a regression may have leaked a secret.
        self.assertEqual(result.returncode, expected, message)

    def json_result(self, result):
        self.assert_status(result, 0)
        try:
            return json.loads(result.stdout)
        except (ValueError, UnicodeError):
            self.fail("CLI did not return valid JSON")
