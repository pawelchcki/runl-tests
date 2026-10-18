"""Native black-box checks of the downloaded, unchanged production executable."""
import json
import hashlib
import os
from pathlib import Path
import secrets
import select
import signal
import ssl
import subprocess
import sys
import unittest
import uuid

from tests.https_fixture import HttpsFixture, hashed_ca_directory, localhost_certificate
from tests.support import RuntimeCase


def macos_keychain_preflight():
    """Read only OS availability and lock state; never request credential items."""
    if sys.platform != "darwin":
        return "macos-keychain=not-applicable"
    import ctypes

    try:
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        security.SecKeychainCopyDefault.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        security.SecKeychainCopyDefault.restype = ctypes.c_int32
        security.SecKeychainGetStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        security.SecKeychainGetStatus.restype = ctypes.c_int32
        core.CFRelease.argtypes = [ctypes.c_void_p]
        core.CFRelease.restype = None
        wallet = ctypes.c_void_p()
        copied = security.SecKeychainCopyDefault(ctypes.byref(wallet))
        status = ctypes.c_uint32()
        try:
            checked = security.SecKeychainGetStatus(wallet, ctypes.byref(status)) if copied == 0 else None
        finally:
            if wallet.value:
                core.CFRelease(wallet)
        unlocked = int(bool(status.value & 1)) if checked == 0 else None
        return f"macos-keychain-copy={copied}; status={checked}; unlocked={unlocked}"
    except (OSError, AttributeError):
        return "macos-keychain-preflight=unavailable"


def macos_osascript_preflight(environment):
    """Check the public Security API in a child with the CLI's filtered env."""
    if sys.platform != "darwin":
        return "macos-osascript=not-applicable"
    # Independently authored OS availability query: no item lookup or contents.
    script = """
ObjC.import('Security');
function run() {
    try {
        const reference = Ref();
        const copied = $.SecKeychainCopyDefault(reference);
        let checked = null;
        let unlocked = null;
        if (copied === 0) {
            const flags = Ref();
            checked = $.SecKeychainGetStatus(reference[0], flags);
            if (checked === 0) unlocked = (flags[0] & 1) ? 1 : 0;
        }
        return JSON.stringify([copied, checked, unlocked]);
    } catch (error) {
        if (error.name === 'TypeError') return 'os-query-type-error';
        if (error.name === 'ReferenceError') return 'os-query-reference-error';
        if (error.name === 'Error') return 'os-query-error';
        return 'os-query-exception';
    }
}
"""
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-l", "JavaScript", "-e", script],
            env=dict(environment), capture_output=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "macos-osascript=timeout"
    except OSError:
        return "macos-osascript=unavailable"
    prefix = f"macos-osascript-exit={result.returncode}"
    if result.returncode != 0:
        return prefix + "; category=os-query-failed"
    markers = {
        b"os-query-type-error": "os-query-type-error",
        b"os-query-reference-error": "os-query-reference-error",
        b"os-query-error": "os-query-error",
        b"os-query-exception": "os-query-exception",
    }
    category = markers.get(result.stdout.strip())
    if category:
        return prefix + "; category=" + category
    try:
        values = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return prefix + "; category=invalid-status"
    if (not isinstance(values, list) or len(values) != 3
            or type(values[0]) is not int or not -(2**31) <= values[0] < 2**31
            or (values[1] is not None and (type(values[1]) is not int or not -(2**31) <= values[1] < 2**31))
            or (values[2] is not None and (type(values[2]) is not int or values[2] not in (0, 1)))):
        return prefix + "; category=invalid-status"
    return prefix + f"; copy={values[0]}; status={values[1]}; unlocked={values[2]}"


class SecretProcessTests(RuntimeCase):
    def release_fixture(self, directory="https", response=None):
        bearer = secrets.token_urlsafe(48)
        values = {"ALPHA": secrets.token_urlsafe(32), "BETA": secrets.token_urlsafe(32) + "\nŁ😀"}
        accepted = []

        def respond(method, path, headers, body):
            valid = method == "POST" and path == "/api/v1/workflow/secrets"
            valid = valid and headers.get("Authorization") == "Bearer " + bearer
            try:
                valid = valid and json.loads(body).get("names") == ["ALPHA", "BETA"]
            except (ValueError, AttributeError):
                valid = False
            accepted.append(valid)
            if not valid:
                return 403, {"error": "test_request_rejected"}, {}
            return (200, {"secrets": values}, {}) if response is None else response(values)

        server = HttpsFixture(self.root / directory, respond)
        environment = {
            **server.environment, "RUNL_TOKEN": bearer,
            "RUNL_REPOSITORY": "repository-blackbox", "RUNL_ENVIRONMENT": "environment-blackbox",
            "BLACKBOX_EXPECT_ALPHA": values["ALPHA"], "BLACKBOX_EXPECT_BETA": values["BETA"],
        }
        return server, environment, accepted, [bearer, *values.values()]

    def assert_private_output(self, result, values):
        self.assertTrue(all(value.encode("utf-8") not in result.stdout + result.stderr for value in values),
                        "Generated credential or secret appeared in process output")

    def test_real_https_secret_injection_literal_argv_exit_and_native_pid(self):
        server, environment, accepted, private = self.release_fixture()
        arguments = ["space here", "--flag", "--", "quotes'\"&$(literal)"]
        script = (
            "import os,sys; "
            "ok=os.environ.get('ALPHA')==os.environ['BLACKBOX_EXPECT_ALPHA'] and "
            "os.environ.get('BETA')==os.environ['BLACKBOX_EXPECT_BETA'] and 'RUNL_TOKEN' not in os.environ and "
            "sys.argv[1:]==['space here','--flag','--',\"quotes'\\\"&$(literal)\"]; "
            "print(os.getpid(),flush=True); sys.exit(37 if ok else 90)"
        )
        with server:
            process = subprocess.Popen(
                self.command("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script, *arguments),
                env={**self.env, **environment}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = process.communicate(timeout=30)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            result = subprocess.CompletedProcess([], process.returncode, stdout, stderr)
            self.assert_private_output(result, private)
            self.assert_status(result, 37, "Injected child arguments, environment or exit status were wrong")
            self.assertTrue(not stderr, "Unexpected process diagnostics")
            self.assertTrue(stdout.strip().isdigit(), "Child did not report a process ID")
            if os.name != "nt":
                self.assertTrue(stdout.strip() == str(process.pid).encode("ascii"),
                                "Unix exec did not retain the production CLI process ID")
            self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")

    def test_secret_injected_child_preserves_stdin_and_literal_arguments(self):
        server, environment, accepted, private = self.release_fixture()
        payload = secrets.token_bytes(64) + b"\x00\n\r\n"
        environment["BLACKBOX_EXPECT_INPUT"] = payload.hex()
        arguments = ["space here", "--flag", "--", "quotes'\"&$(literal)"]
        script = (
            "import os,sys; "
            "ok=sys.stdin.buffer.read()==bytes.fromhex(os.environ['BLACKBOX_EXPECT_INPUT']) and "
            "os.environ.get('ALPHA')==os.environ['BLACKBOX_EXPECT_ALPHA'] and "
            "os.environ.get('BETA')==os.environ['BLACKBOX_EXPECT_BETA'] and 'RUNL_TOKEN' not in os.environ and "
            "sys.argv[1:]==['space here','--flag','--',\"quotes'\\\"&$(literal)\"]; "
            "print('child ok' if ok else 'child failed'); sys.exit(37 if ok else 90)"
        )
        with server:
            result = self.runl("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script, *arguments,
                               extra_env=environment, input=payload)
            self.assert_private_output(result, [*private, payload.hex()])
            self.assert_status(result, 37, "Child stdin or literal arguments changed across secret injection")
            self.assertTrue(result.stdout.replace(b"\r\n", b"\n") == b"child ok\n" and not result.stderr,
                            "Unexpected child stdin-test output")
            self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")

    def test_missing_injected_command_returns_native_exit_127(self):
        server, environment, accepted, private = self.release_fixture()
        with server:
            result = self.runl("with-secrets", "ALPHA", "BETA", "--", str(self.root / "no-such executable.exe"),
                               extra_env=environment)
            self.assert_private_output(result, private)
            self.assert_status(result, 127, "Missing injected executable did not return native exit 127")
            self.assertTrue(not result.stdout, "Missing executable produced child output")
            self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")

    def test_ca_directory_is_a_supported_trust_source(self):
        server, environment, accepted, private = self.release_fixture()
        roots = hashed_ca_directory(server.certificate, self.root / "roots")
        script = "import os,sys; sys.exit(37 if os.environ.get('ALPHA')==os.environ['BLACKBOX_EXPECT_ALPHA'] and 'RUNL_TOKEN' not in os.environ else 90)"
        with server:
            result = self.runl("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script,
                               extra_env={**environment, "SSL_CERT_FILE": None, "SSL_CERT_DIR": str(roots)})
            self.assert_private_output(result, private)
            self.assert_status(result, 37, "Production TLS did not trust the explicit CA directory")
            self.assertTrue(not result.stdout and not result.stderr, "Unexpected CA-directory output")
            self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")

    @unittest.skipUnless(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true",
                         "Machine ROOT-store acceptance runs only on disposable Windows CI hosts")
    def test_windows_machine_root_store_is_used_without_explicit_ca(self):
        # Only this fresh certificate is added and removed, on an ephemeral CI host.
        server, environment, accepted, private = self.release_fixture()
        thumbprint = hashlib.sha1(ssl.PEM_cert_to_DER_cert(server.certificate.read_text(encoding="ascii"))).hexdigest()
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
        self.assertTrue(bool(system_root), "Windows system directory is unavailable")
        certutil = Path(system_root) / "System32" / "certutil.exe"
        script = "import os,sys; sys.exit(37 if os.environ.get('ALPHA')==os.environ['BLACKBOX_EXPECT_ALPHA'] and 'RUNL_TOKEN' not in os.environ else 90)"
        imported = False
        with server:
            try:
                result = subprocess.run([str(certutil), "-f", "-addstore", "Root", str(server.certificate)],
                                        env=self.env, capture_output=True, timeout=30)
                imported = result.returncode == 0
                self.assertTrue(imported, "Fresh test CA import into Windows machine ROOT failed")
                result = self.runl("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script,
                                   extra_env={**environment, "SSL_CERT_FILE": None, "SSL_CERT_DIR": None})
                self.assert_private_output(result, private)
                self.assert_status(result, 37, "Production TLS did not consume Windows machine ROOT")
                self.assertTrue(not result.stdout and not result.stderr, "Unexpected machine-ROOT output")
                self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")
            finally:
                # Attempt cleanup even when import failed or its result was uncertain.
                removed = subprocess.run([str(certutil), "-delstore", "Root", thumbprint],
                                         env=self.env, capture_output=True, timeout=30)
                if imported:
                    self.assertTrue(removed.returncode == 0, "Fresh Windows machine ROOT test CA removal failed")

    @unittest.skipIf(os.name == "nt", "POSIX exec and signal contract; Windows exit status is checked separately")
    def test_unix_signal_reaches_the_injected_child(self):
        server, environment, accepted, private = self.release_fixture()
        script = (
            "import os,signal,sys; "
            "signal.signal(signal.SIGTERM,lambda *_:sys.exit(73)); "
            "print('ready',flush=True); signal.pause()"
        )
        with server:
            process = subprocess.Popen(
                self.command("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script),
                env={**self.env, **environment}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                self.assertTrue(bool(select.select([process.stdout], [], [], 15)[0]), "Child readiness timed out")
                self.assertTrue(process.stdout.readline() == b"ready\n", "Child readiness failed")
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=10)
                result = subprocess.CompletedProcess([], process.returncode, stdout, stderr)
                self.assert_private_output(result, private)
                self.assert_status(result, 73, "Signal did not reach the Unix child")
                self.assertTrue(not stdout and not stderr, "Unexpected signal-test output")
                self.assertTrue(accepted == [True] and not server.errors, "HTTPS release request was invalid")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_tls_failures_never_execute_the_child(self):
        server, environment, accepted, private = self.release_fixture()
        other_certificate, _ = localhost_certificate(self.root / "untrusted")
        marker = self.root / "child-ran"
        script = "from pathlib import Path; import sys; Path(sys.argv[1]).touch()"
        with server:
            for overrides in [
                {"SSL_CERT_FILE": str(other_certificate)},
                {"SSL_CERT_FILE": str(self.root / "missing-ca.pem")},
                {"RUNL_URL": server.origin.replace("localhost", "127.0.0.1")},
                {"RUNL_URL": server.origin.replace("https:", "http:")},
            ]:
                result = self.runl("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", script, str(marker),
                                   extra_env={**environment, **overrides})
                self.assert_private_output(result, private)
                self.assert_status(result, 1, "Untrusted or invalid HTTPS origin was accepted")
                self.assertTrue(not result.stdout and not marker.exists(), "TLS rejection executed the child")
            self.assertTrue(not accepted and not server.errors, "A rejected connection reached the HTTP application")

    def test_redirect_is_not_followed_and_never_executes(self):
        server, environment, accepted, private = self.release_fixture(
            response=lambda _: (302, {}, {"Location": "/redirected"})
        )
        result = None
        with server:
            result = self.runl("with-secrets", "ALPHA", "BETA", "--", sys.executable, "-c", "print('child ran')",
                               extra_env=environment)
            self.assert_private_output(result, private)
            self.assert_status(result, 1, "Redirected secret release was accepted")
            self.assertTrue(not result.stdout, "Rejected release executed the child")
            self.assertTrue(accepted == [True] and len(server.requests) == 1 and not server.errors,
                            "HTTPS redirect was followed")


class DeviceFixture(HttpsFixture):
    def __init__(self, directory):
        self.tokens = [str(uuid.uuid4()) + str(uuid.uuid4()) for _ in range(2)]
        self.device = str(uuid.uuid4()) + str(uuid.uuid4())
        self.code = secrets.token_hex(8).upper()
        self.current = -1
        self.expires_in = 0
        self.authorized_reads = []
        self.revoked = []
        self.invalid = []

        def respond(method, path, headers, body):
            try:
                document = json.loads(body) if body else {}
            except ValueError:
                self.invalid.append(True)
                return 400, {}, {}
            if method == "POST" and path == "/oauth/device":
                if document.get("scope") != "organizations:read repositories:read":
                    self.invalid.append(True)
                self.expires_in = document.get("expires_in", 0)
                return 200, {"device_code": self.device, "user_code": self.code,
                             "verification_uri": self.origin + "/app/device", "expires_in": 600, "interval": 1}, {}
            if method == "POST" and path == "/oauth/token":
                if document.get("device_code") != self.device or self.current + 1 >= len(self.tokens):
                    self.invalid.append(True)
                    return 400, {}, {}
                self.current += 1
                return 200, {"access_token": self.tokens[self.current], "token_type": "Bearer",
                             "expires_in": self.expires_in, "organization": "organization-blackbox"}, {}
            supplied = headers.get("Authorization")
            index = next((i for i, token in enumerate(self.tokens) if supplied == "Bearer " + token), None)
            if index is None:
                self.invalid.append(True)
                return 403, {}, {}
            if method == "DELETE" and path == "/api/v1/me/cli-tokens/current":
                self.revoked.append(index)
                return 200, {}, {}
            if method == "GET" and path == "/api/v1/orgs/organization-blackbox/repositories":
                self.authorized_reads.append(index)
                return 200, {"repositories": []}, {}
            if method == "GET" and path == "/api/v1/orgs":
                self.authorized_reads.append(index)
                return 200, {"organizations": [{"id": "organization-blackbox", "name": "Black-box", "role": "member"}]}, {}
            self.invalid.append(True)
            return 404, {}, {}

        super().__init__(directory, respond)

    def private_output(self, result):
        return any(value.encode("ascii") in result.stdout + result.stderr for value in [*self.tokens, self.device])


class DeviceSessionTests(RuntimeCase):
    def test_command_scoped_login_works_without_a_native_wallet(self):
        with DeviceFixture(self.root / "https") as server:
            result = self.runl("auth", "login", "--organization", "organization-blackbox", "--",
                               *self.command("repositories", "list"), extra_env=server.environment)
            self.assertTrue(not server.private_output(result), "Device credential appeared in output")
            self.assert_status(result, 0, "Command-scoped production login failed")
            self.assertTrue(server.authorized_reads == [0] and not server.invalid and not server.errors,
                            "Temporary child session did not authenticate correctly")
            status = self.runl("auth", "status", extra_env=server.environment)
            self.assertTrue(not server.private_output(status), "Device credential appeared in status output")
            self.assertTrue(self.json_result(status).get("authenticated") is False,
                            "Command-scoped login persisted a native credential")

    @unittest.skipUnless(sys.platform == "darwin" or os.name == "nt", "Native persistence is required on macOS and Windows")
    def test_saved_native_login_reuses_replaces_and_removes_credentials(self):
        self.config(credential_backend="auto", auto_update=False)
        keychain = macos_keychain_preflight()
        osascript = macos_osascript_preflight(self.env)
        with DeviceFixture(self.root / "https") as server:
            attempted = False

            def runl(*args):
                result = self.runl(*args, extra_env=server.environment)
                self.assertTrue(not server.private_output(result), "Native credential appeared in output")
                return result

            initial = runl("auth", "status")
            self.assert_status(initial, 0, f"Initial native status failed ({keychain}; {osascript})")
            self.assertTrue(self.json_result(initial).get("authenticated") is False,
                            "Fresh localhost origin already has a login; no credential changed")
            try:
                attempted = True
                for expected in [0, 1]:
                    self.assert_status(runl("auth", "login", "--organization", "organization-blackbox"), 0,
                                       "Required native credential login failed")
                    status = self.json_result(runl("auth", "status"))
                    self.assertTrue(status.get("authenticated") is True and status.get("organization") == "organization-blackbox",
                                    "Saved native session was not restored by another process")
                    self.assertTrue(self.json_result(runl("repositories", "list")).get("repositories") == [],
                                    "Saved native credential request failed")
                    self.assertTrue(server.authorized_reads[-1:] == [expected], "Wrong saved authorization was reused")
                self.assertTrue(server.revoked == [0], "Relogin did not retire the displaced authorization")
                self.assert_status(runl("auth", "logout"), 0, "Native logout failed")
                self.assertTrue(self.json_result(runl("auth", "status")).get("authenticated") is False,
                                "Native logout left an active local credential")
                self.assertTrue(server.revoked == [0, 1], "Native logout did not revoke the current authorization")
                self.assertTrue(not server.invalid and not server.errors, "Native session request was invalid")
            finally:
                if attempted:
                    self.assert_status(runl("auth", "logout"), 0, "Temporary native credential cleanup failed")


if __name__ == "__main__":
    unittest.main()
