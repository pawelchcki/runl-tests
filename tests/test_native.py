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
    # Independently authored public API queries. The random account never has a
    # stored item; only opaque item references are requested, never contents or
    # attributes, and there are no writes. References are never inspected.
    script = """
ObjC.import('Foundation');
ObjC.import('CoreFoundation');
ObjC.import('Security');
function run(arguments) {
    const summary = {copy: null, status: null, unlocked: null,
        null_result: null, base: null, ui: null, search: null, limit: null, combined: null,
        cast_base: null, cast_combined: null, dictionary: null, keys: null,
        class_string: null, class_equal: null, cast_dictionary: null, cast_keys: null,
        cast_class_string: null, cast_class_equal: null, cast_api: null,
        constant_class_type: null, constant_class_ref: null, constant_class_known: null,
        constant_service_type: null, constant_service_ref: null, constant_service_known: null,
        constant_account_type: null, constant_account_ref: null, constant_account_known: null,
        constant_password_type: null, constant_password_ref: null, constant_password_known: null,
        constant_return_type: null, constant_return_ref: null, constant_return_known: null,
        forced_cast: null, forced_keys: null, forced_error: null,
        literal: null, literal_keys: null, literal_class: null, literal_error: null,
        object_literal: null, object_literal_keys: null, object_literal_error: null,
        incremental_raw: null, incremental_raw_keys: null, incremental_raw_error: null,
        incremental_literal: null, incremental_literal_keys: null, incremental_literal_error: null,
        incremental_cast: null, incremental_cast_keys: null, incremental_cast_error: null,
        object_raw_values: null, object_raw_values_keys: null, object_raw_values_error: null,
        constant_class_deref: null, constant_class_cast: null,
        constant_service_deref: null, constant_service_cast: null,
        constant_account_deref: null, constant_account_cast: null,
        constant_password_deref: null, constant_password_cast: null,
        constant_return_deref: null, constant_return_cast: null,
        phase: 'default', error: null};
    try {
        const reference = Ref();
        summary.copy = $.SecKeychainCopyDefault(reference);
        if (summary.copy === 0) {
            const flags = Ref();
            summary.status = $.SecKeychainGetStatus(reference[0], flags);
            if (summary.status === 0) summary.unlocked = (flags[0] & 1) ? 1 : 0;
            summary.cast_api = typeof ObjC.castRefToObject === 'function' ? 1 : 0;
            summary.phase = 'constants';
            const types = ['undefined', 'object', 'function', 'string', 'number', 'boolean', 'symbol', 'bigint'];
            const constants = [['class', $.kSecClass, 'class'], ['service', $.kSecAttrService, 'svce'],
                ['account', $.kSecAttrAccount, 'acct'], ['password', $.kSecClassGenericPassword, 'genp'],
                ['return', $.kSecReturnRef, 'r_Ref']];
            for (const entry of constants) {
                const prefix = 'constant_' + entry[0];
                summary[prefix + '_type'] = types.indexOf(typeof entry[1]);
                summary[prefix + '_ref'] = Number(entry[1] instanceof Ref);
                try { summary[prefix + '_known'] = Number(ObjC.unwrap(entry[1]) === entry[2]); }
                catch (_) { summary[prefix + '_known'] = 0; }
                try { summary[prefix + '_deref'] = Number(ObjC.unwrap(entry[1][0]) === entry[2]); }
                catch (_) { summary[prefix + '_deref'] = 0; }
                try { summary[prefix + '_cast'] = Number(ObjC.unwrap(ObjC.castRefToObject(entry[1])) === entry[2]); }
                catch (_) { summary[prefix + '_cast'] = 0; }
            }
            for (const mode of ['null_result', 'base', 'ui', 'search', 'limit', 'combined', 'cast_base', 'cast_combined']) {
                summary.phase = mode;
                const cast = mode.indexOf('cast_') === 0;
                if (cast && !summary.cast_api) continue;
                const object = value => cast && value instanceof Ref ? ObjC.castRefToObject(value) : value;
                const combined = mode === 'combined' || mode === 'cast_combined';
                const keys = [object($.kSecClass), object($.kSecAttrService), object($.kSecAttrAccount)];
                const values = [object($.kSecClassGenericPassword), $('runl-public-tests-readiness'), $(arguments[0])];
                if (mode !== 'null_result') {
                    keys.push(object($.kSecReturnRef));
                    values.push(object($.kCFBooleanTrue));
                }
                if (mode === 'ui' || combined) {
                    keys.push(object($.kSecUseAuthenticationUI));
                    values.push(object($.kSecUseAuthenticationUIFail));
                }
                if (mode === 'search' || combined) {
                    keys.push(object($.kSecMatchSearchList));
                    values.push($.NSArray.arrayWithArray([object(reference[0])]));
                }
                if (mode === 'limit' || combined) {
                    keys.push(object($.kSecMatchLimit));
                    values.push(object($.kSecMatchLimitOne));
                }
                const query = $.NSDictionary.dictionaryWithObjectsForKeys(values, keys);
                if (mode === 'base' || mode === 'cast_base') {
                    const prefix = cast ? 'cast_' : '';
                    summary[prefix + 'dictionary'] = $.CFGetTypeID(query) === $.CFDictionaryGetTypeID() ? 1 : 0;
                    summary[prefix + 'keys'] = Number(query.count);
                    const classValue = query.objectForKey($('class'));
                    summary[prefix + 'class_string'] = classValue.isNil() ? 0 : Number(classValue.isKindOfClass($.NSString));
                    summary[prefix + 'class_equal'] = classValue.isNil() ? 0 : Number($.CFEqual(classValue, $.kSecClassGenericPassword));
                }
                const result = mode === 'null_result' ? null : Ref();
                summary[mode] = $.SecItemCopyMatching(query, result);
            }
            const exceptionCode = error => error.name === 'TypeError' ? 1
                : error.name === 'ReferenceError' ? 2 : error.name === 'Error' ? 3 : 4;
            summary.phase = 'forced_cast';
            if (summary.cast_api) {
                try {
                    const keys = [$.kSecClass, $.kSecAttrService, $.kSecAttrAccount, $.kSecReturnRef]
                        .map(value => ObjC.castRefToObject(value));
                    const values = [ObjC.castRefToObject($.kSecClassGenericPassword),
                        $('runl-public-tests-readiness'), $(arguments[0]), ObjC.castRefToObject($.kCFBooleanTrue)];
                    const query = $.NSDictionary.dictionaryWithObjectsForKeys(values, keys);
                    summary.forced_keys = Number(query.count);
                    summary.forced_cast = $.SecItemCopyMatching(query, Ref());
                    summary.forced_error = 0;
                } catch (error) { summary.forced_error = exceptionCode(error); }
            }
            // Apple's public SecItemConstants.c defines these API string values.
            summary.phase = 'literal';
            try {
                const query = $.NSDictionary.dictionaryWithObjectsForKeys(
                    [$('genp'), $('runl-public-tests-readiness'), $(arguments[0]), $(true)],
                    [$('class'), $('svce'), $('acct'), $('r_Ref')]);
                summary.literal_keys = Number(query.count);
                summary.literal_class = Number(ObjC.unwrap(query.objectForKey($('class'))) === 'genp');
                summary.literal = $.SecItemCopyMatching(query, Ref());
                summary.literal_error = 0;
            } catch (error) { summary.literal_error = exceptionCode(error); }
            summary.phase = 'object_literal';
            try {
                const query = $({'class': 'genp', 'svce': 'runl-public-tests-readiness',
                    'acct': arguments[0], 'r_Ref': true});
                summary.object_literal_keys = Number(query.count);
                summary.object_literal = $.SecItemCopyMatching(query, Ref());
                summary.object_literal_error = 0;
            } catch (error) { summary.object_literal_error = exceptionCode(error); }
            for (const mode of ['incremental_raw', 'incremental_literal', 'incremental_cast', 'object_raw_values']) {
                summary.phase = mode;
                try {
                    let query;
                    if (mode === 'object_raw_values') {
                        query = $({'class': $.kSecClassGenericPassword,
                            'svce': 'runl-public-tests-readiness', 'acct': arguments[0], 'r_Ref': $.kCFBooleanTrue});
                    } else {
                        query = $.NSMutableDictionary.dictionary;
                        const entries = mode === 'incremental_cast'
                            ? [[ObjC.castRefToObject($.kSecClass), ObjC.castRefToObject($.kSecClassGenericPassword)],
                               [ObjC.castRefToObject($.kSecAttrService), $('runl-public-tests-readiness')],
                               [ObjC.castRefToObject($.kSecAttrAccount), $(arguments[0])],
                               [ObjC.castRefToObject($.kSecReturnRef), ObjC.castRefToObject($.kCFBooleanTrue)],
                               [ObjC.castRefToObject($.kSecUseAuthenticationUI), ObjC.castRefToObject($.kSecUseAuthenticationUIFail)],
                               [ObjC.castRefToObject($.kSecMatchLimit), ObjC.castRefToObject($.kSecMatchLimitOne)],
                               [ObjC.castRefToObject($.kSecMatchSearchList), $.NSArray.arrayWithObject(ObjC.castRefToObject(reference[0]))]]
                            : mode === 'incremental_raw'
                            ? [[$.kSecClass, $.kSecClassGenericPassword],
                               [$.kSecAttrService, $('runl-public-tests-readiness')],
                               [$.kSecAttrAccount, $(arguments[0])], [$.kSecReturnRef, $.kCFBooleanTrue]]
                            : [[$('class'), $('genp')], [$('svce'), $('runl-public-tests-readiness')],
                               [$('acct'), $(arguments[0])], [$('r_Ref'), $(true)]];
                        for (const entry of entries) query.setObjectForKey(entry[1], entry[0]);
                    }
                    summary[mode + '_keys'] = Number(query.count);
                    summary[mode] = $.SecItemCopyMatching(query, Ref());
                    summary[mode + '_error'] = 0;
                } catch (error) { summary[mode + '_error'] = exceptionCode(error); }
            }
        }
        summary.phase = 'done';
    } catch (error) {
        summary.error = error.name === 'TypeError' ? 'type-error'
            : error.name === 'ReferenceError' ? 'reference-error'
            : error.name === 'Error' ? 'error' : 'exception';
    }
    return JSON.stringify(summary);
}
"""
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-l", "JavaScript", "-e", script, uuid.uuid4().hex],
            env=dict(environment), capture_output=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "macos-osascript=timeout"
    except OSError:
        return "macos-osascript=unavailable"
    prefix = f"macos-osascript-exit={result.returncode}"
    if result.returncode != 0:
        return prefix + "; category=os-query-failed"
    try:
        values = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return prefix + "; category=invalid-status"
    numeric = ("copy", "status", "unlocked", "null_result", "base", "ui", "search", "limit", "combined",
               "cast_base", "cast_combined", "dictionary", "keys", "class_string", "class_equal",
               "cast_dictionary", "cast_keys", "cast_class_string", "cast_class_equal", "cast_api",
               "constant_class_type", "constant_class_ref", "constant_class_known",
               "constant_service_type", "constant_service_ref", "constant_service_known",
               "constant_account_type", "constant_account_ref", "constant_account_known",
               "constant_password_type", "constant_password_ref", "constant_password_known",
               "constant_return_type", "constant_return_ref", "constant_return_known",
               "forced_cast", "forced_keys", "forced_error", "literal", "literal_keys", "literal_class", "literal_error",
               "object_literal", "object_literal_keys", "object_literal_error",
               "incremental_raw", "incremental_raw_keys", "incremental_raw_error",
               "incremental_literal", "incremental_literal_keys", "incremental_literal_error",
               "incremental_cast", "incremental_cast_keys", "incremental_cast_error",
               "object_raw_values", "object_raw_values_keys", "object_raw_values_error",
               "constant_class_deref", "constant_class_cast", "constant_service_deref", "constant_service_cast",
               "constant_account_deref", "constant_account_cast", "constant_password_deref", "constant_password_cast",
               "constant_return_deref", "constant_return_cast")
    phases = ("default", "constants", "null_result", "base", "ui", "search", "limit", "combined", "cast_base",
              "cast_combined", "forced_cast", "literal", "object_literal", "incremental_raw", "incremental_literal", "incremental_cast",
              "object_raw_values", "done")
    errors = (None, "type-error", "reference-error", "error", "exception")
    if (not isinstance(values, dict) or set(values) != {*numeric, "phase", "error"}
            or any(value is not None and (type(value) is not int or not -(2**31) <= value < 2**31)
                   for key in numeric for value in [values[key]])
            or values["unlocked"] not in (None, 0, 1)
            or values["phase"] not in phases or values["error"] not in errors):
        return prefix + "; category=invalid-status"
    fields = "; ".join(f"{key}={values[key]}" for key in (*numeric, "phase", "error"))
    return prefix + "; " + fields


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
        with DeviceFixture(self.root / "https") as server:
            attempted = False

            def runl(*args):
                result = self.runl(*args, extra_env=server.environment)
                self.assertTrue(not server.private_output(result), "Native credential appeared in output")
                return result

            initial = runl("auth", "status")
            if initial.returncode:
                keychain = macos_keychain_preflight()
                osascript = macos_osascript_preflight(self.env)
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
