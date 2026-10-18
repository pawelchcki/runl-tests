"""Local HTTPS fixtures using Python's standard library and an OpenSSL executable.

Certificates are generated afresh for localhost. Request credentials and response
values stay in memory; server diagnostics never include request data.
"""
import http.server
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading
from urllib.parse import urlsplit
from uuid import uuid4


def localhost_certificate(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("An OpenSSL or LibreSSL executable is required for local HTTPS tests")
    configuration = directory / "openssl.cnf"
    configuration.write_text(
        "[req]\nprompt = no\ndistinguished_name = subject\nx509_extensions = server\n"
        f"[subject]\nCN = runl-blackbox-{uuid4().hex}\n[server]\nsubjectAltName = DNS:localhost\n"
        "basicConstraints = critical,CA:TRUE\n"
        "keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\n"
        "extendedKeyUsage = serverAuth\n",
        encoding="ascii",
    )
    key, certificate = directory / "server.key", directory / "server.pem"
    result = subprocess.run(
        [openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "1", "-config", str(configuration), "-keyout", str(key), "-out", str(certificate)],
        capture_output=True, timeout=30,
    )
    if result.returncode:
        raise RuntimeError("Local HTTPS certificate generation failed")
    key.chmod(0o600)
    return certificate, key


def hashed_ca_directory(certificate, directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = subprocess.run(
        [shutil.which("openssl"), "x509", "-in", str(certificate), "-hash", "-noout"],
        capture_output=True, timeout=15,
    )
    subject_hash = result.stdout.strip()
    if result.returncode or len(subject_hash) != 8 or any(byte not in b"0123456789abcdefABCDEF" for byte in subject_hash):
        raise RuntimeError("Local test CA directory preparation failed")
    shutil.copyfile(certificate, directory / (subject_hash.decode("ascii") + ".0"))
    return directory


class HttpsFixture:
    def __init__(self, directory, respond):
        self.certificate, key = localhost_certificate(directory)
        self.respond = respond
        self.requests = []
        self.errors = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def handle_request(self):
                path = urlsplit(self.path).path
                fixture.requests.append((self.command, path))
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > 256 * 1024:
                        status, body, headers = 413, {}, {}
                    else:
                        status, body, headers = fixture.respond(
                            self.command, path, self.headers, self.rfile.read(length)
                        )
                    if isinstance(body, (dict, list)):
                        body = json.dumps(body, ensure_ascii=True).encode("utf-8")
                    elif isinstance(body, str):
                        body = body.encode("utf-8")
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                except Exception as error:
                    fixture.errors.append(type(error).__name__)
                    self.close_connection = True

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

            def log_message(self, *_args):
                pass

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, _request, _client_address):
                error = sys.exc_info()[1]
                if not isinstance(error, (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
                    fixture.errors.append(type(error).__name__)

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.origin = f"https://localhost:{self.server.server_port}"
        self.environment = {"RUNL_URL": self.origin, "SSL_CERT_FILE": str(self.certificate)}
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
