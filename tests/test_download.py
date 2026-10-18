"""The public downloader's boundary checks use only generated, non-product bytes."""

import contextlib
from email.message import Message
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
import urllib.response

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import download


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def describe(data, media_type):
    return {"digest": download.digest(data), "size": len(data), "mediaType": media_type}


def archive(binary, names=("runl",), member_type=tarfile.REGTYPE):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name in names:
            entry = tarfile.TarInfo(name)
            entry.type = member_type
            entry.size = len(binary) if member_type == tarfile.REGTYPE else 0
            entry.linkname = "elsewhere" if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            output.addfile(entry, io.BytesIO(binary) if entry.size else None)
    return stream.getvalue()


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, headers):
        super().__init__(body)
        self.headers = headers


class Opener:
    def __init__(self, objects):
        self.objects = objects
        self.requests = []
        self.changes = {}

    def open(self, request, timeout):
        self.requests.append(request)
        path = request.full_url.removeprefix(download.REGISTRY)
        body = self.objects[path]
        body, headers = self.changes.get(path, (body, {"Content-Length": str(len(body)), "Docker-Content-Digest": download.digest(body)}))
        return Response(body, headers)


class Package:
    def __init__(self, layer=None, platforms=None, config_change=None):
        self.binary = b"generated public downloader test data\n"
        self.layer = archive(self.binary) if layer is None else layer
        self.config = {"identity": "sha256", "revision": download.digest(self.binary)[7:47],
                       "version": "0.1.0+" + download.digest(self.binary)[7:47],
                       "binary": describe(self.binary, download.BINARY)}
        if config_change:
            config_change(self.config)
        self.config_bytes = encode(self.config)
        self.manifest = encode({"schemaVersion": 2, "mediaType": download.MANIFEST,
                                "config": describe(self.config_bytes, download.CONFIG),
                                "layers": [describe(self.layer, download.LAYER)]})
        self.index = encode({"schemaVersion": 2, "mediaType": download.INDEX,
                             "manifests": [{**describe(self.manifest, download.MANIFEST), "platform": item}
                                           for item in platforms or [{"os": "linux", "architecture": "amd64"}]]})
        self.reference = download.digest(self.index)
        self.objects = {"/manifests/latest": self.index,
                        "/manifests/" + self.reference: self.index,
                        "/manifests/" + download.digest(self.manifest): self.manifest,
                        "/blobs/" + download.digest(self.config_bytes): self.config_bytes,
                        "/blobs/" + download.digest(self.layer): self.layer}
        self.opener = Opener(self.objects)
        self.client = download.Downloader(self.opener)


class DownloadTests(unittest.TestCase):
    def test_resolve_latest_once_and_fetch_only_immutable_descriptors(self):
        package = Package()
        self.assertEqual(package.client.resolve("latest"), package.reference)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "runl"
            receipt = package.client.fetch(package.reference, output, ("linux", "amd64"))
            self.assertEqual(output.read_bytes(), package.binary)
            self.assertEqual(receipt["binary_digest"], download.digest(package.binary))
            self.assertEqual(receipt["index_digest"], package.reference)
        paths = [request.full_url for request in package.opener.requests]
        self.assertEqual(sum(path.endswith("/latest") for path in paths), 1)
        self.assertTrue(all(path.startswith(download.REGISTRY + "/") for path in paths))
        for request in package.opener.requests:
            self.assertEqual(request.get_header("User-agent"), download.USER_AGENT)
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("Cookie"))

    def test_fetch_rejects_mutable_or_external_reference_before_network(self):
        package = Package()
        for reference in ["latest", "sha-" + "a" * 40, "https://other.example/file", "../../file"]:
            with self.subTest(reference=reference), self.assertRaises(download.DownloadError):
                package.client.fetch(reference, Path("unused"), ("linux", "amd64"))
        self.assertEqual(package.opener.requests, [])

    def test_each_descriptor_digest_and_size_are_checked_before_install(self):
        for label in ["index", "manifest", "config", "layer"]:
            for failure in ["changed", "truncated", "oversized"]:
                with self.subTest(label=label, failure=failure):
                    package = Package()
                    body = getattr(package, "config_bytes" if label == "config" else label)
                    kind = "manifests" if label in ["index", "manifest"] else "blobs"
                    path = "/" + kind + "/" + download.digest(body)
                    damaged = body[:-1] + bytes([body[-1] ^ 1]) if failure == "changed" else body[:-1] if failure == "truncated" else body + b"x"
                    package.opener.changes[path] = (damaged, {"Content-Length": str(len(damaged))})
                    with tempfile.TemporaryDirectory() as directory:
                        output = Path(directory) / "runl"
                        output.write_bytes(b"previous installation")
                        with self.assertRaises(download.DownloadError):
                            package.client.fetch(package.reference, output, ("linux", "amd64"))
                        self.assertEqual(output.read_bytes(), b"previous installation")
                        self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_missing_length_does_not_allow_truncation_or_oversize(self):
        for changed in [b"short", b"x" * (download.MAX_METADATA + 1)]:
            package = Package()
            package.opener.changes["/manifests/" + package.reference] = (changed, {})
            with self.assertRaises(download.DownloadError):
                package.client.fetch(package.reference, Path("unused"), ("linux", "amd64"))

    def test_malformed_or_conflicting_digest_header_is_rejected(self):
        package = Package()
        package.opener.changes["/manifests/latest"] = (package.index, {"Docker-Content-Digest": "sha256:" + "0" * 64})
        with self.assertRaisesRegex(download.DownloadError, "digest_mismatch"):
            package.client.resolve("latest")

    def test_path_traversal_extra_entries_and_links_never_extract(self):
        binary = Package().binary
        layers = [archive(binary, names=("../runl",)), archive(binary, names=("/runl",)),
                  archive(binary, names=("nested/runl",)), archive(binary, names=("runl", "extra")),
                  archive(binary, member_type=tarfile.SYMTYPE), archive(binary, member_type=tarfile.LNKTYPE)]
        for layer in layers:
            with self.subTest(layer_digest=download.digest(layer)), tempfile.TemporaryDirectory() as directory:
                package = Package(layer=layer)
                output = Path(directory) / "runl"
                with self.assertRaises(download.DownloadError):
                    package.client.fetch(package.reference, output, ("linux", "amd64"))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_binary_hash_and_content_identity_are_separate_checks(self):
        for modify in [lambda config: config["binary"].update(digest="sha256:" + "0" * 64),
                       lambda config: config.update(revision="0" * 40),
                       lambda config: config.update(version="0.1.0+" + "0" * 40),
                       lambda config: config.update(identity="unsupported")]:
            package = Package(config_change=modify)
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(download.DownloadError):
                package.client.fetch(package.reference, Path(directory) / "runl", ("linux", "amd64"))
        package = Package(layer=archive(b"x" * len(Package().binary)))
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(download.DownloadError, "binary_mismatch"):
            package.client.fetch(package.reference, Path(directory) / "runl", ("linux", "amd64"))

    def test_platform_selection_rejects_absent_and_ambiguous_platform(self):
        for entries in [[{"os": "darwin", "architecture": "arm64"}],
                        [{"os": "linux", "architecture": "amd64"}] * 2]:
            package = Package(platforms=entries)
            with self.assertRaisesRegex(download.DownloadError, "platform_not_unique"):
                package.client.fetch(package.reference, Path("unused"), ("linux", "amd64"))
            self.assertEqual(len(package.opener.requests), 1)

    def test_host_aliases_and_windows_executable_name(self):
        for system, machine, expected in [("Linux", "x86_64", ("linux", "amd64")),
                                           ("Darwin", "aarch64", ("darwin", "arm64")),
                                           ("Windows", "AMD64", ("windows", "amd64"))]:
            with mock.patch("download.platform.system", return_value=system), mock.patch("download.platform.machine", return_value=machine):
                self.assertEqual(download.host_platform(), expected)
        package = Package(platforms=[{"os": "windows", "architecture": "amd64"}])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runl"
            receipt = package.client.fetch(package.reference, output, ("windows", "amd64"))
            self.assertFalse(output.exists())
            self.assertEqual(output.with_suffix(".exe").read_bytes(), package.binary)
            self.assertEqual(receipt["os"], "windows")

    def test_redirects_are_denied_and_errors_do_not_echo_upstream_details(self):
        handler = download.NoRedirect()
        for status in [301, 302, 303, 307, 308]:
            self.assertIsNone(handler.redirect_request(None, None, status, "", {}, "https://other.example/blob"))
            opener = mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://other.example/", status, "untrusted upstream text", {}, None)
            with self.assertRaisesRegex(download.DownloadError, "^redirect_denied$"):
                download.Downloader(opener).resolve("latest")
        opener.open.side_effect = OSError("untrusted upstream text")
        with self.assertRaisesRegex(download.DownloadError, "^transport_failure$"):
            download.Downloader(opener).resolve("latest")

    def test_real_urllib_redirect_chain_never_contacts_second_origin(self):
        requests = []

        class Transport(urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request.full_url)
                headers = Message()
                headers["Location"] = "https://other.example/changed"
                response = urllib.response.addinfourl(io.BytesIO(), headers, request.full_url, 302)
                response.msg = "Found"
                return response

        opener = urllib.request.build_opener(download.NoRedirect, Transport())
        with self.assertRaisesRegex(download.DownloadError, "^redirect_denied$"):
            download.Downloader(opener).resolve("latest")
        self.assertEqual(requests, [download.REGISTRY + "/manifests/latest"])

    def test_descriptor_bounds_and_transfer_deadline(self):
        for changed in [{"size": True}, {"size": 0}, {"size": download.MAX_ARCHIVE + 1},
                        {"digest": "sha256:invalid"}, {"mediaType": "foreign/type"}]:
            with self.subTest(changed=changed):
                value = describe(b"generated", download.LAYER)
                value.update(changed)
                with self.assertRaisesRegex(download.DownloadError, "^invalid_descriptor$"):
                    download.descriptor(value, download.LAYER, download.MAX_ARCHIVE)
        package = Package()
        with mock.patch("download.time.monotonic", side_effect=[0, 121]), self.assertRaisesRegex(download.DownloadError, "^download_timeout$"):
            package.client.resolve("latest")

    def test_cli_outputs_only_digest_or_safe_receipt(self):
        package = Package()
        with mock.patch("download.Downloader", return_value=package.client), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(download.main(["resolve", "--reference", "latest"]), 0)
            self.assertEqual(output.getvalue(), package.reference + "\n")
        with tempfile.TemporaryDirectory() as directory, mock.patch("download.Downloader", return_value=package.client), mock.patch("download.host_platform", return_value=("linux", "amd64")), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(download.main(["fetch", "--reference", package.reference, "--output", str(Path(directory) / "runl")]), 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(set(receipt), {"index_digest", "manifest_digest", "config_digest", "layer_digest", "binary_digest", "binary_size", "version", "os", "architecture"})


if __name__ == "__main__":
    unittest.main()
