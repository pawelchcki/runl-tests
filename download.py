"""Download published runl binaries through their public, verified OCI descriptors."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


REGISTRY = "https://app.runnerlesshq.com/v2/internal/runl/production"
USER_AGENT = "runl-public-tests/1.0"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.runnerless.runl.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
BINARY = "application/vnd.runnerless.runl.binary"
MAX_METADATA = 64 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class DownloadError(Exception):
    """A fixed category safe to report without upstream response contents."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def host_platform():
    operating_system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not operating_system or not architecture:
        raise DownloadError("unsupported_platform")
    return operating_system, architecture


def descriptor(value, media_type, maximum):
    if (not isinstance(value, dict) or value.get("mediaType") != media_type
            or not isinstance(value.get("digest"), str) or not DIGEST.fullmatch(value["digest"])
            or type(value.get("size")) is not int or not 0 < value["size"] <= maximum):
        raise DownloadError("invalid_descriptor")
    return value


def document(data, media_type):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        raise DownloadError("invalid_metadata") from None
    if not isinstance(value, dict) or value.get("schemaVersion") != 2 or value.get("mediaType") != media_type:
        raise DownloadError("invalid_metadata")
    return value


class Downloader:
    def __init__(self, opener=None):
        self.opener = opener or urllib.request.build_opener(NoRedirect)

    def read(self, kind, reference, maximum, expected_size=None, expected_digest=None):
        # Only locally validated names are interpolated; descriptor URLs are ignored.
        if kind not in ("manifests", "blobs") or not (reference == "latest" and kind == "manifests" or DIGEST.fullmatch(reference)):
            raise DownloadError("invalid_reference")
        request = urllib.request.Request(REGISTRY + "/" + kind + "/" + reference,
                                         headers={"User-Agent": USER_AGENT, "Accept": INDEX + ", " + MANIFEST + ", application/json"})
        deadline = time.monotonic() + 120
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.status != 200:
                    raise DownloadError("unexpected_http_status")
                size_header = response.headers.get("Content-Length")
                if size_header is not None:
                    if not size_header.isdecimal() or int(size_header) > maximum:
                        raise DownloadError("invalid_size")
                    if expected_size is not None and int(size_header) != expected_size:
                        raise DownloadError("size_mismatch")
                parts = []
                received = 0
                while True:
                    if time.monotonic() >= deadline:
                        raise DownloadError("download_timeout")
                    chunk = response.read(min(65536, maximum + 1 - received))
                    if not chunk:
                        break
                    parts.append(chunk)
                    received += len(chunk)
                    if received > maximum or expected_size is not None and received > expected_size:
                        raise DownloadError("size_mismatch")
                body = b"".join(parts)
                if expected_size is not None and received != expected_size:
                    raise DownloadError("size_mismatch")
                if size_header is not None and received != int(size_header):
                    raise DownloadError("size_mismatch")
                actual_digest = digest(body)
                if expected_digest is not None and actual_digest != expected_digest:
                    raise DownloadError("digest_mismatch")
                digest_header = response.headers.get("Docker-Content-Digest")
                if digest_header is not None and digest_header != actual_digest:
                    raise DownloadError("digest_mismatch")
                return body
        except DownloadError:
            raise
        except urllib.error.HTTPError as error:
            category = "redirect_denied" if 300 <= error.code < 400 else "http_failure"
            error.close()
            raise DownloadError(category) from None
        except Exception:
            raise DownloadError("transport_failure") from None

    def resolve(self, reference="latest"):
        if reference != "latest" and not DIGEST.fullmatch(reference):
            raise DownloadError("invalid_reference")
        body = self.read("manifests", reference, MAX_METADATA,
                         expected_digest=None if reference == "latest" else reference)
        index = document(body, INDEX)
        if not isinstance(index.get("manifests"), list) or not 1 <= len(index["manifests"]) <= 32:
            raise DownloadError("invalid_metadata")
        return digest(body)

    def fetch(self, reference, output, target=None):
        if not DIGEST.fullmatch(reference):
            raise DownloadError("immutable_reference_required")
        operating_system, architecture = target or host_platform()
        index = document(self.read("manifests", reference, MAX_METADATA, expected_digest=reference), INDEX)
        manifests = index.get("manifests")
        if not isinstance(manifests, list) or not 1 <= len(manifests) <= 32:
            raise DownloadError("invalid_metadata")
        matches = [entry for entry in manifests if isinstance(entry, dict)
                   and isinstance(entry.get("platform"), dict)
                   and entry["platform"].get("os") == operating_system
                   and entry["platform"].get("architecture") == architecture]
        if len(matches) != 1:
            raise DownloadError("platform_not_unique")
        selected = descriptor(matches[0], MANIFEST, MAX_METADATA)
        manifest = document(self.read("manifests", selected["digest"], MAX_METADATA, selected["size"], selected["digest"]), MANIFEST)
        config_descriptor = descriptor(manifest.get("config"), CONFIG, MAX_METADATA)
        layers = manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != 1:
            raise DownloadError("invalid_layers")
        layer_descriptor = descriptor(layers[0], LAYER, MAX_ARCHIVE)
        config_body = self.read("blobs", config_descriptor["digest"], MAX_METADATA, config_descriptor["size"], config_descriptor["digest"])
        try:
            config = json.loads(config_body)
        except (ValueError, UnicodeError):
            raise DownloadError("invalid_metadata") from None
        if not isinstance(config, dict):
            raise DownloadError("invalid_metadata")
        binary_descriptor = descriptor(config.get("binary"), BINARY, MAX_ARCHIVE)
        version = config.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"0\.1\.0\+[0-9a-f]{40}", version):
            raise DownloadError("invalid_identity")
        if config.get("identity") is not None:
            if (config["identity"] != "sha256" or config.get("revision") != binary_descriptor["digest"][7:47]
                    or version != "0.1.0+" + binary_descriptor["digest"][7:47]):
                raise DownloadError("invalid_identity")
        layer = self.read("blobs", layer_descriptor["digest"], MAX_ARCHIVE, layer_descriptor["size"], layer_descriptor["digest"])
        binary = unpack(layer, binary_descriptor)
        output = Path(output)
        if operating_system == "windows" and not output.name.lower().endswith(".exe"):
            output = output.with_name(output.name + ".exe")
        install(binary, output)
        return {"index_digest": reference, "manifest_digest": selected["digest"],
                "config_digest": config_descriptor["digest"], "layer_digest": layer_descriptor["digest"],
                "binary_digest": binary_descriptor["digest"], "binary_size": len(binary),
                "version": version, "os": operating_system, "architecture": architecture}


def unpack(layer, binary_descriptor):
    try:
        with tarfile.open(fileobj=io.BytesIO(layer), mode="r:") as archive:
            member = archive.next()
            if (member is None or member.name != "runl" or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.linkname or member.issparse() or member.size != binary_descriptor["size"]):
                raise DownloadError("unsafe_archive")
            binary = archive.extractfile(member).read(binary_descriptor["size"] + 1)
            if archive.next() is not None:
                raise DownloadError("unsafe_archive")
    except DownloadError:
        raise
    except Exception:
        raise DownloadError("invalid_archive") from None
    if len(binary) != binary_descriptor["size"] or digest(binary) != binary_descriptor["digest"]:
        raise DownloadError("binary_mismatch")
    return binary


def install(binary, output):
    temporary = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".runl-download-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(binary)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o755)
        os.replace(temporary, output)
    except OSError:
        raise DownloadError("output_failure") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                raise DownloadError("output_failure") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--reference", required=True)
    fetch = commands.add_parser("fetch")
    fetch.add_argument("--reference", required=True)
    fetch.add_argument("--output", required=True)
    options = parser.parse_args(argv)
    try:
        downloader = Downloader()
        result = downloader.resolve(options.reference) if options.command == "resolve" else downloader.fetch(options.reference, options.output)
    except DownloadError as error:
        print("runl download failed: " + str(error), file=sys.stderr)
        return 1
    print(result if isinstance(result, str) else json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
