"""Update between two genuine published binaries through a fresh HTTPS mirror."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import download
from tests.https_fixture import HttpsFixture
from tests.support import RuntimeCase


class PublishedUpdateTests(RuntimeCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        supplied = os.environ.get("RUNL_BASELINE_BINARY")
        reference = os.environ.get("RUNL_PACKAGE_DIGEST", "")
        if not supplied or not download.DIGEST.fullmatch(reference):
            raise RuntimeError("Updater tests require RUNL_BASELINE_BINARY and immutable RUNL_PACKAGE_DIGEST")
        cls.baseline = Path(supplied).resolve()
        if not cls.baseline.is_file():
            raise RuntimeError("RUNL_BASELINE_BINARY does not identify a downloaded executable")
        client = download.Downloader()
        cls.package_digest = reference
        cls.objects = {}

        def read(kind, reference, maximum, expected=None):
            body = client.read(kind, reference, maximum,
                               expected_size=expected["size"] if expected else None,
                               expected_digest=reference)
            cls.objects[f"/v2/internal/runl/production/{kind}/{reference}"] = body
            return body

        index = download.document(read("manifests", reference, download.MAX_METADATA), download.INDEX)
        operating_system, architecture = download.host_platform()
        matches = [entry for entry in index["manifests"]
                   if entry.get("platform", {}).get("os") == operating_system
                   and entry.get("platform", {}).get("architecture") == architecture]
        if len(matches) != 1:
            raise RuntimeError("Published package does not uniquely select the native platform")
        selected = download.descriptor(matches[0], download.MANIFEST, download.MAX_METADATA)
        cls.manifest_digest = selected["digest"]
        manifest = download.document(read("manifests", selected["digest"], download.MAX_METADATA, selected), download.MANIFEST)
        config_descriptor = download.descriptor(manifest["config"], download.CONFIG, download.MAX_METADATA)
        cls.config_digest = config_descriptor["digest"]
        config = json.loads(read("blobs", config_descriptor["digest"], download.MAX_METADATA, config_descriptor))
        if len(manifest["layers"]) != 1:
            raise RuntimeError("Published package does not contain a single executable layer")
        layer_descriptor = download.descriptor(manifest["layers"][0], download.LAYER, download.MAX_ARCHIVE)
        cls.layer_digest = layer_descriptor["digest"]
        layer = read("blobs", layer_descriptor["digest"], download.MAX_ARCHIVE, layer_descriptor)
        binary_descriptor = download.descriptor(config["binary"], download.BINARY, download.MAX_ARCHIVE)
        cls.current_bytes = download.unpack(layer, binary_descriptor)
        cls.current_digest = binary_descriptor["digest"]
        cls.current_version = config["version"]
        cls.baseline_bytes = cls.baseline.read_bytes()
        cls.baseline_digest = download.digest(cls.baseline_bytes)
        if cls.baseline_digest == cls.current_digest:
            raise RuntimeError("Updater baseline must contain genuinely different published executable bytes")
        if download.digest(cls.binary.read_bytes()) != cls.current_digest:
            raise RuntimeError("Selected test executable does not match the immutable published package")

    def installed_baseline(self):
        output = self.root / ("installed-runl.exe" if os.name == "nt" else "installed-runl")
        shutil.copyfile(self.baseline, output)
        output.chmod(0o755)
        self.assertTrue(download.digest(output.read_bytes()) == self.baseline_digest,
                        "Baseline copy was changed before the updater ran")
        return output

    def run_installed(self, executable, *args, environment):
        prefix = [] if os.name == "nt" else ["/bin/sh"]
        return subprocess.run(prefix + [str(executable), *args], env={**self.env, **environment},
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=90)

    def mirror(self, damaged=None):
        def respond(method, path, headers, body):
            if method != "GET" or path not in self.objects:
                return 404, {}, {}
            original = self.objects[path]
            response = original
            if path == damaged:
                response = original[:-1] + bytes([original[-1] ^ 1])
            return 200, response, {"Docker-Content-Digest": download.digest(original)}

        return HttpsFixture(self.root / "https", respond)

    def test_real_changed_content_update_replaces_baseline_with_published_bytes(self):
        installed = self.installed_baseline()
        with self.mirror() as server:
            result = self.run_installed(
                installed, "update", "--track", "production", "--version", self.package_digest,
                environment={**server.environment, "RUNL_REGISTRY": server.origin},
            )
            self.assert_status(result, 0, "Published baseline could not update through verified HTTPS")
            self.assertTrue(installed.read_bytes() == self.current_bytes,
                            "Updater did not install the exact newer published executable")
            self.assertTrue(not server.errors, "HTTPS mirror reported an unexpected failure")
            self.assertEqual(server.requests[0], ("GET", "/v2/internal/runl/production/manifests/" + self.package_digest))
            self.assertEqual(len(server.requests), 4, "Updater did not traverse the expected published OCI graph")
        version = self.run_installed(installed, "--version", environment={})
        self.assert_status(version, 0, "Updated executable could not run")
        self.assertTrue(self.current_version.encode("ascii") in version.stdout + version.stderr,
                        "Updated executable did not report the selected published content identity")

    def test_corrupt_published_responses_preserve_the_distinct_installed_baseline(self):
        paths = ["/v2/internal/runl/production/manifests/" + self.package_digest,
                 "/v2/internal/runl/production/manifests/" + self.manifest_digest,
                 "/v2/internal/runl/production/blobs/" + self.config_digest,
                 "/v2/internal/runl/production/blobs/" + self.layer_digest]
        for path in paths:
            with self.subTest(component=path.split("/")[-2]):
                installed = self.installed_baseline()
                with self.mirror(damaged=path) as server:
                    result = self.run_installed(
                        installed, "update", "--track", "production", "--version", self.package_digest,
                        environment={**server.environment, "RUNL_REGISTRY": server.origin},
                    )
                    self.assertTrue(result.returncode != 0, "Updater accepted a corrupt published response")
                    self.assertTrue(installed.read_bytes() == self.baseline_bytes,
                                    "Failed update changed the installed baseline executable")
                    self.assertTrue(("GET", path) in server.requests,
                                    "Negative case did not reach its intentionally corrupted response")
                    self.assertTrue(not server.errors, "HTTPS mirror reported an unexpected failure")


if __name__ == "__main__":
    unittest.main()
