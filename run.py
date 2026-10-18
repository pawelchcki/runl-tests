"""Fetch a published package and run its complete public acceptance suite."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from download import DIGEST, REGISTRIES, Downloader, DownloadError, registry


BASELINE_INDEX = "sha256:724f5305b960d431773b9af650d53466309d55cd5e76870a27141addeef9e04d"
BASELINE_BINARY = "sha256:3f5663700e0eb3b40596d8dff9398b85cc27d01567a3d9ab6e193e5a05065fe3"
ALTERNATE_INDEX = "sha256:e5645ae893df364c9b5c2c00981b36351bbfeeb842d975989b61573095522184"
ROOT = Path(__file__).resolve().parent


def requested_package(event, manual_digest="", manual_track="production", dispatch_digest=""):
    """Only an explicit manual run may select an anonymously published staging package."""
    track = manual_track if event == "workflow_dispatch" else "production"
    registry(track)
    requested = dispatch_digest if event == "repository_dispatch" else manual_digest if event == "workflow_dispatch" else ""
    if event == "repository_dispatch" and not requested:
        raise DownloadError("immutable_reference_required")
    if requested and (not isinstance(requested, str) or not DIGEST.fullmatch(requested)):
        raise DownloadError("invalid_reference")
    return track, requested or "latest"


def prepare(reference="latest", track="production"):
    client = Downloader(track=track)
    index = client.resolve(reference)
    suffix = ".exe" if os.name == "nt" else ""
    binary = ROOT / ".runl" / ("runl" + suffix)
    receipt = client.fetch(index, binary)
    # A rollback to our first baseline still receives a distinct published input.
    baseline_index = ALTERNATE_INDEX if receipt["binary_digest"] == BASELINE_BINARY else BASELINE_INDEX
    baseline = ROOT / ".runl" / ("baseline-runl" + suffix)
    previous = Downloader(track="production").fetch(baseline_index, baseline)
    if previous["binary_digest"] == receipt["binary_digest"]:
        raise DownloadError("baseline_not_distinct")
    return {**receipt, "binary": str(binary), "baseline_binary": str(baseline),
            "baseline_index_digest": baseline_index, "baseline_track": "production"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", default="latest", help="Immutable OCI index digest, or latest")
    parser.add_argument("--track", choices=tuple(REGISTRIES), default="production")
    args = parser.parse_args()
    try:
        receipt = prepare(args.digest, args.track)
    except DownloadError as error:
        print("Published package preparation failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(receipt), flush=True)
    environment = {**os.environ, "RUNL_TEST_BINARY": receipt["binary"],
                   "RUNL_BASELINE_BINARY": receipt["baseline_binary"],
                   "RUNL_PACKAGE_DIGEST": receipt["index_digest"],
                   "RUNL_PACKAGE_TRACK": receipt["track"]}
    return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                          cwd=ROOT, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
