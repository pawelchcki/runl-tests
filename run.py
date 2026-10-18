"""Fetch a published package and run its complete public acceptance suite."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from download import Downloader, DownloadError


BASELINE_INDEX = "sha256:724f5305b960d431773b9af650d53466309d55cd5e76870a27141addeef9e04d"
BASELINE_BINARY = "sha256:3f5663700e0eb3b40596d8dff9398b85cc27d01567a3d9ab6e193e5a05065fe3"
ALTERNATE_INDEX = "sha256:e5645ae893df364c9b5c2c00981b36351bbfeeb842d975989b61573095522184"
ROOT = Path(__file__).resolve().parent


def prepare(reference="latest"):
    client = Downloader()
    index = client.resolve(reference)
    suffix = ".exe" if os.name == "nt" else ""
    binary = ROOT / ".runl" / ("runl" + suffix)
    receipt = client.fetch(index, binary)
    # A rollback to our first baseline still receives a distinct published input.
    baseline_index = ALTERNATE_INDEX if receipt["binary_digest"] == BASELINE_BINARY else BASELINE_INDEX
    baseline = ROOT / ".runl" / ("baseline-runl" + suffix)
    previous = client.fetch(baseline_index, baseline)
    if previous["binary_digest"] == receipt["binary_digest"]:
        raise DownloadError("baseline_not_distinct")
    return {**receipt, "binary": str(binary), "baseline_binary": str(baseline),
            "baseline_index_digest": baseline_index}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", default="latest", help="Immutable OCI index digest, or latest")
    args = parser.parse_args()
    try:
        receipt = prepare(args.digest)
    except DownloadError as error:
        print("Published package preparation failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(receipt), flush=True)
    environment = {**os.environ, "RUNL_TEST_BINARY": receipt["binary"],
                   "RUNL_BASELINE_BINARY": receipt["baseline_binary"],
                   "RUNL_PACKAGE_DIGEST": receipt["index_digest"]}
    return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                          cwd=ROOT, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
