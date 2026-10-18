# Published runl acceptance

This public repository tests the published `runl` executable on native hosts. The
product source stays private. It contains the downloader, black-box tests and CI
configuration; it does not check out the private product repository or require
test-only executables, account credentials, repository secrets or real secret values.

Every workflow run resolves one OCI package digest before starting its
matrix. All five hosts download that exact package, so a concurrent `latest` update
cannot make the hosts test different versions. Automatic runs select production;
an explicit manual or local run can select already-public staging binaries:

| Host | Standard GitHub Actions label |
| --- | --- |
| Linux x86-64 | `ubuntu-24.04` |
| Linux ARM64 | `ubuntu-24.04-arm` |
| macOS ARM64 | `macos-14` |
| macOS Intel | `macos-15-intel` |
| Windows x86-64 | `windows-2025` |

The downloader accepts only the public production and staging registries at
`https://app.runnerlesshq.com/v2/internal/runl/production` and
`https://app.runnerlesshq.com/v2/internal/runl/staging`. It never accepts another
origin or credentials, and a missing staging package does not fall back to production.
It verifies package and
executable hashes before execution. Hashes establish content integrity against the
selected digest; they are not a signed provenance attestation or a claim that a
particular private source revision produced the executable.

## Run locally

Python 3.12 and OpenSSL must be available on `PATH`. These are the only test tools;
the test runner uses Python's standard library. The native GitHub images already
include OpenSSL, and CI verifies its availability before running TLS tests.

```sh
python run.py
# Repeat a particular published package:
python run.py --digest sha256:FULL_64_HEX_PACKAGE_DIGEST
# Explicitly test an anonymously published staging package:
python run.py --track staging --digest sha256:FULL_64_HEX_PACKAGE_DIGEST
```

The launcher downloads the selected executable and a distinct, unchanged production
baseline for update tests, then runs the suite. The baseline always comes from
production, including when the selected current executable is staging. It verifies every package descriptor,
archive and executable before starting them. `download.py` also exposes individual
`resolve` and `fetch` commands with the same optional `--track production|staging`
choice for inspecting a package separately; production is the default.

On Windows the downloader adds `.exe`, so the path is `.runl/runl.exe`. On Unix
the path is `.runl/runl`. The tests exercise the actual published CLI; they do not
build or substitute a testing variant. This covers observable public behavior and
does not replace the private implementation, ABI or authorized service integration
tests.

Coverage includes native host metadata and content version, preferences, real HTTPS
secret injection and redaction, literal arguments, stdin, exit codes, Unix process
IDs/signals, CA-file/directory trust, rejected TLS/redirects, temporary device sessions,
and required Keychain/Credential Manager login replacement/logout on macOS/Windows.
Ephemeral Windows runners also verify machine certificate-store trust and remove the
fresh test certificate afterward. Update tests replace an older published executable
with the exact selected published bytes and prove corrupted downloads leave it intact.
Mock credentials are generated in memory; test failures do not print captured CLI output.
The machine certificate-store mutation is skipped during local runs; it is required
on the disposable Windows GitHub Actions host. Native saved-login checks use an
isolated localhost origin and require the current user's Keychain/Credential Manager.

## Triggers and results

Pushes, pull requests and a daily schedule test production `latest`, resolved once
to its immutable digest. A manual `workflow_dispatch` offers a `track` dropdown
(production by default, or staging) and an optional `digest` input; leave the digest
empty for the selected track's `latest`, or supply `sha256:` followed by 64 lowercase
hexadecimal characters. Staging executables must already be anonymously published;
this does not publish private source or build the product in this repository.

An authorized publisher can send `repository_dispatch` with event type
`runl-published` and a `client_payload.digest` containing the same immutable digest
format. This workflow validates the value in Python and never treats it as a shell
command. It requires no receiving secret. The producer must already have access to
this repository with the GitHub permission required to create a dispatch; this
repository does not create or broaden that access. Repository dispatch always tests
production, regardless of any extra payload fields.

Each matrix job has a 15-minute limit and uses `contents: read`, with checkout
credential persistence disabled. Tests receive no account secrets. The only uploaded
artifact is a small JSON receipt containing the selected track, production baseline
track, package and executable digests,
public test commit, native runner and test outcome. Receipts expire after one day;
binary files, captured process output, temporary TLS keys and test working directories
are not uploaded. Ordinary Actions logs still contain the test runner's results.

## Runner availability and cost

These are standard GitHub-hosted runner labels, whose compute is free in public
repositories. No larger runner or paid service is requested. An account billing
lock can nevertheless block GitHub Actions, including free-tier access; a public
repository does not establish that the owner's current billing state permits a run.
Treat a completed native matrix as the evidence of availability.

References: [standard runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[account billing locks](https://docs.github.com/en/billing/how-tos/troubleshooting/locked-account),
and [repository dispatch permissions](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).
OpenSSL is listed in the official
[Linux x86-64](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md),
[Linux ARM64](https://github.com/actions/partner-runner-images/blob/main/images/Ubuntu2404-Readme.md),
[macOS ARM64](https://github.com/actions/runner-images/blob/main/images/macos/macos-14-arm64-Readme.md),
[macOS Intel](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md)
and [Windows](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md)
image inventories. Action references are pinned to verified official commit SHAs.
