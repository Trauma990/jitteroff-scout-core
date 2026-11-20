# JITTEROFF Scout Core

![Scout Core: four diagnostic checkpoints leading to a report pulse](assets/scout-core-hero.png)

[![CI](https://github.com/Trauma990/jitteroff-scout-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Trauma990/jitteroff-scout-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-00cc84)](LICENSE)

**A small, local diagnostic CLI for public endpoints.** Describe the checks in a JSON profile, approve that exact file by its SHA-256 digest, and get a bounded report that you can inspect before sharing. Scout Core runs on Windows and Linux with .NET 10. It does not require a JITTEROFF account or any JITTEROFF server.

> [!IMPORTANT]
> This repository is a **0.1 development implementation**, not a tagged release. The [current status](docs/STATUS.md) lists the remaining release gates. A passing check is an observation at one moment, not proof that an app, game, or voice service works end to end.

[Quick start](#quick-start) · [What it checks](#what-it-checks) · [Reading results](#reading-results) · [Privacy and safety](#privacy-and-safety) · [فارسی](docs/README.fa.md)

## Why use it?

- **Explicit scope:** profiles name up to 10 public DNS endpoints and their ordered checks. No range scan or private-address switch.
- **Consent before traffic:** `validate` and `plan` are offline. `run` requires the digest of the exact profile bytes.
- **Honest outcomes:** blocked, inconclusive, cancelled, and budget-exhausted work cannot be reported as a successful complete run.
- **Local, reviewable output:** JSON is canonical; optional static HTML and Markdown are rendered from it. Reports are never uploaded by Scout Core.
- **Independent core:** the public project contains no JITTEROFF private API, account logic, production network configuration, or customer data.

## Quick start

Install the **.NET 10 SDK 10.0.300** (or a later 10.0 patch), clone this repository, and run from its root:

```sh
dotnet restore --locked-mode
dotnet build --no-restore
dotnet test --no-restore
```

Review the bundled public example, then inspect its plan. These commands make **no network request to the endpoint**:

```sh
dotnet run --project src/Scout.Cli -- validate examples/public-web.json
dotnet run --project src/Scout.Cli -- plan examples/public-web.json
```

To run the checks, copy the SHA-256 printed by `plan` into the next command. The value below is for the **unmodified** bundled example; if you edit the file, use its new digest. This step sends DNS, TCP, TLS, and HTTP requests to the public example endpoint.

```sh
dotnet run --project src/Scout.Cli -- run examples/public-web.json --allow-profile-digest d63a5e6dd8d004a4da886f1c88d21c4a6a8995d7eec7e1bf19179dcaa00ece26 --out report.json
dotnet run --project src/Scout.Cli -- render report.json --format html --out report.html
```

Open `report.json` before sharing it. `run` requires an existing output directory and refuses to replace a file unless `--overwrite` is supplied. A different profile, even with a one-byte edit, requires a new digest.

## What it checks

The [example profile](examples/public-web.json) checks `example.com` with `HEAD /` and expects HTTP 200. Your own UTF-8 JSON profile can specify these ordered checks:

1. **DNS:** resolve the hostname and reject the entire answer if any address is non-public.
2. **TCP:** re-resolve, apply the address policy, then connect to a validated IP. The recorded probe duration includes these steps; it is **not ping**.
3. **TLS:** verify certificate hostname and chain. Online revocation is explicitly **not checked**.
4. **HTTP/1.1:** send a `HEAD` or `GET` request with the original hostname for TLS and `Host`, then record the **final** status code. Informational `1xx` responses are not accepted as a result; `101` is unsupported. Redirects are never followed and response bodies are not retained.

The checks must form an ordered prefix: `dns`, `dns,tcp`, `dns,tcp,tls`, or `dns,tcp,tls,http`. Scout resolves again before each check, validates all returned addresses, and gives the socket a concrete approved IP. Profiles are limited to 128 KiB and 10 endpoints; a run takes up to 3 samples within a 90-second total budget. See the [0.1 contract](docs/CONTRACT-0.1.md) and [profile schema](contracts/profile-0.1.schema.json) for exact fields and limits. The C# parser is authoritative where generic JSON Schema cannot express a rule.

Library callers that construct `Profile` records directly receive the same model validation at the public runner boundary. The library does not provide the CLI's file-digest consent ceremony; embedding applications must obtain their own authorization before running probes.

Other commands:

```sh
dotnet run --project src/Scout.Cli -- run examples/public-web.json --allow-profile-digest d63a5e6dd8d004a4da886f1c88d21c4a6a8995d7eec7e1bf19179dcaa00ece26 --samples 3 --out report-3.json
dotnet run --project src/Scout.Cli -- render report.json --format markdown --out report.md
dotnet run --project src/Scout.Cli -- diff report.json report-3.json --out comparison.md
```

`diff` only compares reports with the same profile ID, exact profile digest, and network-policy version. It reports observed differences without inferring a cause or declaring an improvement.

## Reading results

`run_status: complete` means every planned check was accounted for; it does **not** mean every check passed. Individual checks use `pass`, `fail`, `blocked`, `inconclusive`, `skipped`, or `cancelled` with a typed reason. A safety refusal is `blocked`; an observation that cannot be trusted is `inconclusive`; a dependency or exhausted budget is `skipped`.

- Exit `0`: complete run, all observed checks passed.
- Exit `1`: complete run, at least one observed check failed.
- Exit `2`: invalid input or output request.
- Exit `3`: partial run or internal error.
- Exit `130`: user cancellation.

No check is silently retried. An incomplete or unknown result cannot yield exit `0`. See the [threat model](docs/THREAT-MODEL.md) for the limits of these observations.

## Privacy and safety

Scout Core does not capture packets, inspect applications, change system settings, use credentials, send telemetry, or upload reports. It rejects IP literals in profiles and blocks non-public addresses according to its public-address policy. It does not follow HTTP redirects. Test-only loopback fixtures are **not** exposed as CLI options.

Reports omit raw DNS names and IP addresses. Instead, addresses get HMAC tokens from a new in-memory key on each run. **This is not full anonymization:** public profile and endpoint IDs, timestamps, platform, timings, statuses, and the profile digest remain visible. Never put personal data or secrets in IDs, and review every report before distributing it.

The security tests include a real local DNS server changing its answer mid-run, a real socket that must not connect to loopback, TLS/HTTP fixtures, seeded report privacy cases, and checks against false success. [Evidence and CI links](docs/evidence/2026-11-20-stage-3-publication.md) are recorded alongside the code.

## Project and release status

The source, [architecture decision](docs/ADR-0001.md), [contract](docs/CONTRACT-0.1.md), [threat model](docs/THREAT-MODEL.md), English docs, and [Persian introduction](docs/README.fa.md) are public. CI builds and tests on Windows and Ubuntu. A separate [manual packaging workflow](.github/workflows/package-candidate.yml) makes short-lived **candidate** archives with SHA-256 checksums and SPDX SBOMs; those artifacts are not a release.

Use [GitHub Releases](https://github.com/Trauma990/jitteroff-scout-core/releases) for tagged downloads. The [release checklist](https://github.com/Trauma990/jitteroff-scout-core/issues/3) and [status evidence](docs/STATUS.md) record validation and known limitations. [Distributed component license notes](docs/THIRD-PARTY-LICENSES.md) describe the binary archives.

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) before a pull request. Keep all code and examples independent of private JITTEROFF infrastructure. Report security issues through the [private vulnerability reporting route](SECURITY.md), not a public exploit issue.

Scout Core and its original project artwork are distributed under [Apache-2.0](LICENSE). The generated README illustration has its [own provenance note](assets/README.md). Self-contained binaries embed .NET runtime components with separate terms; the Windows binary includes Microsoft's .NET Library License text. Review the [component license notes](docs/THIRD-PARTY-LICENSES.md) before redistributing a binary.
