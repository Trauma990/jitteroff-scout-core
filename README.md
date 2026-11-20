# JITTEROFF Scout Core

Scout Core is a local, opt-in endpoint diagnostic CLI for software maintainers. A small JSON profile declares public DNS hosts and expected HTTP status codes. Scout runs DNS, TCP, TLS and HTTP/1.1 checks, then writes a bounded report to a path you choose. It does **not** capture packets, scan IP ranges, change network settings, upload reports, use service account credentials or depend on JITTEROFF infrastructure.

This is an early **0.1 development implementation**, not a released diagnostic product. See [status and known gaps](docs/STATUS.md) before using it. A completed command is not proof that an application works or that a network problem has a particular cause.

## Requirements and build

.NET SDK 10.0.300 or a later 10.0 patch. From a clean checkout:

```powershell
dotnet restore --locked-mode
dotnet build --no-restore
dotnet test --no-restore
```

## First run

`validate` and `plan` do not access the network. Read the profile itself before approving a run. Only a SHA-256 digest of the **exact UTF-8 profile bytes** grants consent to that particular profile:

```powershell
dotnet run --project src/Scout.Cli -- plan examples/public-web.json
dotnet run --project src/Scout.Cli -- run examples/public-web.json --allow-profile-digest <digest-from-plan> --out report.json
dotnet run --project src/Scout.Cli -- render report.json --format html --out report.html
```

The example makes requests to a public demonstration domain. Running is optional. Do not include private targets or secrets in a profile. The CLI intentionally has no `--allow-private` switch.

`run` needs an existing output directory and refuses to replace a file unless `--overwrite` is supplied. `render` accepts `--format html` or `--format markdown`; `diff` takes two JSON reports and writes Markdown only when their profile ID, exact digest and network-policy version match. Up to three samples can be requested with `--samples 1`, `2` or `3`. No result is silently retried.

Exit codes: `0` complete with expected checks passing; `1` complete with observed check failures; `2` invalid input/output; `3` partial or internal error; `130` user cancellation. A blocked or inconclusive check never produces exit code 0. Run reports use a separate `run_status` (`complete`, `partial`, `cancelled`, `error`).

## Contract and boundaries

See [version 0.1 contract](docs/CONTRACT-0.1.md), [threat model](docs/THREAT-MODEL.md), and [architecture decision](docs/ADR-0001.md). The CLI accepts a maximum of 10 endpoints, 3 samples, 128 KiB profiles, and a 90-second total run budget. It permits only ordered prefixes of `dns,tcp,tls,http`. HTTPS requests use the approved IP, preserve the DNS name for certificate validation and `Host`, and do not follow redirects. HTTP response bodies are never stored.

Reports contain per-run HMAC tokens for addresses rather than raw addresses. IDs, timing, platform and status remain visible; this is **not complete anonymization**. Review every report before sharing it.

## Interpretation and privacy

DNS `pass` means the system resolver returned addresses that the public-address policy accepted. TCP `pass` means a socket connected to a validated address, with connect duration recorded. TLS `pass` means the certificate chain and hostname validated at that moment; online revocation is **not** checked. HTTP `pass` means a HEAD/GET response matched the profile's expected status. None of these checks proves that a game, voice connection or app works end to end. `fail` records a directly observed unmet expectation. `blocked` records a safety-policy refusal. `inconclusive` records that a reliable observation was unavailable. `skipped` records a dependency or total-budget condition.

The JSON report is the canonical artifact. The static HTML and Markdown renderers accept only the report model, escape display values, and do not fetch external assets. No cookies, authorization headers, response bodies, packet traces or application files are collected. `report_id` is random. Address tokens are HMAC values using a new in-memory key each run; they cannot be correlated across runs. The report still includes public endpoint IDs, timestamps and platform context, so check it before sending it to anyone.

## Development

The public profile schema is at [contracts/profile-0.1.schema.json](contracts/profile-0.1.schema.json). The strict C# parser is authoritative for duplicate keys, hostname and exact request-path rules that generic JSON Schema validators may not fully enforce. External includes and environment substitution are unsupported. Tests include controlled loopback fixtures, but these are not available as a CLI network-policy option. GitHub CI runs a read-only build and test matrix when the repository is published; local evidence is recorded under [docs/evidence](docs/evidence/2026-11-20-stage-1.md).

## Project scope

The public implementation is original code in a fresh repository. It contains no JITTEROFF accounts, private API, server configuration, captures, or proprietary application code. An optional JITTEROFF adapter can be considered later in a separate private repository. Maintainers and contributors must keep that boundary.

License: Apache-2.0. See [LICENSE](LICENSE). Security issues: [SECURITY.md](SECURITY.md).
