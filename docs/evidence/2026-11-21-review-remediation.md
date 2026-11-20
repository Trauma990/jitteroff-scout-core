# Review remediation — 2026-11-21

Base reviewed commit: `2b9d908`. This is local development evidence, not proof of a tagged release.

## Changes

- HTTP reads the final response after bounded informational responses. `101` and missing final responses fail. All response headers share a 16 KiB limit, and at most eight informational blocks are accepted.
- Profiles reject informational expected statuses. The public `Runner` snapshots and validates caller-built profiles before any network work, preventing later caller mutation from changing the destination.
- The IPv4 policy blocks `192.0.0.0/24` and `192.0.2.0/24` precisely, not entire `/16` ranges.
- Imported reports validate identifiers, run metadata, probe-specific reasons, and the required address/status evidence for successful checks. An HTTP pass without a final status is rejected.
- Candidate packaging uses a locked restore for `win-x64` and `linux-x64`, then publishes without restore. A later review found that the previous candidate embedded .NET 10.0.11, which has published security advisories; commit `f1e70ab` pins .NET 10.0.15 and includes that runtime pack's license and third-party notices.

## Local checks

- `dotnet restore --locked-mode -p:SelfContained=true -p:RuntimeFrameworkVersion=10.0.15` — passed locally.
- `dotnet test --no-restore --configuration Release` — 61 passed, 0 failed.
- `dotnet publish ... --runtime win-x64 --self-contained true --no-restore -p:RuntimeFrameworkVersion=10.0.15` — passed on the developer Windows host; the offline `plan` command passed.
- `dotnet publish ... --runtime linux-x64 --self-contained true --no-restore -p:RuntimeFrameworkVersion=10.0.15` — cross-publish passed on the developer Windows host; Linux execution was not repeated here.
- Both generated runtime configuration files name `Microsoft.NETCore.App/10.0.15`.

## Public CI and candidate artifacts

- Review-remediation code commit `260619e` passed [Windows and Ubuntu CI](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44828471884).
- [Manual candidate run 44828879276](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44828879276) passed locked restore, tests, self-contained publish, SBOM validation, ZIP checksum verification and artifact upload for Windows and Linux. This run embedded .NET 10.0.11 and is now obsolete.
- [Commit `f1e70ab` CI](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44831960917) and [candidate run 44831969842](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44831969842) passed on Windows and Ubuntu. Both new candidates embed .NET 10.0.15.
- Downloaded both new CI artifacts and independently matched each inner ZIP to its `SHA256SUMS` file: Windows SHA-256 `2f8a46770047204a8cff2ff2f667bfef0599ab146364affb8e82d8a665b945d9`; Linux SHA-256 `dcd4bcf45a77f54b400a6a73e23da0965b46dea628c2592cfbf18df1afa0baa1`.
- Both new archives contain the binary, Scout license, .NET runtime license/notices, license notes and SPDX SBOM. The copied runtime license and notices match the local 10.0.15 runtime packs by SHA-256. The downloaded Windows binary passed offline `plan` on this developer host; this is not the clean-host test.
- The new Linux SBOM lists six packages and the Windows SBOM seven, all at 10.0.15 where applicable. All package license fields are `NOASSERTION`; both include both RIDs from source lockfiles and additional runtime packages not present in the CLI's actual dependency list. They are not per-archive license clearance.
- The actual `Scout.Cli.deps.json` for each local build names only its own platform's `Microsoft.NETCore.App.Runtime/10.0.15`; the app-host binary is also embedded. The 10.0.15 runtime and host packs both declare MIT in their NuGet metadata and carry identical license and notice files for each platform. The [general .NET licensing overview](https://github.com/dotnet/core/blob/main/license-information.md) describes Windows product distributions under the .NET Library License, so the formal Windows distribution interpretation remains open.

## Still open before v0.1.0

- Run the downloaded commit `f1e70ab` archive on a Windows machine without .NET SDK **and** Runtime, documenting the exact host environment.
- Correct or supplement the SBOM so it identifies the actual shipped components, review remaining `NOASSERTION` fields, and resolve the Windows distribution-license interpretation.
- Require CI on `main` via branch protection or a repository ruleset, if the GitHub plan permits it.
