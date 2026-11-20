# Review remediation — 2026-11-21

Base reviewed commit: `2b9d908`. This is local development evidence, not proof of a tagged release.

## Changes

- HTTP reads the final response after bounded informational responses. `101` and missing final responses fail. All response headers share a 16 KiB limit, and at most eight informational blocks are accepted.
- Profiles reject informational expected statuses. The public `Runner` snapshots and validates caller-built profiles before any network work, preventing later caller mutation from changing the destination.
- The IPv4 policy blocks `192.0.0.0/24` and `192.0.2.0/24` precisely, not entire `/16` ranges.
- Imported reports validate identifiers, run metadata, probe-specific reasons, and the required address/status evidence for successful checks. An HTTP pass without a final status is rejected.
- Candidate packaging uses a locked restore for `win-x64` and `linux-x64`, then publishes without restore. It includes the exact .NET 10.0.11 runtime pack's license and third-party notices.

## Local checks

- `dotnet restore --locked-mode -p:SelfContained=true -p:RuntimeFrameworkVersion=10.0.11` — passed.
- `dotnet test --no-restore --configuration Release` — 61 passed, 0 failed.
- `dotnet publish ... --runtime win-x64 --self-contained true --no-restore` — passed on the developer Windows host.
- `dotnet publish ... --runtime linux-x64 --self-contained true --no-restore` — cross-publish passed on the developer Windows host; Linux execution was not repeated here.

## Still open before v0.1.0

- Run the **new final-SHA** archive on a Windows machine without .NET SDK **and** Runtime; verify its downloaded SHA-256.
- Inspect both final archives and SBOMs, confirm license notices, and resolve remaining unidentified license entries. The packaging workflow has not yet been rerun in public CI for this change.
- Require CI on `main` via branch protection or a repository ruleset, if the GitHub plan permits it.
