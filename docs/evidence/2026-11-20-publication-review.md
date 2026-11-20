# Public-source preflight — 2026-11-20

Scope reviewed: staged source and documentation only. No existing JITTEROFF application source or server configuration was copied. The current repository has no remote yet; this is a local preflight, not a GitHub publication result.

- `git diff --cached --check`: no whitespace errors.
- Staged paths were checked for `bin/`, `obj/`, `artifacts/`, `reports/`, executable, archive, key, certificate and environment-file extensions: none included.
- Staged text was searched for known production IPs, JITTEROFF private paths, the production domain and a previously supplied credential string: no matches. The credential value is **not** included in this document or repository.
- Application projects use only .NET 10 framework APIs and local project references. NuGet dependencies exist only in the xUnit/coverage test project and are captured by lock files.
- Apache-2.0 license text was obtained from the official Apache Software Foundation source. No proprietary code was transferred from the existing product.

Before public push: confirm the GitHub owner, inspect the final staged diff again, and run clean locked restore/build/tests. After push: inspect Windows and Linux CI, then update status with actual links and evidence. No 0.1 release tag is authorized by this preflight alone.
