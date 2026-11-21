# Independent retest remediation (2026-11-21)

The independent retest against `b5bb4d1` found six reproducible pre-release defects. This change addresses each without introducing a dependency on JITTEROFF's private infrastructure.

- DNS re-resolution with an empty answer now produces a validated `fail/dns_no_answer` result at DNS, TCP, TLS, or HTTP. Controlled resolver tests cover TCP/TLS and a local TLS fixture covers HTTP. No external connection is used by those tests.
- Linux candidate packaging uses Unix `zip` to retain the executable bit. The CI smoke job downloads the artifact, extracts it, checks `Scout.Cli` is executable, and runs the documented offline `plan` command.
- SBOM curation regenerates the SHA-256 sidecar after the final manifest write. The package job validates the digest before archiving and after extraction; the release gate verifies it inside both final archives.
- Profile identifiers, endpoint identifiers, host labels, and profile/report versions use absolute regex end anchors. Parser and direct-library tests reject newline-bearing values before resolution.
- Imported report JSON requires all contract fields and rejects null/duplicate check objects. The CLI classifies semantically invalid report imports as input errors (exit 2). Tests cover raw JSON and the spawned CLI process.
- The IPv6 policy applies the IANA non-global default for `2001::/23`, with the specific global exceptions from the [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry). Its report policy identifier is now `public-address-v2`.

Local verification: locked restore and Release tests with .NET SDK `10.0.404` passed **90/90**, with zero skipped. The Linux archive permission, SBOM sidecar, and clean-host package checks require a fresh GitHub packaging run before any release. This file records implementation evidence, not a public-release approval.
