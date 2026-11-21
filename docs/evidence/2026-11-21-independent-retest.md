# Independent retest remediation (2026-11-21)

The independent retest against `b5bb4d1` found six reproducible pre-release defects. This change addresses each without introducing a dependency on JITTEROFF's private infrastructure.

- DNS re-resolution with an empty answer now produces a validated `fail/dns_no_answer` result at DNS, TCP, TLS, or HTTP. Controlled resolver tests cover TCP/TLS and a local TLS fixture covers HTTP. No external connection is used by those tests.
- Linux candidate packaging uses Unix `zip` to retain the executable bit. The CI smoke job downloads the artifact, extracts it, checks `Scout.Cli` is executable, and runs the documented offline `plan` command.
- SBOM curation regenerates the SHA-256 sidecar after the final manifest write. The package job validates the digest before archiving and after extraction; the release gate verifies it inside both final archives.
- Profile identifiers, endpoint identifiers, host labels, and profile/report versions use absolute regex end anchors. Parser and direct-library tests reject newline-bearing values before resolution.
- Imported report JSON requires all contract fields and rejects null/duplicate check objects. The CLI classifies semantically invalid report imports as input errors (exit 2). Tests cover raw JSON and the spawned CLI process.
- The IPv6 policy applies the IANA non-global default for `2001::/23`, with the specific global exceptions from the [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry). Its report policy identifier is now `public-address-v2`.

Local verification: locked restore and Release tests with .NET SDK `10.0.404` passed **90/90**, with zero skipped. [GitHub CI](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44903426135) passed on Windows and Ubuntu. The [non-publishing package run](https://github.com/Trauma990/jitteroff-scout-core/actions/runs/44903495135) passed both package jobs, downloaded Linux archive execution, and a downloaded Windows executable run without .NET installed.

Both GitHub artifact containers were independently downloaded and matched their GitHub SHA-256 digests: Linux `cbb24df806cf6b3cb4ca9f9067f62206b57b867fedb342851ffef0061beda534`; Windows `6cdaa4c0c60e771d749481fbb64df51c68a98f657ac28e3f70aac20e855055b4`. The inner ZIPs matched their included checksum files: Linux `2906c46d2718ee80f314b4f26843c22fbb5ca33eede4e959aaa7e4fac3ae5e8f`; Windows `91d69e091eb2a668d9b71087258a99f69996d7fbebb7439936325eeb688855d8`. Independently inspected Linux ZIP metadata records `Scout.Cli` as `0755`. Each extracted SBOM matched its `.sha256` sidecar: Linux `8adfacaabadc6224b1a601b369654f374941605a27d7494b318fc678b31d3273`; Windows `00381f3849794337aac768d83fd4a32d178d98144ee502d46ef81c91f8105c5d`.

This evidence covers the `0.1.0-dev` candidate from this branch. It is not a public-release approval or a claim that a `v0.1.0` tag exists. The final package workflow must run from `main` at the release commit.
