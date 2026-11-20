# Distributed component licenses

Scout Core's own source and binary are Apache-2.0 licensed. The self-contained
candidate archives also embed components from the .NET 10.0.15 runtime and
native app-host packs for the archive's platform. The packaging job copies the **exact runtime pack's**
`LICENSE.TXT` and `THIRD-PARTY-NOTICES.TXT` into each archive as
`DOTNET-RUNTIME-LICENSE.txt` and
`DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt`. The runtime pack declares MIT in its
NuGet metadata. On the locally inspected 10.0.15 packs, the app-host pack's
license and notice files have identical SHA-256 hashes to the runtime pack's
files for each platform. The .NET files do not become Apache-2.0 merely because
the Scout Core application is Apache-2.0.

For Windows, [Microsoft's platform-specific guidance](https://github.com/dotnet/core/blob/main/license-information-windows.md)
identifies `coreclr.dll` and the runtime embedded in a single-file binary under
the [.NET Library License](https://dotnet.microsoft.com/en-us/dotnet_library_license.htm),
with other runtime files generally under MIT. The NuGet runtime pack's MIT
metadata and license file do not override that guidance. The Windows archive
therefore also includes `DOTNET-WINDOWS-LIBRARY-LICENSE.txt`, copied from
Microsoft's official `dotnet-runtime-10.0.15-win-x64.zip` after its SHA-512 was
checked against [Microsoft's release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json).
The source copy is in `third_party/dotnet/` with SHA-256
`7f6839a61ce892b79c6549e2dc5a81fdbd240a0b260f8881216b45b7fda8b45d`.
Distribution of a Windows binary also requires the publisher to review the
Library License's end-user terms and obligations; packaging the text does not
itself complete that review.

The xUnit and test SDK packages are used to build and test the project. They
are not bundled in the self-contained CLI archive. The generated SPDX SBOM
lists packaged files; a post-generation check reads the published CLI's
dependency manifest and limits package entries to Scout Core, the target
runtime pack, and the native app-host pack. It records the primary declared
licenses and embeds the Windows Library License text as an SPDX LicenseRef.
Individual file licenses remain `NOASSERTION` because the single-file binary
contains components with multiple licenses and third-party notices. An SPDX
declaration is evidence of inventory work, not a substitute for reviewing the
actual archive, notices, and redistribution obligations. This review is
tracked by [release issue #3](https://github.com/Trauma990/jitteroff-scout-core/issues/3).

References: [.NET licensing overview](https://github.com/dotnet/core/blob/main/license-information.md),
[.NET runtime asset licensing model](https://github.com/dotnet/runtime/blob/main/docs/project/licensing-assets.md).
