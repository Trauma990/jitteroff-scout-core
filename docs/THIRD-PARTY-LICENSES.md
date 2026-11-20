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

There is an unresolved licensing interpretation for Windows: the exact
10.0.15 runtime pack carries an MIT license file and declares MIT in NuGet,
while [.NET's general licensing overview](https://github.com/dotnet/core/blob/main/license-information.md)
describes Windows product distributions under the
[.NET Library License](https://dotnet.microsoft.com/en-us/dotnet_library_license.htm).
Do not infer that the package metadata alone settles the distribution terms.
Resolve this discrepancy before a formal Windows release.

The xUnit and test SDK packages are used to build and test the project. They
are not bundled in the self-contained CLI archive. The generated SPDX SBOM
lists packaged files and dependencies, but a `NOASSERTION` license field is
not proof of license clearance. The candidate SBOMs include both Linux and
Windows runtime identifiers from the source lockfiles, so their package lists
are not exact inventories of their respective binary archives. Before tagging
a release, inspect the actual
archive, verify the runtime license and notices are present, and review the
SBOM's remaining unidentified components against the archive. This review is
tracked by [release issue #3](https://github.com/Trauma990/jitteroff-scout-core/issues/3).

References: [.NET licensing overview](https://github.com/dotnet/core/blob/main/license-information.md),
[.NET runtime asset licensing model](https://github.com/dotnet/runtime/blob/main/docs/project/licensing-assets.md).
