# Distributed component licenses

Scout Core's own source and binary are Apache-2.0 licensed. The self-contained
candidate archives also embed components from the .NET 10.0.11 runtime pack for
the archive's platform. The packaging job copies the **exact pack's**
`LICENSE.TXT` and `THIRD-PARTY-NOTICES.TXT` into each archive as
`DOTNET-RUNTIME-LICENSE.txt` and
`DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt`. The runtime pack declares MIT in its
NuGet metadata. The .NET files do not become Apache-2.0 merely because the
Scout Core application is Apache-2.0.

The xUnit and test SDK packages are used to build and test the project. They
are not bundled in the self-contained CLI archive. The generated SPDX SBOM
lists packaged files and dependencies, but a `NOASSERTION` license field is
not proof of license clearance. Before tagging a release, inspect the actual
archive, verify the runtime license and notices are present, and review the
SBOM's remaining unidentified components against the archive. This review is
tracked by [release issue #3](https://github.com/Trauma990/jitteroff-scout-core/issues/3).

References: [.NET licensing overview](https://github.com/dotnet/core/blob/main/license-information.md),
[.NET runtime asset licensing model](https://github.com/dotnet/runtime/blob/main/docs/project/licensing-assets.md).
