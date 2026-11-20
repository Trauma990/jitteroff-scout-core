# Windows .NET runtime license provenance

`windows-runtime-10.0.15-LICENSE.txt` is the unmodified `LICENSE.txt` from
Microsoft's official [`dotnet-runtime-10.0.15-win-x64.zip`](https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.15/dotnet-runtime-10.0.15-win-x64.zip).
The archive's SHA-512 was checked against
[Microsoft's 10.0 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json):

`06f0bedd59ae4ac722ada805a6d6bbf605bcdc790c71f59b7003878072902b5cde5dec8c40c0baa81192660d4748e9d79afdbdcb0c0ea9d6b821d0a044c4c6dd`

The extracted license file's SHA-256 is
`7f6839a61ce892b79c6549e2dc5a81fdbd240a0b260f8881216b45b7fda8b45d`.
Microsoft's [Windows licensing guidance](https://github.com/dotnet/core/blob/main/license-information-windows.md)
identifies the runtime embedded in a single-file Windows binary under the
.NET Library License. The runtime pack's separate MIT text and third-party
notices are also bundled with the candidate artifact.
