param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$DepsPath,
    [Parameter(Mandatory = $true)][ValidateSet('win-x64', 'linux-x64')][string]$Rid,
    [Parameter(Mandatory = $true)][string]$RuntimeVersion,
    [Parameter(Mandatory = $true)][string]$RuntimePackPath,
    [Parameter(Mandatory = $true)][string]$HostPackPath,
    [string]$WindowsLicensePath
)

$ErrorActionPreference = 'Stop'
foreach ($name in @('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT')) {
    $runtimeFile = Join-Path $RuntimePackPath $name
    $hostFile = Join-Path $HostPackPath $name
    if (-not (Test-Path $runtimeFile) -or -not (Test-Path $hostFile) -or
        (Get-FileHash $runtimeFile -Algorithm SHA256).Hash -ne (Get-FileHash $hostFile -Algorithm SHA256).Hash) {
        throw "The reviewed runtime and native-host $name files are missing or differ."
    }
}
$hostNuspec = Join-Path $HostPackPath "microsoft.netcore.app.host.$Rid.nuspec"
if (-not (Test-Path $hostNuspec) -or
    (Get-Content $hostNuspec -Raw) -notmatch '<license type="expression">MIT</license>') {
    throw 'The native-host pack does not declare the reviewed MIT license.'
}
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -AsHashtable
$deps = Get-Content -LiteralPath $DepsPath -Raw | ConvertFrom-Json -AsHashtable
$runtimeName = "Microsoft.NETCore.App.Runtime.$Rid"
$hostName = "Microsoft.NETCore.App.Host.$Rid"
$runtimeLibrary = "runtimepack.$runtimeName/$RuntimeVersion"
$unexpectedLibraries = @($deps.libraries.Keys | Where-Object {
    $_ -ne $runtimeLibrary -and $_ -notmatch '^Scout\.[A-Za-z]+/0\.1\.0$'
})
if (-not $deps.libraries.Contains($runtimeLibrary) -or $unexpectedLibraries.Count -gt 0) {
    throw "Published dependency list does not match the reviewed Scout/runtime set: $($unexpectedLibraries -join ', ')"
}

$root = @($manifest.packages | Where-Object { $_.SPDXID -eq 'SPDXRef-RootPackage' })
$runtime = @($manifest.packages | Where-Object { $_.name -eq $runtimeName -and $_.versionInfo -eq $RuntimeVersion })
if ($root.Count -ne 1 -or $runtime.Count -ne 1) {
    throw 'SBOM generator did not identify exactly one root and target runtime package.'
}
$root = $root[0]
$runtime = $runtime[0]
$root.licenseDeclared = 'Apache-2.0'
$root.licenseConcluded = 'Apache-2.0'
$root.licenseInfoFromFiles = @('Apache-2.0')
$runtime.licenseDeclared = if ($Rid -eq 'win-x64') { 'MIT AND LicenseRef-DotNet-Library' } else { 'MIT' }
$runtime.licenseConcluded = $runtime.licenseDeclared
$runtime.licenseComments = 'Primary .NET runtime terms; consult bundled third-party notices for additional components.'
$runtime.supplier = 'Organization: Microsoft Corporation'

# The native host is embedded in the single-file executable. sbom-tool may omit
# this build input, so add it explicitly after checking its installed pack.
$hostPackage = @($manifest.packages | Where-Object { $_.name -eq $hostName -and $_.versionInfo -eq $RuntimeVersion })
if ($hostPackage.Count -gt 1) { throw 'SBOM contains duplicate native-host packages.' }
if ($hostPackage.Count -eq 0) {
    $hostPackage = @{
        name = $hostName
        SPDXID = "SPDXRef-Package-AppHost-$Rid"
        versionInfo = $RuntimeVersion
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        licenseDeclared = 'MIT'
        licenseConcluded = 'MIT'
        copyrightText = 'NOASSERTION'
        supplier = 'Organization: Microsoft Corporation'
        externalRefs = @(@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:nuget/$hostName@$RuntimeVersion"
        })
    }
} else {
    $hostPackage = $hostPackage[0]
    $hostPackage.licenseDeclared = 'MIT'
    $hostPackage.licenseConcluded = 'MIT'
    $hostPackage.supplier = 'Organization: Microsoft Corporation'
}

if ($Rid -eq 'win-x64') {
    if (-not $WindowsLicensePath -or -not (Test-Path -LiteralPath $WindowsLicensePath)) {
        throw 'The verified Windows .NET Library License text is required.'
    }
    $licenseText = Get-Content -LiteralPath $WindowsLicensePath -Raw
    $expectedHash = '7f6839a61ce892b79c6549e2dc5a81fdbd240a0b260f8881216b45b7fda8b45d'
    if ((Get-FileHash $WindowsLicensePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        throw 'Windows .NET Library License text differs from the verified 10.0.15 archive.'
    }
    if ($licenseText -notmatch '^MICROSOFT SOFTWARE LICENSE TERMS' -or
        $licenseText -notmatch 'MICROSOFT \.NET LIBRARY') {
        throw 'Windows .NET Library License text does not match the expected document.'
    }
    $manifest.hasExtractedLicensingInfos = @(@{
        licenseId = 'LicenseRef-DotNet-Library'
        name = 'Microsoft .NET Library License'
        extractedText = $licenseText
    })
}

$manifest.packages = @($root, $runtime, $hostPackage)
$manifest.relationships = @(
    @{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = $root.SPDXID },
    @{ spdxElementId = $root.SPDXID; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = $runtime.SPDXID },
    @{ spdxElementId = $root.SPDXID; relationshipType = 'DEPENDS_ON'; relatedSpdxElement = $hostPackage.SPDXID }
)

$manifest | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $ManifestPath -Encoding utf8
