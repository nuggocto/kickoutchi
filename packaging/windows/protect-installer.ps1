# cargo-dist 0.34.0 does not verify PowerShell installer downloads.
# Embed hashes of the same-run Windows artifacts before testing or publishing.
param(
    [Parameter(Mandatory)]
    [string]$Distrib
)

$ErrorActionPreference = 'Stop'

function Replace-Once([string]$Text, [string]$Old, [string]$New) {
    $index = $Text.IndexOf($Old, [StringComparison]::Ordinal)
    if ($index -lt 0 -or $index -ne $Text.LastIndexOf($Old, [StringComparison]::Ordinal)) {
        throw "Unexpected cargo-dist PowerShell template: expected exactly one occurrence of '$Old'."
    }
    return $Text.Replace($Old, $New)
}

$directory = (Resolve-Path -LiteralPath $Distrib).Path
$installerPath = Join-Path $directory 'kickoutchi-installer.ps1'
$installer = [IO.File]::ReadAllText($installerPath)
if ($installer.Contains('# SIG # Begin signature block')) {
    throw 'Refusing to rewrite an already signed installer.'
}
if ($installer.Contains('function Assert-ReleaseArtifactHash(')) {
    throw 'The installer already has release checksum checks.'
}

$archive = 'kickoutchi-x86_64-pc-windows-msvc.zip'
$updater = 'kickoutchi-x86_64-pc-windows-msvc-update'
$archiveHash = (Get-FileHash -LiteralPath (Join-Path $directory $archive) -Algorithm SHA256).Hash
$updaterHash = (Get-FileHash -LiteralPath (Join-Path $directory $updater) -Algorithm SHA256).Hash

$verify = @'
function Assert-ReleaseArtifactHash($path, $artifact, $expected) {
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $stream = [IO.File]::OpenRead($path)
    try {
      $actual = [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '')
    } finally {
      $stream.Dispose()
    }
  } finally {
    $sha256.Dispose()
  }
  if ($actual -ne $expected) {
    throw "SHA-256 mismatch for $artifact (expected $expected, got $actual)"
  }
}
'@

# Verify the archive before it is unpacked. Verify the updater before returning
# the staged files to Invoke-Installer, which changes binaries, receipt and PATH.
$newline = if ($installer.Contains("`r`n")) { "`r`n" } else { "`n" }
$verify = $verify -replace '\r?\n', $newline
$download = 'function Download($download_url, $platforms, $arch) {'
$archiveCall = '  Invoke-DownloadFile -client $wc -url $url -path $dir_path'
$updaterCall = '    Invoke-DownloadFile -client $wc -url $updater_url -path $out_name'
$installer = Replace-Once $installer $download "$verify$newline$newline$download"
$installer = Replace-Once $installer $archiveCall (
    $archiveCall + $newline + ('  Assert-ReleaseArtifactHash $dir_path $artifact_name ''{0}''' -f $archiveHash)
)
$installer = Replace-Once $installer $updaterCall (
    $updaterCall + $newline + ('    Assert-ReleaseArtifactHash $out_name $updater_id ''{0}''' -f $updaterHash)
)

[IO.File]::WriteAllText($installerPath, $installer)
