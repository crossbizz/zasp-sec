# Install or uninstall the exact approved binary for the signed-in employee.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Install','Uninstall')][string]$Action)
$ErrorActionPreference = 'Stop'
if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { throw 'Assign this app with User install behavior.' }
$local = [Environment]::GetFolderPath('LocalApplicationData')
if ([String]::IsNullOrWhiteSpace($local)) { throw 'Local Application Data is unavailable.' }
$policy = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release.json') -Raw | ConvertFrom-Json
if ($policy.schema_version -ne 'zasp.intune-cli.v1' -or $policy.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or $policy.signer_thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid release manifest.' }

function Assert-PlainPath([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -Force -LiteralPath $Path
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted reparse point in the CLI install path.' }
    }
}
function Test-Release([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    Assert-PlainPath $Path
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    if ($hash -ne $policy.sha256) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return $signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq $policy.signer_thumbprint
}
$vendor = Join-Path $local 'Zasp'
$folder = Join-Path $vendor 'CLI'
$target = Join-Path $folder 'zaspctl.exe'
Assert-PlainPath $vendor
Assert-PlainPath $folder
Assert-PlainPath $target

if ($Action -eq 'Uninstall') {
    # An older uninstall assignment must not remove a newer release or user files.
    if ((Test-Path -LiteralPath $target -PathType Leaf) -and (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $policy.sha256) {
        Remove-Item -LiteralPath $target
    }
    return
}
if (Test-Release $target) { return }
$package = Join-Path $PSScriptRoot 'zaspctl.exe'
if (!(Test-Release $package)) { throw 'Package hash, Authenticode chain or pinned signer did not match this release.' }
[IO.Directory]::CreateDirectory($folder) | Out-Null
Assert-PlainPath $vendor
Assert-PlainPath $folder
$staged = Join-Path $folder ([Guid]::NewGuid().ToString() + '.tmp')
$backup = Join-Path $folder ([Guid]::NewGuid().ToString() + '.bak')
try {
    [IO.File]::Copy($package, $staged, $false)
    if (!(Test-Release $staged)) { throw 'Staged CLI verification failed.' }
    Assert-PlainPath $target
    if (Test-Path -LiteralPath $target) {
        [IO.File]::Replace($staged, $target, $backup)
    } else {
        [IO.File]::Move($staged, $target)
    }
} finally {
    if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup }
}
