[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
# Exercise the staging path with a synthetic signature result. The separate
# native unsigned-release test uses the real Authenticode verifier.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('zasp-pretool-stage-'+[guid]::NewGuid().ToString('N'))
try {
 [IO.Directory]::CreateDirectory($fixture)|Out-Null
 $exe=Join-Path $fixture 'synthetic-fixture.bin'
 [IO.File]::WriteAllText($exe,'inert staging fixture')
 $hash=(Get-FileHash -LiteralPath $exe).Hash
 $thumb='A'*40
 function Get-AuthenticodeSignature([string]$LiteralPath) {
  if ($LiteralPath -cne $exe) { throw 'Unexpected staging input.' }
  return [pscustomobject]@{Status='Valid'; SignerCertificate=[pscustomobject]@{Thumbprint=$thumb}}
 }
 $stage=Join-Path $fixture 'stage'
 & (Join-Path $PSScriptRoot 'Stage-Device.ps1') -SignedExecutable $exe -AgentSHA256 $hash -SignerThumbprint $thumb -NewOutput $stage
 foreach ($name in @('Manage-Device.ps1','Manage-Pretool.ps1','Collect-Inventory.ps1')) {
  if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $stage "input/$name")).Hash) { throw 'Staged management file differs.' }
 }
 foreach ($name in @('Detect-Device.ps1','Detect-Pretool.ps1')) {
  $path=Join-Path $stage $name
  $source=[IO.File]::ReadAllText($path)
  $errors=$null; $tokens=$null
  $null=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
  if ($errors.Count -or !$source.Contains($hash) -or !$source.Contains($thumb)) { throw "Invalid generated $name" }
 }
 $target=Join-Path $fixture 'wrong-pin'
 $rejected=$false
 try { & (Join-Path $PSScriptRoot 'Stage-Device.ps1') -SignedExecutable $exe -AgentSHA256 $hash -SignerThumbprint ('B'*40) -NewOutput $target } catch { $rejected=$_.Exception.Message -eq 'Release verification failed.' }
 if (!$rejected -or (Test-Path -LiteralPath $target)) {throw 'Mismatched signer was staged.'}
 Write-Output 'Verified both generated Intune detectors and packaged broker management scripts.'
} finally { if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force } }
