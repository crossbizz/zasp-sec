[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$SignedExecutable,
 [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$AgentSHA256,
 [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$SignerThumbprint,
 [Parameter(Mandatory)][string]$NewOutput
)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $NewOutput) { throw 'Use a new staging directory.' }
$signature=Get-AuthenticodeSignature -LiteralPath $SignedExecutable
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $SignerThumbprint -or (Get-FileHash -LiteralPath $SignedExecutable -Algorithm SHA256).Hash -ne $AgentSHA256) { throw 'Release verification failed.' }
$inputDir=Join-Path $NewOutput 'input'
New-Item -Type Directory -Path $NewOutput -ErrorAction Stop | Out-Null
New-Item -Type Directory -Path $inputDir -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $SignedExecutable -Destination (Join-Path $inputDir 'zasp-device-windows.exe')
foreach ($f in @('Manage-Device.ps1','Collect-Inventory.ps1','Watch-Inventory.ps1','Sync-Inventory.ps1','Manage-Pretool.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination (Join-Path $inputDir $f) }
$detector=(Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'Detect-Device.ps1.template')).Replace('__SHA256__',$AgentSHA256.ToUpperInvariant()).Replace('__THUMBPRINT__',$SignerThumbprint.ToUpperInvariant())
[IO.File]::WriteAllText((Join-Path $NewOutput 'Detect-Device.ps1'),$detector)
# The optional Win32 assignment uses the same verified payload and a separate detector.
$pretoolDetect=(Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'Manage-Pretool.ps1'))
$pretoolDetect=$pretoolDetect.Substring($pretoolDetect.IndexOf("$([char]36)ErrorActionPreference='Stop'"))
$pretoolDetect="$([char]36)Action='Detect'`n$([char]36)AgentSHA256='$AgentSHA256'`n$([char]36)SignerThumbprint='$SignerThumbprint'`n"+$pretoolDetect
[IO.File]::WriteAllText((Join-Path $NewOutput 'Detect-Pretool.ps1'),$pretoolDetect)
