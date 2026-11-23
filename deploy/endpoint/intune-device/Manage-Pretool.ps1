[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Install','Detect','Uninstall')][string]$Action,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$AgentSHA256,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SignerThumbprint,
 [string]$IssuerPublicKey,[string]$EmployeeHome,[string]$Workspace,[string]$DelegationVerifier,
 [ValidateSet('continue','deny')][string]$OnUnavailable='continue',[switch]$ExistingManagedHook
)
$ErrorActionPreference='Stop'
if (![Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -or ![Environment]::Is64BitProcess) { throw 'Run in 64-bit LocalSystem context.' }
$pf=[Environment]::GetFolderPath('ProgramFiles')
$root=Join-Path $pf 'Zasp Inventory Device'
$claude=Join-Path $pf 'ClaudeCode'
$hook=Join-Path $claude 'managed-settings.json'
$exe=Join-Path $root 'zasp-device-windows.exe'
$cfg=Join-Path $root 'pretool.json'
$owned=Join-Path $root 'pretool-managed-hook.sha256'
$task='Zasp Claude Pretool Broker'
$matcher='^(Bash|Read|Write|Edit|MultiEdit|Glob|Grep|WebFetch|mcp__.*)$'
$utf8=New-Object Text.UTF8Encoding($false)
function Assert-Managed([string]$Path) {
 if (!(Test-Path -LiteralPath $Path)) { return }
 $item=Get-Item -LiteralPath $Path -Force
 if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Managed paths must not be reparse points.' }
 $acl=Get-Acl -LiteralPath $Path
 $admins=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $admins) { throw 'Managed object has an unexpected owner.' }
 foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if ($ace.AccessControlType -ne 'Allow' -or ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
  if (($ace.IdentityReference.Value -notin $admins) -and (([int]$ace.FileSystemRights -band 0x500d0156) -ne 0)) { throw 'Untrusted principal may modify managed data.' }
 }
}
function Write-Atomic([string]$Path,[string]$Value) {
 $tmp=Join-Path ([IO.Path]::GetDirectoryName($Path)) ([guid]::NewGuid().ToString()+'.tmp')
 try {
  [IO.File]::WriteAllText($tmp,$Value,$utf8)
  if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp,$Path,$null) } else { [IO.File]::Move($tmp,$Path) }
 } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp } }
}
function Valid-Release {
 if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
 $sig=Get-AuthenticodeSignature -LiteralPath $exe
 return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Thumbprint -eq $SignerThumbprint -and (Get-FileHash -LiteralPath $exe).Hash -eq $AgentSHA256)
}
foreach ($path in @($root,$claude,$exe,$cfg,$hook,$owned)) { Assert-Managed $path }
$hasMarker=Test-Path -LiteralPath $owned -PathType Leaf
$hasHook=Test-Path -LiteralPath $hook -PathType Leaf
$allowedHashes=@()
if ($hasMarker) {
 $allowedHashes=@([IO.File]::ReadAllLines($owned))
 if ($allowedHashes.Count -notin @(1,2) -or @($allowedHashes | Where-Object { $_ -notmatch '^[A-F0-9]{64}$' }).Count) { throw 'Managed hook ownership marker is invalid.' }
}
$currentHash=if ($hasHook) { (Get-FileHash -LiteralPath $hook).Hash }
$ownsHook=$hasMarker -and $hasHook -and $currentHash -cin $allowedHashes
$job=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
$externalFlag=Join-Path $root 'pretool-external-hook.txt'
Assert-Managed $externalFlag
$external=($ExistingManagedHook -or (Test-Path -LiteralPath $externalFlag -PathType Leaf))
if ($DelegationVerifier) { $matcher='.*' }
$verb=if ($DelegationVerifier) {'claude-pretool-delegated'} elseif ($OnUnavailable -eq 'deny') {'claude-pretool'} else {'claude-pretool-open'}
$command='"'+$exe.Replace('\','/')+'" '+$verb
function Has-ExternalHook {
 if (!$hasHook) {return $false}
 $doc=[IO.File]::ReadAllText($hook)|ConvertFrom-Json
 foreach ($group in $doc.hooks.PreToolUse) {
  if ($group.matcher -cne $matcher) { continue }
  foreach ($entry in $group.hooks) { if ($entry.type -eq 'command' -and $entry.command -ceq $command -and $entry.async -ne $true) { return $true } }
 }
 return $false
}
if ($external -and $hasMarker) { throw 'Remove the previous managed integration before changing hook ownership.' }
if ($Action -eq 'Detect' -and $external) {
 $command=[IO.File]::ReadAllText($externalFlag)
 if ($command.EndsWith(' claude-pretool-delegated')) { $matcher='.*' }
}
if ($Action -eq 'Detect') {
 if ((Valid-Release) -and ($ownsHook -or ($external -and (Has-ExternalHook))) -and (Test-Path -LiteralPath $cfg -PathType Leaf) -and $job.State -eq 'Running' -and $job.Actions[0].Execute -eq $exe -and $job.Actions[0].Arguments -eq 'pretool-broker') { Write-Output 'Pretool broker installed'; exit 0 }
 exit 1
}
if (!$external -and $hasHook -and !$ownsHook) { throw 'Claude managed settings are owned or edited elsewhere. Preserve them and use the documented manual integration.' }
if ($Action -eq 'Uninstall') {
 if ($external -and (Test-Path -LiteralPath $externalFlag)) { Remove-Item -LiteralPath $externalFlag }; if ($ownsHook) { Remove-Item -LiteralPath $hook }; if ($hasMarker) { Remove-Item -LiteralPath $owned }
 if ($job) { Stop-ScheduledTask -TaskName $task; Unregister-ScheduledTask -TaskName $task -Confirm:$false }
 if (Test-Path -LiteralPath $cfg -PathType Leaf) { Remove-Item -LiteralPath $cfg }
 return
}
if ($external -and !(Has-ExternalHook)) { throw 'Merge the exact synchronous pre-tool hook in the existing Claude managed settings before deploying.' }
if (!(Valid-Release)) { throw 'Install the pinned enrollment app first.' }
if (!(Test-Path -LiteralPath (Join-Path $root 'device.json') -PathType Leaf)) { throw 'Provision the unique device binding before enabling the broker.' }
foreach ($dir in @($EmployeeHome,$Workspace)) {
 if ($dir -notmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetFullPath($dir) -cne $dir) { throw 'Choose canonical absolute local paths.' }
}
if ([Convert]::FromBase64String($IssuerPublicKey).Length -ne 32) { throw 'Expected an independently provisioned Ed25519 public key.' }
$device=& $exe init-device-key
if ($LASTEXITCODE -or ($device | ConvertFrom-Json).device_public_key -ceq $IssuerPublicKey) { throw 'The policy issuer and device key must differ.' }
$configBody=@{issuer_public_key=$IssuerPublicKey;home=$EmployeeHome;workspace=$Workspace}
if ($DelegationVerifier) {
 $verifier=$DelegationVerifier|ConvertFrom-Json
 $fields=@('agent_id','environment_id','organization_id','parent_task_id','public_key','workspace_id')
 if (Compare-Object $fields @($verifier.PSObject.Properties.Name)) { throw 'Delegation verifier fields are incomplete or unrecognized.' }
 if ([Convert]::FromBase64String($verifier.public_key).Length -ne 32 -or $verifier.public_key -ceq ($device | ConvertFrom-Json).device_public_key) { throw 'Expected the independent delegation issuer public key.' }
 $deviceConfig=[IO.File]::ReadAllText((Join-Path $root 'device.json'))|ConvertFrom-Json
 foreach ($scopeField in @('organization_id','workspace_id','environment_id')) {
  if ($verifier.$scopeField -cne $deviceConfig.binding.$scopeField) { throw 'Delegation must match the enrolled device scope.' }
 }
 foreach ($field in @('agent_id','parent_task_id')) {
  if ($verifier.$field -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$') { throw 'Invalid task or agent binding.' }
 }
 $configBody.delegation=$verifier
}
$config=$configBody|ConvertTo-Json -Depth 4 -Compress
$settings=@{hooks=@{PreToolUse=@(@{matcher=$matcher;hooks=@(@{type='command';command=$command;timeout=3})})}}|ConvertTo-Json -Depth 8 -Compress
if (!(Test-Path -LiteralPath $claude)) { [IO.Directory]::CreateDirectory($claude)|Out-Null; Assert-Managed $claude }
# Stop exactly the existing broker when changing its pinned configuration. Keep
# any previously installed hook in place so its configured unavailable action holds.
if ($job) { Stop-ScheduledTask -TaskName $task }
Write-Atomic $cfg $config
$system=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settingsJob=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $exe -Argument 'pretool-broker') -Principal $system -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settingsJob -Force|Out-Null
Start-ScheduledTask -TaskName $task
if ($external) { Write-Atomic $externalFlag $command; return }
# Save the ownership digest first. A retry can complete an interrupted first
# install when no hook was published, or refuse an externally edited hook.
$sha=[Security.Cryptography.SHA256]::Create()
try { $newHash=[BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($settings))).Replace('-','') } finally { $sha.Dispose() }
$transitions=@($allowedHashes | Where-Object { $_ -ceq $currentHash -and $_ -cne $newHash }) + @($newHash)
Write-Atomic $owned ($transitions -join [Environment]::NewLine)
Write-Atomic $hook $settings
Write-Atomic $owned $newHash
