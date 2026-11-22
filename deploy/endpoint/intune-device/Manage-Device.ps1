[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Install','Detect','Uninstall')][string]$Action,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$AgentSHA256,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SignerThumbprint,
 [ValidatePattern('^S-1-(5-21|12-1)(-[0-9]+){4}$')][string]$EmployeeSID,
 [ValidateSet('personal','managed')][string]$Scope='personal'
)
$ErrorActionPreference='Stop'
if (![Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { throw 'Deploy as LocalSystem.' }
if (![Environment]::Is64BitProcess) { throw 'Run the 64-bit system PowerShell host.' }
$root=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Zasp Inventory Device'
$exe=Join-Path $root 'zasp-device-windows.exe'
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Assert-Plain([string]$Path) {
 if ((Test-Path -LiteralPath $Path) -and ((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'A managed path is a reparse point.' }
}
function Valid-Release([string]$Path) {
 if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
 Assert-Plain $Path
 $sig=Get-AuthenticodeSignature -LiteralPath $Path
 return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash -eq $AgentSHA256 -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Thumbprint -eq $SignerThumbprint
}
Assert-Plain $root
Assert-Plain $exe
if ($Action -eq 'Detect') {
 if ((Valid-Release $exe) -and (Get-ScheduledTask -TaskName 'Zasp Inventory Device Sync' -ErrorAction SilentlyContinue) -and (Get-ScheduledTask -TaskName 'Zasp Inventory User Scan' -ErrorAction SilentlyContinue)) { Write-Output 'Installed'; exit 0 }
 exit 1
}
if ($Action -eq 'Uninstall') {
 $tasks=@('Zasp Inventory User Scan','Zasp Inventory Device Sync')
 if (!(Test-Path -LiteralPath $exe)) {
  foreach ($task in $tasks) { if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { throw 'A scheduled task still needs controlled cleanup.' } }
  return
 }
 if (!(Valid-Release $exe)) { throw 'Installed release identity differs or is unavailable.' }
 foreach ($task in $tasks) {
  if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $task; Unregister-ScheduledTask -Confirm:$false -TaskName $task }
 }
 # Preserve the sealed queue for controlled recovery. Remove the employee's
 # plaintext handoff and managed collector after stopping the task that writes it.
 foreach ($known in @('Collect-Inventory.ps1','report.json')) {
  $item=Join-Path $root $known
  Assert-Plain $item
  if (Test-Path -LiteralPath $item -PathType Leaf) { Remove-Item -LiteralPath $item }
 }
 Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Zasp Inventory Device' -Name 'EmployeeStatusV1' -ErrorAction SilentlyContinue
 Remove-Item -LiteralPath $exe
 return
}
$existingConfig=Join-Path $root 'device.json'
Assert-Plain $existingConfig
if (Test-Path -LiteralPath $existingConfig) {
 $existing=Get-Content -Raw -LiteralPath $existingConfig | ConvertFrom-Json
 if ($existing.assigned_sid -ne $EmployeeSID -or $existing.scope -ne $Scope) { throw 'Assigned user or scope changed. Retire and re-enroll this device before reassignment.' }
}
if (!$EmployeeSID) { throw 'Choose the assigned employee security identifier.' }
$src=Join-Path $PSScriptRoot 'zasp-device-windows.exe'
if (!(Valid-Release $src)) { throw 'Managed release hash or Authenticode verification failed.' }
[IO.Directory]::CreateDirectory($root) | Out-Null
Assert-Plain $root
# Program Files prevents an employee from creating or replacing the parent.
$folderAcl=New-Object Security.AccessControl.DirectorySecurity
$folderAcl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
Set-Acl -LiteralPath $root -AclObject $folderAcl
foreach ($name in @('report.json','Collect-Inventory.ps1','identity.dpapi','transport.dpapi','state.dpapi','inventory.lock','device.json')) { Assert-Plain (Join-Path $root $name) }
$report=Join-Path $root 'report.json'
if (!(Test-Path -LiteralPath $report)) { [IO.File]::WriteAllBytes($report,[byte[]]@()) }
# Only the assigned user gets write-data. A user cannot replace the file or grant access.
$fileAcl=New-Object Security.AccessControl.FileSecurity
$registryPath='HKLM:\SOFTWARE\Zasp Inventory Device'
if (!(Test-Path -LiteralPath $registryPath)) { New-Item -Path $registryPath | Out-Null }
$registryAcl=New-Object Security.AccessControl.RegistrySecurity
$registryAcl.SetSecurityDescriptorSddlForm("O:SYG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;$EmployeeSID)")
Set-Acl -LiteralPath $registryPath -AclObject $registryAcl
$fileAcl.SetSecurityDescriptorSddlForm("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x100002;;;$EmployeeSID)")
Set-Acl -LiteralPath $report -AclObject $fileAcl
if (!(Valid-Release $exe)) {
 $tmp=Join-Path $root ([guid]::NewGuid().ToString()+'.tmp')
 try {
  [IO.File]::Copy($src,$tmp,$false)
  if (!(Valid-Release $tmp)) { throw 'Staged executable verification failed.' }
  if (Test-Path -LiteralPath $exe) { [IO.File]::Replace($tmp,$exe,$null) } else { [IO.File]::Move($tmp,$exe) }
 } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp } }
}
$collector=Join-Path $root 'Collect-Inventory.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Collect-Inventory.ps1') -Destination $collector -Force
& $exe init-device-key
if ($LASTEXITCODE) { throw 'Device key initialization failed.' }
$interval=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 5)
$system=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$employee=New-ScheduledTaskPrincipal -UserId $EmployeeSID -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'Zasp Inventory Device Sync' -Action (New-ScheduledTaskAction -Execute $exe -Argument 'sync') -Principal $system -Trigger $interval -Force | Out-Null
$argsValue='-NoProfile -NonInteractive -File "'+$collector+'" -Scope '+$Scope
Register-ScheduledTask -TaskName 'Zasp Inventory User Scan' -Action (New-ScheduledTaskAction -Execute $ps -Argument $argsValue) -Principal $employee -Trigger @($interval,(New-ScheduledTaskTrigger -AtLogOn -User $EmployeeSID)) -Force | Out-Null
