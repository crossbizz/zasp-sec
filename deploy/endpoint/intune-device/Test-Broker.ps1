[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestExecutable)
$ErrorActionPreference='Stop'
# Hosted disposable Windows worker. Start a short-lived test executable as
# SYSTEM and make actual pipe calls from the runner's distinct user token.
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.IsSystem -or ![Environment]::Is64BitProcess) { throw 'A distinct native Windows CI user is required.' }
$id='ZaspBrokerTest-'+[guid]::NewGuid().ToString('N')
$root=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $id
$exe=Join-Path $root 'broker.test.exe'
$registered=$false
try {
 [IO.Directory]::CreateDirectory($root)|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
 Set-Acl -LiteralPath $root -AclObject $acl
 Copy-Item -LiteralPath $TestExecutable -Destination $exe
 $employeeFile=Join-Path $root 'employee.sid'
 [IO.File]::WriteAllText($employeeFile,$identity.User.Value)
 $inputACL=New-Object Security.AccessControl.FileSecurity
 $inputACL.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
 Set-Acl -LiteralPath $employeeFile -AclObject $inputACL
 $done=Join-Path $root 'employee.done'
 [IO.File]::WriteAllBytes($done,[byte[]]@())
 $doneACL=New-Object Security.AccessControl.FileSecurity
 $doneACL.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;$($identity.User.Value))")
 Set-Acl -LiteralPath $done -AclObject $doneACL
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $argsValue='-test.v -test.timeout=75s -test.run=^TestNativeManagedPretoolPipe$ -zasp-test-pipe-role=system "-zasp-test-pipe-root='+$root+'"'
 $log=Join-Path $root 'system-test.log'
 $runner=Join-Path $env:SystemRoot 'System32\cmd.exe'
 # Executable, arguments and log name are constructed only from Program Files
 # and the generated GUID. Preserve diagnostics for the CI job before cleanup.
 $command='/d /s /c ""'+$exe+'" '+$argsValue+' >"'+$log+'" 2>&1"'
 $action=New-ScheduledTaskAction -Execute $runner -Argument $command -WorkingDirectory $root
 Register-ScheduledTask -TaskName $id -Action $action -Principal $principal -Force|Out-Null
 $registered=$true
 Start-ScheduledTask -TaskName $id
 & $exe -test.v -test.timeout=40s '-test.run=^TestNativeManagedPretoolPipe$' '-zasp-test-pipe-role=employee' "-zasp-test-pipe-root=$root"
 if ($LASTEXITCODE) { throw "Employee broker fixture failed ($LASTEXITCODE)." }
 $until=(Get-Date).AddSeconds(60)
 do { Start-Sleep -Milliseconds 250; $job=Get-ScheduledTask -TaskName $id } while ($job.State -eq 'Running' -and (Get-Date) -lt $until)
 $result=(Get-ScheduledTaskInfo -TaskName $id).LastTaskResult
 if ($job.State -eq 'Running' -or $result -ne 0) { throw "SYSTEM broker fixture failed ($result)." }
} finally {
 if ($log -and (Test-Path -LiteralPath $log)) { Get-Content -LiteralPath $log -Tail 60 }
 if ($registered) {
  Stop-ScheduledTask -TaskName $id -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $id -Confirm:$false
 }
 if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
