# Run with the assigned employee's interactive token. Metadata stays on this Windows device until sync.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('personal','managed','project')][string]$Scope)
$ErrorActionPreference='Stop'
$folder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Zasp Inventory Device'
$cli=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Zasp\CLI\zaspctl.exe'
$assignmentFile=Join-Path $folder 'device.json'
. (Join-Path $PSScriptRoot 'Watch-Inventory.ps1')
# Enrollment can finish while the assigned employee is already signed in.
Watch-ZaspPaths -Files @($assignmentFile,$cli) -Until { [IO.File]::Exists($assignmentFile) -and [IO.File]::Exists($cli) }
$assignment = Get-Content -Raw -LiteralPath $assignmentFile | ConvertFrom-Json
if ($assignment.scope -ne $Scope) { throw 'The employee task and device assignment select different inventory scopes.' }
$scanArgs = @('addons','inventory','--local','--scope',$Scope,'--harness','all','--json')
if ($Scope -eq 'project') {
 $project = [string]$assignment.project_root
 if ($project -notmatch '^[A-Za-z]:\\.+' -or [IO.Path]::GetFullPath($project) -cne $project -or $project.EndsWith('\')) { throw 'Provision an absolute project directory in the device assignment.' }
 $scanArgs += @('--project',$project)
}
if ($Scope -eq 'managed') {
 $base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ClaudeCode'
 $dirs = @(Join-Path $base 'skills')
 $files = @(Join-Path $base 'managed-mcp.json')
} else {
 $base = if ($Scope -eq 'personal') { [Environment]::GetFolderPath('UserProfile') } else { $project }
 $dirs = @((Join-Path $base '.claude/skills'),(Join-Path $base '.agents/skills'))
 $files = if ($Scope -eq 'project') { @(Join-Path $base '.mcp.json') } else { @() }
}
Watch-ZaspPaths -Directories $dirs -Files $files -OnChange {
 $report = & $cli @scanArgs
 $code=$LASTEXITCODE
 if ($code -notin @(0,3) -or !$report) { throw 'The user-context scanner did not produce an inventory.' }
 $data = [Text.UTF8Encoding]::new($false).GetBytes(($report -join [Environment]::NewLine))
 if ($data.Length -gt 1MB) { throw 'Inventory handoff exceeds the device limit.' }
 # Only FILE_WRITE_DATA and SYNCHRONIZE are granted to this SID on the fixed file.
 $deadline = [DateTime]::UtcNow.AddSeconds(3)
 while ($true) {
  try {
   $stream = [IO.FileStream]::new((Join-Path $folder 'report.json'),[IO.FileMode]::Open,([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::Synchronize),[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
   break
  } catch [IO.IOException] {
   if (($_.Exception.HResult -band 0xffff) -notin @(32,33) -or [DateTime]::UtcNow -ge $deadline) { throw }
   Start-Sleep -Milliseconds 100
  }
 }
 try { $stream.SetLength(0); $stream.Write($data,0,$data.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
