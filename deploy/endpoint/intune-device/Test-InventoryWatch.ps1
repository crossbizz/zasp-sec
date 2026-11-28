# Exercise real filesystem notifications in a separate employee-context process.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('zasp-inventory-watch-' + [guid]::NewGuid().ToString('N'))
if ($IsMacOS -and $fixture.StartsWith('/var/')) { $fixture = '/private' + $fixture }
$project = Join-Path $fixture 'assigned'
$root = Join-Path $project '.agents/skills'
$bundle = Join-Path $root 'sample'
$manifest = Join-Path $bundle 'SKILL.md'
$observed = Join-Path $fixture 'observed'
$watch = Join-Path $PSScriptRoot 'Watch-Inventory.ps1'
$job = $null

function Wait-Observation([string]$Expected) {
 $deadline = [DateTime]::UtcNow.AddSeconds(15)
 while ([DateTime]::UtcNow -lt $deadline) {
  if ($job.State -ne 'Running') { Receive-Job $job; throw 'Inventory watcher stopped unexpectedly.' }
  if ([IO.File]::Exists($observed) -and [IO.File]::ReadAllText($observed).Contains("$Expected;")) { return }
  Start-Sleep -Milliseconds 80
 }
 throw "Missing inventory notification for $Expected"
}

try {
 [IO.Directory]::CreateDirectory($project) | Out-Null
 $job = Start-Job -ScriptBlock {
  param($watch,$root,$manifest,$observed,$project)
  $ErrorActionPreference = 'Stop'
  . $watch
  $assignment = Join-Path $project 'assignment.json'
  Watch-ZaspPaths -Files @($assignment) -Until { [IO.File]::Exists($assignment) }
  $mcp = Join-Path $project '.mcp.json'
  Watch-ZaspPaths -Directories @($root) -Files @($mcp) -OnChange {
   $value = if ([IO.File]::Exists($manifest)) { [IO.File]::ReadAllText($manifest) } else { 'absent' }
   $value += if ([IO.File]::Exists($mcp)) { '+mcp' } else { '' }
   [IO.File]::AppendAllText($observed, "$value;")
  }
 } -ArgumentList $watch,$root,$manifest,$observed,$project
 [IO.File]::WriteAllText((Join-Path $project 'assignment.json'), '{}')
 Wait-Observation 'absent'
 [IO.File]::WriteAllText((Join-Path $project 'unrelated.txt'), 'ignore')
 Start-Sleep -Milliseconds 1200
 if ([IO.File]::ReadAllText($observed) -ne 'absent;') { throw 'An unrelated file or an idle interval caused a scan.' }
 [IO.Directory]::CreateDirectory($bundle) | Out-Null
 [IO.File]::WriteAllText($manifest, 'added')
 Wait-Observation 'added'
 [IO.File]::WriteAllText($manifest, 'edited')
 Wait-Observation 'edited'
 [IO.File]::WriteAllText((Join-Path $project '.mcp.json'), '{}')
 Wait-Observation 'edited+mcp'
 [IO.Directory]::Move($root, (Join-Path $fixture 'old-skills'))
 Wait-Observation 'absent+mcp'
 [IO.File]::WriteAllText((Join-Path $fixture 'old-skills/sample/SKILL.md'), 'replacement')
 [IO.Directory]::Move((Join-Path $fixture 'old-skills'), $root)
 Wait-Observation 'replacement+mcp'
 Stop-Job $job; Remove-Job $job; $job = $null
 $handoff = Join-Path $fixture 'report.json'
 $observed = Join-Path $fixture 'sync-calls'
 $job = Start-Job -ScriptBlock {
  param($watch,$handoff,$observed)
  $ErrorActionPreference = 'Stop'
  . $watch
  Watch-ZaspPaths -Files @($handoff) -TransportHeartbeatSeconds 60 -OnChange {
   $snapshot = if ([IO.File]::Exists($handoff)) { [IO.File]::ReadAllText($handoff) } else { 'waiting' }
   [IO.File]::AppendAllText($observed, "$snapshot;")
  }
 } -ArgumentList $watch,$handoff,$observed
 Wait-Observation 'waiting'
 [IO.File]::WriteAllText($handoff, 'new-report')
 Wait-Observation 'new-report'
 Write-Output 'Verified event-driven inventory and immediate transport wakeup.'
} finally {
 if ($job) { Stop-Job $job; Remove-Job $job -Force }
 if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
