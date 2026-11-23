# Run with the assigned employee's interactive token. Metadata stays on this Windows device until sync.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('personal','managed')][string]$Scope)
$ErrorActionPreference='Stop'
$folder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Zasp Inventory Device'
$cli=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Zasp\CLI\zaspctl.exe'
if (!(Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Install the user-context Zasp CLI first.' }
$report = & $cli addons inventory --local --scope $Scope --harness all --json
$code=$LASTEXITCODE
if ($code -notin @(0,3) -or !$report) { throw 'The user-context scanner did not produce an inventory.' }
$data = [Text.UTF8Encoding]::new($false).GetBytes(($report -join [Environment]::NewLine))
if ($data.Length -gt 1MB) { throw 'Inventory handoff exceeds the device limit.' }
# Only FILE_WRITE_DATA and SYNCHRONIZE are granted to this SID on the fixed file.
$stream = [IO.FileStream]::new((Join-Path $folder 'report.json'),[IO.FileMode]::Open,([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::Synchronize),[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
try { $stream.SetLength(0); $stream.Write($data,0,$data.Length); $stream.Flush($true) } finally { $stream.Dispose() }
exit $code
