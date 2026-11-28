# Run by the device's LocalSystem transport task. The employee can write the
# fixed handoff but receives no task-control, signing or network authority.
$ErrorActionPreference='Stop'
$folder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Zasp Inventory Device'
$agent=Join-Path $folder 'zasp-device-windows.exe'
. (Join-Path $PSScriptRoot 'Watch-Inventory.ps1')
Watch-ZaspPaths -Files @(Join-Path $folder 'report.json') -TransportHeartbeatSeconds 300 -OnChange {
 # sync owns the existing process lock, durable queue and device credential.
 # A transport failure retries at the next handoff or heartbeat.
 & $agent sync
}
