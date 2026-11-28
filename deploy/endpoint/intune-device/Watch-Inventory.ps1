# Used independently by the employee collector and the protected device transport.
function Watch-ZaspPaths {
 param(
  [string[]]$Directories, [string[]]$Files,
  [Parameter(Mandatory,ParameterSetName='Observe')][scriptblock]$OnChange,
  [Parameter(Mandatory,ParameterSetName='Await')][scriptblock]$Until,
  [Parameter(ParameterSetName='Observe')][int]$TransportHeartbeatSeconds = 0
 )

 function Add-InventoryWatch([string]$Directory, [string]$Filter, [bool]$Recursive, [IO.NotifyFilters]$Notify) {
  $key = "$Directory|$Filter|$Recursive|$Notify"
  if ($watchers.ContainsKey($key)) { return }
  $watcher = [IO.FileSystemWatcher]::new($Directory, $Filter)
  $watchers[$key] = $watcher
  $watcher.IncludeSubdirectories = $Recursive
  $watcher.NotifyFilter = $Notify
  foreach ($event in 'Changed','Created','Deleted','Renamed','Error') {
   $id = 'Zasp.Inventory.' + [guid]::NewGuid().ToString('N')
   Register-ObjectEvent -InputObject $watcher -EventName $event -SourceIdentifier $id -MaxTriggerCount 1
   $ids.Add($id)
  }
  $watcher.EnableRaisingEvents = $true
 }

 function Add-InventoryTarget([string]$Target, [bool]$IsDirectory) {
  $chain = [Collections.Generic.Stack[string]]::new()
  $path = [IO.Path]::GetFullPath($Target)
  while ($parent = [IO.Path]::GetDirectoryName($path)) { $chain.Push($path); $path = $parent }
  foreach ($child in $chain) {
   $leaf = [IO.Path]::GetFileName($child)
   # Listen for the specific ancestor before looking for its child. This also
   # catches a missing hierarchy created by moving a populated directory.
   $notify = [IO.NotifyFilters]'DirectoryName,Attributes'
   if (!$IsDirectory -and $child -eq $Target) { $notify = $contents }
   Add-InventoryWatch $path $leaf $false $notify
   if (![IO.Directory]::Exists($child) -or ([IO.File]::GetAttributes($child) -band [IO.FileAttributes]::ReparsePoint)) { return }
   $path = $child
  }
  if ($IsDirectory) { Add-InventoryWatch $path '*' $true $contents }
 }

 $contents = [IO.NotifyFilters]'FileName,DirectoryName,LastWrite,Size'
 while ($true) {
  $ids = [Collections.Generic.List[string]]::new()
  $watchers = @{}
  try {
   foreach ($dir in $Directories) { Add-InventoryTarget $dir $true }
   foreach ($file in $Files) { Add-InventoryTarget $file $false }
   if (!$watchers.Count) { throw 'No assigned inventory location could be watched.' }
   # Arm first so changes during the scan trigger the next pass. Every
   # subscription queues at most one notification, including buffer overflow.
   if ($Until) {
    if (& $Until) { return }
   } else { & $OnChange }
   # Only the transport sets a heartbeat. The employee scanner sleeps
   # indefinitely until the filesystem signals a change or an overflow.
   $pending = if ($TransportHeartbeatSeconds -gt 0) { Wait-Event -Timeout $TransportHeartbeatSeconds } else { Wait-Event }
   if (!$pending) { continue }
   Start-Sleep -Milliseconds 350
  } finally {
   foreach ($watcher in $watchers.Values) { $watcher.Dispose() }
   foreach ($id in $ids) {
    Unregister-Event -SourceIdentifier $id -ErrorAction SilentlyContinue
    Remove-Event -SourceIdentifier $id -ErrorAction SilentlyContinue
   }
  }
 }
}
