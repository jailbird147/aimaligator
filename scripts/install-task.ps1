# Creates a Windows scheduled task that runs AIMaligator every 5 minutes.
# Run from the installed folder (next to config.json):
#   powershell -ExecutionPolicy Bypass -File scripts\install-task.ps1

$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
$python = Resolve-Path $python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Venv python not found - install AIMaligator first (see install.ps1)."
}

$action = New-ScheduledTaskAction -Execute $python `
    -Argument "-m aimaligator --once" `
    -WorkingDirectory (Resolve-Path (Join-Path $PSScriptRoot ".."))
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "AIMaligator" `
    -Action $action -Trigger $trigger -Settings $settings `
    -Description "Alert-only watchdog for local AI apps"
