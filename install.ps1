# AIMaligator installer for Windows.
#
# Usage (from the folder containing install.ps1 and the wheels):
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Options:
#   -InstallDir F:\AIMaligator   where to install (default: F:\AIMaligator)
#   -TaskName  AIMaligator       scheduled task name (default: AIMaligator)
#   -SkipTask                    do not register the scheduled task
#
# What it does:
#   1. Finds a Python 3.10+ (via the 'py' launcher or 'python')
#   2. Creates a virtual environment in <InstallDir>\.venv
#   3. Installs the AIMaligator wheel + psutil (from local wheels if present,
#      otherwise from the internet)
#   4. Registers a scheduled task that checks every 5 minutes
#   5. Runs 'aimaligator --init' to detect your AI apps and take a baseline

param(
    [string]$InstallDir = "F:\AIMaligator",
    [string]$TaskName = "AIMaligator",
    [switch]$SkipTask
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Find Python
$py = (Get-Command py -ErrorAction SilentlyContinue).Source
if ($py) {
    & $py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "The 'py' launcher has no Python 3.10+." }
} else {
    $py = (Get-Command python -ErrorAction Stop).Source
    & $py -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required." }
}
Write-Host "Using Python: $py"

# 2. Virtual environment
$venv = Join-Path $InstallDir ".venv"
if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    & $py -3 -m venv $venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "venv pip bootstrap failed - retrying without pip"
        Remove-Item -Recurse -Force $venv -ErrorAction SilentlyContinue
        & $py -3 -m venv --without-pip $venv
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed - see messages above." }
    }
}
$vpython = Join-Path $venv "Scripts\python.exe"
Write-Host "Virtual environment: $venv"

# 3. Install wheels (local first, internet as fallback)
# Some machines fail to bootstrap pip inside the venv; fall back to the
# host pip driving the venv's interpreter directly.
$wheels = Get-ChildItem -Path $here -Filter "*.whl" -Recurse | Select-Object -First 1
if ($wheels) {
    $wheelDir = Split-Path $wheels.FullName
    Write-Host "Installing from local wheels in $wheelDir ..."
    & $vpython -m pip install --no-index --find-links $wheelDir aimaligator
    if ($LASTEXITCODE -ne 0) {
        Write-Host "venv pip unavailable - using host pip instead"
        & $py -3 -m pip --python $vpython install --no-index --find-links $wheelDir aimaligator
    }
} else {
    # Cloning the repository: no wheels, so install from this source tree.
    Write-Host "No local wheels found - installing from local source..."
    & $vpython -m pip install $here
    if ($LASTEXITCODE -ne 0) {
        Write-Host "venv pip unavailable - using host pip instead"
        & $py -3 -m pip --python $vpython install $here
    }
}
if ($LASTEXITCODE -ne 0) { throw "Package installation failed." }

# 4. Scheduled task
if (-not $SkipTask) {
    $action = New-ScheduledTaskAction -Execute $vpython `
        -Argument "-m aimaligator --once" `
        -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Settings $settings `
        -Description "Alert-only watchdog for local AI apps" | Out-Null
    Write-Host "Scheduled task '$TaskName' registered (checks every 5 minutes)."
}

# 5. Detect AI apps and take the first baseline
Push-Location $InstallDir
& $vpython -m aimaligator --init
Pop-Location
Write-Host ""
Write-Host "AIMaligator is installed. Check anytime with:"
Write-Host "  $venv\Scripts\aimaligator.exe --once"

# temp line to verify --diff
# temp line 2 to verify --diff
