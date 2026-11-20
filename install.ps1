$ErrorActionPreference = 'Stop'
$name = 'freezeMe-Security'

$src = Join-Path $PSScriptRoot "$name.exe"
if (-not (Test-Path $src)) { throw 'Run build.bat first.' }

$dir = Join-Path $env:ProgramFiles $name
$exe = Join-Path $dir "$name.exe"
$ini = Join-Path $dir 'freeze.ini'

# stop old copy
if (Test-Path $exe) {
    Start-Process -FilePath $exe -ArgumentList '--stop' -Wait
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force -Path $dir | Out-Null

# remove the old "Freeze" install if it's there, keep its combo
$oldDir = Join-Path $env:ProgramFiles 'Freeze'
$oldExe = Join-Path $oldDir 'Freeze.exe'
if (Test-Path $oldExe) {
    Start-Process -FilePath $oldExe -ArgumentList '--stop' -Wait
    Start-Sleep -Seconds 2
    $oldIni = Join-Path $oldDir 'freeze.ini'
    if ((Test-Path $oldIni) -and -not (Test-Path $ini)) { Copy-Item $oldIni $ini }
    Unregister-ScheduledTask -TaskName 'Freeze' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $oldDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Removed old Freeze install.'
}

Copy-Item $src $exe -Force

# only ask for a combo on first install
$hasCombo = (Test-Path $ini) -and (Select-String -Path $ini -Pattern '^Chord=.+' -Quiet)
if ($hasCombo) {
    Write-Host 'Keeping existing combo.'
} else {
    Write-Host 'Enter your combo in the window...'
    Start-Process -FilePath $exe -ArgumentList '--enrol' -Wait
}

if (-not (Test-Path $ini) -or -not (Select-String -Path $ini -Pattern '^Chord=.+' -Quiet)) {
    throw 'No combo saved, not installed.'
}

# admins + SYSTEM only
& icacls $ini /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null

# run at sign-in as admin, no time limit
$user      = "$env:USERDOMAIN\$env:USERNAME"
$action    = New-ScheduledTaskAction -Execute $exe
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 4
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Installed. Test with: `"$exe`" --test"
